"""Security review (brief 06): CSRF on every state-changing POST, cross-site rejection, authorization
of disabled/pending admins on every /admin route, and IDOR attempts on ids in URLs and forms."""

from __future__ import annotations

import sqlite3

import pytest
from sqlalchemy import select

from app.db import read_session, write_session
from app.models import AdminSession, AdminUser, Chair, PaymentEvent, User, UserSession
from app.services import admin_auth, ledger
from app.timeutil import utcnow
from app.web import routes_user, tokens
from tests import factories
from tests.admin_support import fast_hasher, login_as, make_real_admin, new_client  # noqa: F401
from tests.test_admin_routes_authz import POST_DATA, ROUTES, call, fill, principals, world  # noqa: F401
from tests.user_support import scan_token

USER_POSTS = {r.path for r in routes_user.router.routes if "POST" in r.methods}
# /coffee/{kind} is protected by the signed scan token plus the fetch-metadata/Origin check; every other user
# POST needs a CSRF token bound to the user session, or (before sign-in) to the `coffee_csrf` cookie.
USER_POST_DATA = {
    "/coffee/undo/{event_id}": {},
    "/login": {"username": "mallory", "password": "x"},
    "/register": {"username": "mallory", "display_name": "Mallory", "chair_id": "{chair_id}",
                  "email": "mallory@tum.de", "password": "a-long-enough-password",
                  "password2": "a-long-enough-password", "privacy_ack": "1"},
    "/register/guest": {"username": "mallory", "display_name": "Mallory", "sponsor_email": "alice@tum.de",
                        "password": "a-long-enough-password", "password2": "a-long-enough-password",
                        "privacy_ack": "1"},
    "/verify/{token}": {},
    "/forgot": {"username": "alice"},
    "/reset/{token}": {"password": "a-long-enough-password", "password2": "a-long-enough-password"},
    "/account/edit": {"display_name": "Pwned", "chair_id": "{chair_id}"},
    "/account/password": {"current_password": "x", "password": "a-long-enough-password",
                          "password2": "a-long-enough-password"},
    "/logout": {},
}
PRE_SESSION_POSTS = ["/login", "/register", "/register/guest", "/verify/{token}", "/forgot", "/reset/{token}"]


def url(path: str, world: dict) -> str:
    return fill(path, {**world, "token": "sometoken"})


def snapshot(db_path) -> dict:
    """All rows of all tables except rate-limit bookkeeping and last-seen stamps."""
    con = sqlite3.connect(db_path)
    try:
        out = {}
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for t in tables:
            if t in ("rate_limit_events", "alembic_version"):
                continue
            cols = [c[1] for c in con.execute(f'PRAGMA table_info("{t}")')]
            keep = [c for c in cols if c != "last_seen_at"]
            out[t] = sorted(map(repr, con.execute(f'SELECT {", ".join(keep)} FROM "{t}"')))
        return out
    finally:
        con.close()


def test_user_post_inventory_is_complete():
    assert USER_POSTS == set(USER_POST_DATA) | {"/coffee/{kind}"}


@pytest.mark.parametrize("path", sorted(USER_POST_DATA))
@pytest.mark.parametrize("token", ["missing", "foreign_session", "wrong_scope"])
def test_user_posts_require_session_bound_csrf(path, token, client, db, world, login, db_path):
    other = factories.make_user(db, "Eve", db.get(Chair, world["chair_id"]))
    other_session = factories.make_session(db, other, raw_token="e" * 43)
    db.rollback()
    login(db.get(User, world["user_id"]))
    data = {k: fill(v, world) for k, v in USER_POST_DATA[path].items()}
    if token == "foreign_session":  # the attacker's own valid token, bound to the attacker's session
        data["csrf_token"] = tokens.csrf_token("user", str(other_session.id))
    elif token == "wrong_scope":  # the admin-scoped MAC of the same key must not verify as a user token
        data["csrf_token"] = tokens.csrf_token("admin", "x")
    before = snapshot(db_path)
    r = client.post(url(path, world), data=data, follow_redirects=False)
    assert r.status_code == 403, (path, r.status_code)
    assert snapshot(db_path) == before


@pytest.mark.parametrize("path", PRE_SESSION_POSTS)
@pytest.mark.parametrize("mode", ["no_cookie_no_token", "no_cookie_forged_token", "token_of_another_cookie",
                                  "cookie_without_token", "user_scope_token"])
def test_pre_session_posts_require_the_cookie_bound_token(path, mode, client, db, world, db_path):
    data = {k: fill(v, world) for k, v in USER_POST_DATA[path].items()}
    if mode == "no_cookie_forged_token":
        data["csrf_token"] = tokens.csrf_token("anon", "guess")
    elif mode == "token_of_another_cookie":
        client.cookies.set("coffee_csrf", "mine")
        data["csrf_token"] = tokens.csrf_token("anon", "theirs")
    elif mode == "cookie_without_token":
        client.cookies.set("coffee_csrf", "mine")
    elif mode == "user_scope_token":
        client.cookies.set("coffee_csrf", "mine")
        data["csrf_token"] = tokens.csrf_token("user", "mine")
    before = snapshot(db_path)
    r = client.post(url(path, world), data=data, follow_redirects=False)
    assert r.status_code == 403, (path, mode, r.status_code)
    assert snapshot(db_path) == before


@pytest.mark.parametrize("path", PRE_SESSION_POSTS)
def test_pre_session_posts_accept_the_matching_token(path, client, db, world):
    client.cookies.set("coffee_csrf", "mine")
    data = {k: fill(v, world) for k, v in USER_POST_DATA[path].items()}
    data["csrf_token"] = tokens.csrf_token("anon", "mine")
    r = client.post(url(path, world), data=data, follow_redirects=False)
    assert r.status_code != 403, path


def _all_posts():
    users = [("user", p) for p in sorted(USER_POST_DATA)] + [("user", "/coffee/{kind}")]
    admins = [("admin", p) for m, p, _ in ROUTES if m == "POST"]
    return users + admins


@pytest.mark.parametrize("area,path", _all_posts())
@pytest.mark.parametrize("headers", [{"Origin": "https://evil.example"}, {"Origin": "null"},
                                     {"Sec-Fetch-Site": "cross-site"},
                                     {"Origin": "http://testserver.evil.example"}], ids=["origin", "null", "fetch", "suffix"])
def test_cross_site_posts_rejected_on_every_route(area, path, headers, client, db, world, login, principals, db_path):
    login(db.get(User, world["user_id"]))
    data = {"csrf_token": "irrelevant", "token": "x"}
    before = snapshot(db_path)
    if area == "admin":
        c, csrf = principals["global"]
        data = {**{k: fill(v, world) for k, v in POST_DATA.get(path, {}).items()}, "csrf_token": csrf}
        r = c.post(fill(path, world), data=data, headers=headers, follow_redirects=False)
    else:
        r = client.post(url(path, world), data=data, headers=headers, follow_redirects=False)
    assert r.status_code == 403
    assert snapshot(db_path) == before


ADMIN_POSTS = [p for m, p, _ in ROUTES if m == "POST" and p != "/admin/login"]


@pytest.mark.parametrize("path", ADMIN_POSTS)
@pytest.mark.parametrize("token", ["missing", "other_admin_session", "user_scope"])
def test_admin_posts_require_session_bound_csrf(path, token, app, db, world, principals, db_path):
    c, _ = principals["global"]
    data = {k: fill(v, world) for k, v in POST_DATA[path].items()}
    if token == "other_admin_session":
        _, other_csrf = principals["in_scope"]
        data["csrf_token"] = other_csrf
    elif token == "user_scope":
        with read_session() as r:
            secret = r.scalars(select(AdminSession.csrf_secret).join(AdminUser)
                               .where(AdminUser.username == "global")).first()
        data["csrf_token"] = tokens.csrf_token("user", secret)
    before = snapshot(db_path)
    r = c.post(fill(path, world), data=data, follow_redirects=False)
    assert r.status_code == 403, (path, r.status_code)
    assert snapshot(db_path) == before


@pytest.mark.parametrize("state", ["disabled", "group_user_inactive", "group_user_unverified", "expired", "revoked"])
def test_dead_or_incomplete_admin_sessions_reach_nothing(state, app, db, world, db_path, chair):
    group = state.startswith("group_user")
    admin_id, _ = make_real_admin(username="victim", role="chair" if group else "global",
                                  chairs=[chair] if group else ())
    c = new_client(app)
    csrf = login_as(c, admin_id)
    with write_session() as w:
        s = w.scalars(select(AdminSession).where(AdminSession.admin_id == admin_id)).one()
        if state == "disabled":  # flag flipped without revoking the sessions
            w.get(AdminUser, admin_id).active = False
        elif state == "group_user_inactive":  # the linked account is deactivated: the session dies with it
            w.get(AdminUser, admin_id).user.status = "inactive"
        elif state == "group_user_unverified":
            w.get(AdminUser, admin_id).user.verified_at = None
        elif state == "expired":
            s.expires_at = utcnow()
        else:
            s.revoked_at = utcnow()
    before = snapshot(db_path)
    for method, path, _ in ROUTES:
        if path == "/admin/login":
            continue
        r = call(c, method, path, world, csrf)
        assert r.status_code == 303 and r.headers["location"] == "/admin/login", (state, method, path)
    assert snapshot(db_path) == before


# ----- IDOR -----------------------------------------------------------------------------------------
def test_user_cannot_view_or_undo_foreign_events(client, db, world, login, db_path):
    me = factories.make_user(db, "Mallory", db.get(Chair, world["chair_id"]))
    raw = login(me)
    victim_event = world["event_id"]
    assert client.get(f"/coffee/done/{victim_event}").status_code == 404
    with read_session() as r:
        sid = admin_auth.hash_token(raw)
        session_id = r.scalar(select(UserSession.id).where(UserSession.token_hash == sid))
    before = snapshot(db_path)
    r = client.post(f"/coffee/undo/{victim_event}", data={"csrf_token": tokens.csrf_token("user", str(session_id))},
                    follow_redirects=False)
    assert r.status_code in (400, 403, 404)
    assert snapshot(db_path) == before


def test_chair_admin_cannot_reach_foreign_ids_through_an_in_scope_url(app, db, world, principals, other_chair, db_path):
    c, csrf = principals["in_scope"]
    other_user = db.get(User, world["other_user_id"])
    foreign_event = factories.add_events(db, other_user, "single")[0]
    foreign_pay = factories.make_payment(db, other_user, factories.make_admin(db, "global"), 300)
    uid = world["user_id"]
    before = snapshot(db_path)
    attempts = [
        (f"/admin/users/{uid}/events/{foreign_event.id}/reverse", {}),
        (f"/admin/users/{uid}/payment", {"amount": "-3", "correction_of": str(foreign_pay.id)}),
        (f"/admin/users/{world['other_user_id']}/payment", {"amount": "5"}),
        (f"/admin/users/{world['other_user_id']}/sessions/revoke", {}),
        (f"/admin/users/{uid}/chair", {"chair_id": str(other_chair.id)}),
        (f"/admin/users/{uid}/merge", {"target_id": str(world["user2_id"])}),
    ]
    for url, data in attempts:
        r = c.post(url, data={**data, "csrf_token": csrf}, follow_redirects=False)
        ok_redirect = r.status_code == 303 and "msg=" in r.headers["location"]
        assert not ok_redirect and r.status_code in (303, 403, 404), (url, r.status_code)
    for url in (f"/admin/exports/ledger.csv?chair={other_chair.id}", f"/admin/users/export.csv?chair={other_chair.id}",
                f"/admin/users?chair={other_chair.id}", f"/admin/users/{world['other_user_id']}"):
        assert c.get(url, follow_redirects=False).status_code in (403, 404), url
    assert snapshot(db_path) == before
    body = c.get("/admin/exports/ledger.csv").text + c.get("/admin/users/export.csv").text + c.get("/admin").text
    assert "Bob" not in body
    with read_session() as r:
        assert ledger.is_reversed(r, foreign_event.id) is False
        assert r.scalar(select(PaymentEvent.id).where(PaymentEvent.correction_of_id == foreign_pay.id)) is None


def test_scan_post_without_token_or_with_foreign_kind_token_changes_nothing(client, db, world, login, db_path):
    login(db.get(User, world["user_id"]))
    before = snapshot(db_path)
    double = scan_token(client, "double")
    for kind, data in (("single", {}), ("single", {"token": double}), ("single", {"token": "a.b"})):
        assert client.post(f"/coffee/{kind}", data=data, follow_redirects=False).status_code == 400
    assert snapshot(db_path) == before
