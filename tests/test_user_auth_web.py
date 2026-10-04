"""user-web (task 2.5): /login, /logout, /register, /verify, /forgot, /reset over HTTP (memory mail backend)."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.db import write_session
from app.models import (AuditLog, ConsumptionEvent, PasswordResetToken, PendingAction, PendingRegistration,
                        RateLimitEvent, User, UserSession)
from app.services import mail, passwords, pending, sessions
from app.timeutil import utcnow
from tests import factories
from tests.conftest import reload_settings
from tests.user_support import PASSWORD, counts, event_id_from, events, field, make_account, post_scan, sign_in

NEW_PASSWORD = "an even better battery"


@pytest.fixture(autouse=True)
def memory_mail(monkeypatch):
    monkeypatch.setenv("MAIL_BACKEND", "memory")
    reload_settings()
    mail.clear_outbox()
    mail.reset_status()
    yield
    mail.clear_outbox()
    mail.reset_status()


def _db_counts(db):
    db.rollback()
    return {m.__name__: db.scalar(select(func.count()).select_from(m))
            for m in (User, UserSession, PendingRegistration, PasswordResetToken, PendingAction, ConsumptionEvent,
                      AuditLog, RateLimitEvent)}


def _link(path: str) -> str:
    (message,) = [m for m in mail.get_outbox() if path in m.body]
    (url,) = [u for u in mail.extract_links(message) if path in u]
    return "/" + url.split("/", 3)[3]


def _csrf(client, path):
    return field(client.get(path).text, "csrf_token")


def _register_form(chair, **over):
    data = {"username": "erika", "display_name": "Erika Muster", "chair_id": str(chair.id),
            "email": "erika@tum.de", "password": PASSWORD, "password2": PASSWORD, "privacy_ack": "1"}
    data.update(over)
    return data


def _register(client, chair, **over):
    data = _register_form(chair, **over)
    data["csrf_token"] = _csrf(client, "/register")
    return client.post("/register", data=data, follow_redirects=False)


# ----- scan -> /login -------------------------------------------------------------------------------------
def test_scan_without_a_session_stores_the_coffee_and_goes_to_login(client, db, price):
    r = post_scan(client, "single")
    assert r.status_code == 303 and r.headers["location"] == "/login"
    page = client.get("/login")
    assert "will be recorded as soon as you have signed in" in page.text
    assert 'href="/register"' in page.text and "Create account" in page.text and 'href="/forgot"' in page.text
    assert events(db) == []


def test_login_page_writes_nothing_and_has_the_fields(client, db):
    before = _db_counts(db)
    r = client.get("/login")
    assert r.status_code == 200 and _db_counts(db) == before
    for name in ("username", "password", "csrf_token"):
        assert f'name="{name}"' in r.text
    assert 'type="password"' in r.text and 'autocomplete="current-password"' in r.text
    assert "coffee_csrf=" in r.headers["set-cookie"]
    assert r.headers["cache-control"] == "no-store"


def test_login_notice_is_whitelisted(client):
    assert "password has been changed" in client.get("/login?notice=reset").text
    assert "<script>" not in client.get("/login?notice=<script>").text
    assert "password has been changed" not in client.get("/login?notice=whatever").text


# ----- login ----------------------------------------------------------------------------------------------
def test_login_success_goes_to_the_account_with_a_session_cookie(client, db, chair):
    alice = make_account(db, "Alice", chair)
    r = sign_in(client, alice)
    assert r.status_code == 303 and r.headers["location"] == "/account"
    assert "coffee_session=" in r.headers["set-cookie"]
    page = client.get("/account")
    assert page.status_code == 200 and "Alice" in page.text


@pytest.mark.parametrize("kind,label", [("single", "Single recorded"), ("double", "Double recorded")])
def test_login_records_the_pending_coffee_once(client, db, chair, price, kind, label):
    alice = make_account(db, "Alice", chair)
    post_scan(client, kind)
    r = sign_in(client, alice)
    done = r.headers["location"]
    assert done.startswith("/coffee/done/")
    (event,) = events(db)
    assert done.endswith(str(event.id)) and event.user_id == alice.id
    assert label in client.get(done).text and "Undo this coffee" in client.get(done).text
    assert any(c.startswith("coffee_pending=") and ('=""' in c or "Max-Age=0" in c)
               for c in r.headers.get_list("set-cookie"))  # the pending cookie is cleared
    # signing in again (another tab) records nothing new
    again = sign_in(client, alice)
    assert again.headers["location"] == "/account" and len(events(db)) == 1
    assert event_id_from(post_scan(client, "single")) and len(events(db)) == 2


def test_login_with_a_view_site_pending_goes_to_the_overview(client, db, chair):
    alice = make_account(db, "Alice", chair)
    with write_session() as w:
        pid = pending.create_view_site_pending(w)
    client.cookies.set("coffee_pending", pid)
    assert "overview as soon as you have signed in" in client.get("/login").text
    r = sign_in(client, alice)
    assert r.status_code == 303 and r.headers["location"] == "/overview"
    db.rollback()
    assert db.scalars(select(PendingAction)).one().consumed_at is not None


def test_login_after_an_expired_scan_explains_it(client, db, chair, price):
    alice = make_account(db, "Alice", chair)
    post_scan(client, "single")
    db.rollback()
    db.query(PendingAction).update({PendingAction.consumed_at: utcnow()})
    db.commit()
    assert sign_in(client, alice).headers["location"] == "/account?notice=expired"


def test_login_without_a_price_keeps_the_account_signed_in(client, db, chair):
    alice = make_account(db, "Alice", chair)
    post_scan(client, "single")
    assert sign_in(client, alice).headers["location"] == "/account?notice=no_price"
    assert "no coffee price" in client.get("/account?notice=no_price").text


def test_failed_login_is_generic_and_sets_no_session(client, db, chair):
    alice = make_account(db, "Alice", chair)
    wrong = sign_in(client, alice, "not the password")
    unknown = sign_in(client, "nobody", PASSWORD)
    for r in (wrong, unknown):
        assert r.status_code == 401 and "Username or password is not correct" in r.text
        assert "coffee_session" not in r.headers.get("set-cookie", "")
    assert 'value="nobody"' in unknown.text and PASSWORD not in unknown.text  # username kept, password never echoed
    # the failures were committed, so they count
    db.rollback()
    assert db.scalar(select(func.count()).select_from(RateLimitEvent).where(RateLimitEvent.bucket == "login")) == 2


def test_login_is_rate_limited_with_a_clear_message(client, db, chair):
    alice = make_account(db, "Alice", chair)
    for _ in range(5):
        assert sign_in(client, alice, "nope nope nope").status_code == 401
    r = sign_in(client, alice)
    assert r.status_code == 429 and "Too many attempts" in r.text and "coffee_session" not in r.headers.get("set-cookie", "")


def test_login_rotates_the_session_of_the_browser(client, db, chair):
    alice = make_account(db, "Alice", chair)
    sign_in(client, alice)
    old = client.cookies.get("coffee_session")
    sign_in(client, alice)
    new = client.cookies.get("coffee_session")
    assert old != new
    from app.db import read_session

    with read_session() as r:
        assert sessions.resolve_session(r, old, touch=False) is None
        assert sessions.resolve_session(r, new, touch=False) is not None


@pytest.mark.parametrize("state", ["inactive", "unverified"])
def test_unusable_accounts_cannot_log_in(client, db, chair, state):
    alice = make_account(db, "Alice", chair)
    if state == "inactive":
        alice.status = "inactive"
    else:
        alice.verified_at = None
    db.commit()
    r = sign_in(client, alice)
    assert r.status_code == 401 and "Username or password is not correct" in r.text


def test_login_requires_csrf(client, db, chair):
    alice = make_account(db, "Alice", chair)
    client.get("/login")
    r = client.post("/login", data={"username": alice.username, "password": PASSWORD}, follow_redirects=False)
    assert r.status_code == 403 and "coffee_session" not in r.headers.get("set-cookie", "")


def test_overlong_fields_are_refused_by_the_form_limit(client, db):
    token = _csrf(client, "/login")
    r = client.post("/login", data={"csrf_token": token, "username": "u" * 5000, "password": "p"})
    assert r.status_code == 400


# ----- logout ---------------------------------------------------------------------------------------------
def test_logout_revokes_the_session_and_needs_csrf(client, db, chair):
    alice = make_account(db, "Alice", chair)
    sign_in(client, alice)
    raw = client.cookies.get("coffee_session")
    assert client.post("/logout", data={}, follow_redirects=False).status_code == 403
    csrf = field(client.get("/account").text, "csrf_token")
    r = client.post("/logout", data={"csrf_token": csrf}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/?notice=left"
    from app.db import read_session

    with read_session() as rs:
        assert sessions.resolve_session(rs, raw, touch=False) is None
    assert client.get("/account", follow_redirects=False).headers["location"] == "/login"
    assert "You have been signed out" in client.get("/?notice=left").text


def test_logout_without_a_session_goes_to_login(client):
    r = client.post("/logout", data={"csrf_token": "x"}, follow_redirects=False)
    assert r.status_code == 403  # no binding at all


# ----- register -------------------------------------------------------------------------------------------
def test_register_page_has_the_member_form(client, db, chair):
    page = client.get("/register")
    assert page.status_code == 200
    for name in ("username", "display_name", "chair_id", "email", "password", "password2", "privacy_ack"):
        assert f'name="{name}"' in page.text
    assert str(chair.id) in page.text and "coffee_csrf=" in page.headers["set-cookie"]


def test_register_sends_one_mail_and_shows_the_neutral_page(client, db, chair):
    before = _db_counts(db)
    r = _register(client, chair)
    assert r.status_code == 200 and "Check your mail" in r.text
    (message,) = mail.get_outbox()
    assert message.to == "erika@tum.de" and "/verify/" in message.body
    after = _db_counts(db)
    assert after["PendingRegistration"] == before["PendingRegistration"] + 1 and after["User"] == before["User"]


def test_register_gives_the_same_page_for_a_known_email_and_a_different_mail(client, db, chair):
    factories.make_member(db, "Existing", chair, username="existing", email="erika@tum.de")
    new = _register(client, chair, username="newname", email="fresh@tum.de")
    known = _register(client, chair, username="otherone", email="erika@tum.de")
    assert new.status_code == known.status_code == 200 and new.text == known.text
    fresh_mail, known_mail = mail.get_outbox()
    assert "/verify/" in fresh_mail.body
    assert "/verify/" not in known_mail.body and "already have an account" in known_mail.body.lower()
    assert _db_counts(db)["PendingRegistration"] == 1


@pytest.mark.parametrize("over,needle", [
    ({"username": "x"}, "3 to 32 characters"),
    ({"username": "Bad Name!"}, "lower-case letters"),
    ({"email": "erika@gmail.com"}, "university e-mail"),
    ({"email": "nonsense"}, "valid e-mail"),
    ({"password": "short", "password2": "short"}, "too short"),
    ({"password": "erika", "password2": "erika", "username": "erika"}, "too short"),
    ({"password2": "different battery"}, "not the same"),
    ({"privacy_ack": ""}, "privacy information"),
    ({"chair_id": ""}, "Please choose"),
    ({"display_name": "  "}, "Please enter a name"),
])
def test_register_validation_errors_are_shown_and_send_nothing(client, db, chair, over, needle):
    before = _db_counts(db)
    r = _register(client, chair, **over)
    assert r.status_code == 400 and needle in r.text
    assert 'value="erika@' in r.text or "email" in over  # entered values are kept ...
    assert PASSWORD not in r.text  # ... except passwords
    assert mail.get_outbox() == []
    after = _db_counts(db)
    assert after["PendingRegistration"] == before["PendingRegistration"]
    assert after["RateLimitEvent"] == before["RateLimitEvent"]  # a refused form does not use up the limits


def test_register_username_taken_by_a_user_or_a_cli_admin(client, db, chair, global_admin):
    factories.make_member(db, "Existing", chair, username="erika")
    assert "already taken" in _register(client, chair).text
    assert "already taken" in _register(client, chair, username=global_admin.username).text
    assert mail.get_outbox() == []


def test_register_is_rate_limited_per_ip(client, db, chair):
    for i in range(10):
        assert _register(client, chair, username=f"user{i}", email=f"u{i}@tum.de").status_code == 200
    r = _register(client, chair, username="onetoomany", email="late@tum.de")
    assert r.status_code == 429 and "Too many attempts" in r.text


def test_register_requires_csrf(client, db, chair):
    client.get("/register")
    r = client.post("/register", data=_register_form(chair), follow_redirects=False)
    assert r.status_code == 403 and mail.get_outbox() == []


def test_register_inactive_chair_is_refused(client, db, chair):
    off = factories.make_chair(db, short_name="OFF", active=False)
    r = _register(client, chair, chair_id=str(off.id))
    assert r.status_code == 400 and "Please choose" in r.text


# ----- verify ---------------------------------------------------------------------------------------------
def _registered_link(client, chair, **over):
    _register(client, chair, **over)
    return _link("/verify/")


def test_verify_get_shows_the_confirm_page_and_writes_nothing(client, db, chair):
    link = _registered_link(client, chair)
    before = _db_counts(db)
    for _ in range(2):  # a mail scanner prefetching the link
        r = client.get(link)
        assert r.status_code == 200 and "erika" in r.text and "Erika Muster" in r.text and "CHA" in r.text
        assert 'method="post"' in r.text and "Confirm and sign in" in r.text
        assert "erika@tum.de" not in r.text
    assert _db_counts(db) == before


def test_verify_post_creates_the_member_and_signs_in(client, db, chair):
    link = _registered_link(client, chair)
    page = client.get(link)
    r = client.post(link, data={"csrf_token": field(page.text, "csrf_token")}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/account?notice=registered"
    assert "coffee_session=" in r.headers["set-cookie"]
    db.rollback()
    user = db.scalars(select(User).where(User.username == "erika")).one()
    assert user.account_kind == "member" and user.email == "erika@tum.de" and user.verified_at is not None
    assert passwords.verify_password(user.password_hash, PASSWORD)
    assert "Your account is ready" in client.get(r.headers["location"]).text
    # the link is single use
    again = client.get(link)
    assert again.status_code == 400 and "not valid" in again.text


def test_verify_records_the_pending_coffee(client, db, chair, price):
    post_scan(client, "double")
    link = _registered_link(client, chair)
    page = client.get(link)
    r = client.post(link, data={"csrf_token": field(page.text, "csrf_token")}, follow_redirects=False)
    done = event_id_from(r)
    (event,) = events(db)
    assert str(event.id) == done and event.quantity == 2


def test_verify_in_a_fresh_browser_works_with_its_own_csrf_cookie(client, db, chair, app):
    link = _registered_link(client, chair)
    with TestClient(app, raise_server_exceptions=False) as mail_app_browser:
        page = mail_app_browser.get(link)
        r = mail_app_browser.post(link, data={"csrf_token": field(page.text, "csrf_token")}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/account?notice=registered"


def test_verify_double_submit_creates_one_user_and_the_second_goes_to_the_account(client, db, chair):
    link = _registered_link(client, chair)
    token = field(client.get(link).text, "csrf_token")
    first = client.post(link, data={"csrf_token": token}, follow_redirects=False)
    # the second tap still carries the session cookie of the first response
    second = client.post(link, data={"csrf_token": token}, follow_redirects=False)
    assert first.status_code == 303 and second.status_code in (303, 403)
    db.rollback()
    assert db.scalar(select(func.count()).select_from(User).where(User.username == "erika")) == 1


def test_verify_without_the_csrf_token_creates_nothing(client, db, chair):
    link = _registered_link(client, chair)
    client.get(link)
    r = client.post(link, data={}, follow_redirects=False)
    assert r.status_code == 403
    db.rollback()
    assert db.scalar(select(func.count()).select_from(User).where(User.username == "erika")) == 0


@pytest.mark.parametrize("token", ["nonsense", "a" * 43, "é" * 10, "x" * 300])
def test_verify_unknown_tokens_are_one_page(client, token):
    r = client.get(f"/verify/{token}")
    assert r.status_code == 400 and "not valid" in r.text


def test_verify_conflicts_are_explained(client, db, chair):
    link = _registered_link(client, chair)
    factories.make_member(db, "Squatter", chair, username="erika", email="squatter@tum.de")  # took the name meanwhile
    page_token = field(client.get(link).text, "csrf_token")
    r = client.post(link, data={"csrf_token": page_token}, follow_redirects=False)
    assert r.status_code == 409 and "username has been taken" in r.text and "coffee_session" not in r.headers.get("set-cookie", "")


def test_verify_expired_token(client, db, chair):
    link = _registered_link(client, chair)
    from datetime import timedelta

    from app.timeutil import utcnow

    db.rollback()
    db.query(PendingRegistration).update({PendingRegistration.expires_at: utcnow() - timedelta(minutes=1)})
    db.commit()
    assert client.get(link).status_code == 400


# ----- forgot / reset -------------------------------------------------------------------------------------
def _forgot(client, username):
    return client.post("/forgot", data={"csrf_token": _csrf(client, "/forgot"), "username": username},
                       follow_redirects=False)


def test_forgot_page_and_the_neutral_answer(client, db, chair):
    assert client.get("/forgot").status_code == 200 and 'name="username"' in client.get("/forgot").text
    make_account(db, "Alice", chair, username="alice")
    known, unknown = _forgot(client, "alice"), _forgot(client, "nobody")
    assert known.status_code == unknown.status_code == 200 and known.text == unknown.text
    assert "If the account exists" in known.text
    (message,) = mail.get_outbox()  # only the known account got a mail
    assert message.to == "alice@tum.de" and "/reset/" in message.body and "alice" in message.body


def test_forgot_for_a_guest_mails_the_sponsor(client, db, chair):
    sponsor = make_account(db, "Sponsor", chair, username="sponsor")
    factories.make_guest(db, sponsor, "Gast", username="gast", password_hash=passwords.hash_password(PASSWORD))
    _forgot(client, "gast")
    (message,) = mail.get_outbox()
    assert message.to == sponsor.email and "gast" in message.body


def test_forgot_is_rate_limited(client, db, chair):
    make_account(db, "Alice", chair, username="alice")
    assert [_forgot(client, "alice").status_code for _ in range(3)] == [200, 200, 200]
    r = _forgot(client, "alice")
    assert r.status_code == 429 and "Too many attempts" in r.text


def test_forgot_requires_csrf(client, db, chair):
    make_account(db, "Alice", chair, username="alice")
    client.get("/forgot")
    assert client.post("/forgot", data={"username": "alice"}).status_code == 403
    assert mail.get_outbox() == []


def test_full_reset_flow(client, db, chair):
    alice = make_account(db, "Alice", chair, username="alice")
    sign_in(client, alice)
    raw_session = client.cookies.get("coffee_session")
    _forgot(client, "alice")
    link = _link("/reset/")
    before = _db_counts(db)
    page = client.get(link)
    assert page.status_code == 200 and "alice" in page.text and 'name="password2"' in page.text
    assert _db_counts(db) == before  # GET writes nothing
    r = client.post(link, data={"csrf_token": field(page.text, "csrf_token"), "password": NEW_PASSWORD,
                                "password2": NEW_PASSWORD}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login?notice=reset"
    assert "coffee_session" not in r.headers.get("set-cookie", "")  # no sign-in by the reset itself
    from app.db import read_session

    with read_session() as rs:
        assert sessions.resolve_session(rs, raw_session, touch=False) is None  # all sessions are gone
    assert client.get("/account", follow_redirects=False).headers["location"] == "/login"
    assert sign_in(client, alice, PASSWORD).status_code == 401
    assert sign_in(client, alice, NEW_PASSWORD).status_code == 303
    # the link is single use
    assert client.get(link).status_code == 400
    assert client.post(link, data={"csrf_token": _csrf(client, "/login"), "password": "x" * 12,
                                   "password2": "x" * 12}).status_code in (400, 403)


def test_reset_weak_password_and_mismatch_keep_the_link_alive(client, db, chair):
    make_account(db, "Alice", chair, username="alice")
    _forgot(client, "alice")
    link = _link("/reset/")
    token = field(client.get(link).text, "csrf_token")
    r = client.post(link, data={"csrf_token": token, "password": "short", "password2": "short"})
    assert r.status_code == 400 and "too short" in r.text and "alice" in r.text
    r = client.post(link, data={"csrf_token": token, "password": NEW_PASSWORD, "password2": "something else here"})
    assert r.status_code == 400 and "not the same" in r.text
    r = client.post(link, data={"csrf_token": token, "password": NEW_PASSWORD, "password2": NEW_PASSWORD},
                    follow_redirects=False)
    assert r.status_code == 303


def test_reset_unknown_and_expired_links_are_one_page(client, db, chair):
    for path in ("/reset/nonsense", "/reset/" + "a" * 43, "/reset/" + "x" * 300):
        r = client.get(path)
        assert r.status_code == 400 and "not valid" in r.text
    make_account(db, "Alice", chair, username="alice")
    _forgot(client, "alice")
    link = _link("/reset/")
    from datetime import timedelta

    from app.timeutil import utcnow

    db.rollback()
    db.query(PasswordResetToken).update({PasswordResetToken.expires_at: utcnow() - timedelta(minutes=1)})
    db.commit()
    assert client.get(link).status_code == 400
    assert client.post(link, data={"csrf_token": _csrf(client, "/login"), "password": NEW_PASSWORD,
                                   "password2": NEW_PASSWORD}).status_code in (400, 403)


def test_reset_requires_csrf(client, db, chair):
    make_account(db, "Alice", chair, username="alice")
    _forgot(client, "alice")
    link = _link("/reset/")
    client.get(link)
    r = client.post(link, data={"password": NEW_PASSWORD, "password2": NEW_PASSWORD}, follow_redirects=False)
    assert r.status_code == 403
    db.rollback()
    assert db.scalars(select(PasswordResetToken)).one().consumed_at is None


# ----- no GET writes, pages ------------------------------------------------------------------------------
def test_gets_of_the_auth_pages_never_write(client, db, chair):
    make_account(db, "Alice", chair, username="alice")
    _forgot(client, "alice")
    reset = _link("/reset/")
    verify = _registered_link(client, chair)
    before = _db_counts(db)
    for path in ("/login", "/login?notice=reset", "/register", "/forgot", reset, verify, "/verify/nonsense",
                 "/reset/nonsense", "/"):
        assert client.get(path).status_code in (200, 400), path
    assert _db_counts(db) == before


def test_home_links_to_sign_in_and_register_for_anonymous_visitors(client):
    page = client.get("/").text
    assert 'href="/login"' in page and 'href="/register"' in page
    assert "access code" not in page.lower()


@pytest.mark.parametrize("path", ["/join", "/profiles", "/profiles/select", "/account/leave"])
def test_the_v1_gate_routes_are_gone(client, path):
    assert client.get(path, follow_redirects=False).status_code in (404, 405)
    assert client.post(path, data={"code": "x"}, follow_redirects=False).status_code in (404, 405)


def test_the_gate_cookie_opens_nothing(client):
    client.cookies.set("coffee_gate", "anything")
    assert "name=\"code\"" not in client.get("/login").text
    assert client.get("/account", follow_redirects=False).headers["location"] == "/login"
