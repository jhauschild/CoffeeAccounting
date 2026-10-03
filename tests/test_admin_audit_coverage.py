"""PROMPT §7: every admin action leaves an audit entry; no secrets, source IP recorded."""

from __future__ import annotations

import json

from sqlalchemy import select

from app import cli
from app.db import read_session
from app.models import AdminUser, AuditLog
from tests import factories
from tests.admin_support import (  # noqa: F401
    CSRF_RE, NEW_PASSWORD, PASSWORD, current_code, fast_hasher, login_as, make_real_admin, new_client, page_csrf,
)

REQUIRED = {
    # logins, logout, TOTP
    "admin.login.failed", "admin.login.password_ok", "admin.login.success", "admin.logout", "admin.totp_enrolled",
    "admin.totp_reset", "admin.password_changed", "admin.sessions_revoked",
    # CLI admin management
    "admin.created", "admin.password_reset", "admin.chairs_set", "admin.disabled",
    # chairs, prices, users
    "chair.created", "chair.renamed", "chair.deactivated", "chair.reactivated", "price.added", "user.chair_changed",
    "user.updated", "user.merged", "user.deactivated", "user.reactivated", "user.sessions_revoked",
    # ledger
    "payment.recorded", "payment.corrected", "event.adjustment", "event.reversed",
    # exports
    "export.users_csv", "export.ledger_csv",
}


def test_every_admin_action_is_audited_without_secrets(app, db, chair, other_chair, price, monkeypatch):
    from sqlalchemy import select as sel
    # --- login + enrollment + logout through the real forms (failed attempt first)
    make_real_admin(username="newbie", totp=False)
    c = new_client(app)
    token = page_csrf(c, "/admin/login")
    c.post("/admin/login", data={"username": "newbie", "password": "wrong password!", "csrf_token": token})
    r = c.post("/admin/login", data={"username": "newbie", "password": PASSWORD, "csrf_token": token},
               follow_redirects=False)
    c.cookies.set("coffee_admin", next(x for x in r.headers.get_list("set-cookie") if x.startswith("coffee_admin="))
                  .split(";")[0].split("=", 1)[1], path="/admin")
    page = c.get("/admin/totp/setup")
    with read_session() as s:
        secret = s.scalars(sel(AdminUser).where(AdminUser.username == "newbie")).one().totp_secret
    done = c.post("/admin/totp/setup", data={"code": current_code(secret), "csrf_token": CSRF_RE.search(page.text).group(1)})
    codes = [x for x in done.text.split("<code>")[1:]]
    c.cookies.set("coffee_admin", next(x for x in done.headers.get_list("set-cookie") if x.startswith("coffee_admin="))
                  .split(";")[0].split("=", 1)[1], path="/admin")
    csrf = page_csrf(c, "/admin/account")
    c.post("/admin/account/password", data={"current_password": PASSWORD, "new_password": NEW_PASSWORD,
                                            "new_password2": NEW_PASSWORD, "csrf_token": csrf})
    c.post("/admin/account/sessions/revoke", data={"csrf_token": csrf})
    c.post("/admin/logout", data={"csrf_token": csrf})

    # --- admin work as a global admin
    admin_id, _ = make_real_admin(username="boss")
    g = new_client(app)
    gcsrf = login_as(g, admin_id)

    def post(path, **data):
        return g.post(path, data={"csrf_token": gcsrf, **data}, follow_redirects=False)

    alice = factories.make_user(db, "Alice", chair)
    dup = factories.make_user(db, "Alice 2", chair)
    events = factories.add_events(db, alice, ["single", "double"])
    post("/admin/chairs", full_name="Beans", short_name="BN")
    with read_session() as s:
        from app.models import Chair
        bn = s.scalars(sel(Chair).where(Chair.short_name == "BN")).one().id
    post(f"/admin/chairs/{bn}/rename", full_name="Beans 2", short_name="BN2")
    post(f"/admin/chairs/{bn}/active", active="0")
    post(f"/admin/chairs/{bn}/active", active="1")
    post("/admin/prices", price="0.80")
    post(f"/admin/users/{alice.id}/chair", chair_id=str(other_chair.id))
    post(f"/admin/users/{alice.id}/rename", display_name="Alice Q")
    post(f"/admin/users/{alice.id}/payment", amount="3,00")
    with read_session() as s:
        from app.models import PaymentEvent
        pid = s.scalars(sel(PaymentEvent)).one().id
    post(f"/admin/users/{alice.id}/payment", amount="1", correction_of=str(pid))
    post(f"/admin/users/{alice.id}/adjustment", quantity="1", note="x")
    post(f"/admin/users/{alice.id}/events/{events[0].id}/reverse")
    post(f"/admin/users/{alice.id}/status", active="0")
    post(f"/admin/users/{alice.id}/status", active="1")
    post(f"/admin/users/{alice.id}/sessions/revoke")
    post(f"/admin/users/{dup.id}/merge", target_id=str(alice.id))
    g.get("/admin/users/export.csv")
    g.get("/admin/exports/ledger.csv")

    # --- CLI management (system actor)
    import io
    assert cli.main(["set-admin-chairs", "--username", "x", "--chair", "BN2"]) == 1  # unknown admin: nothing audited
    make_real_admin(role="chair", chairs=[chair], username="cadm")
    assert cli.main(["set-admin-chairs", "--username", "cadm", "--chair", "BN2"]) == 0
    monkeypatch.setattr("sys.stdin", io.StringIO(NEW_PASSWORD + "\n"))
    assert cli.main(["reset-admin-password", "--username", "cadm", "--password-stdin"]) == 0
    assert cli.main(["reset-admin-totp", "--username", "newbie"]) == 0
    assert cli.main(["disable-admin", "--username", "cadm"]) == 0

    with read_session() as s:
        entries = list(s.scalars(select(AuditLog).order_by(AuditLog.id)))
        s.expunge_all()
    actions = {e.action for e in entries}
    assert REQUIRED <= actions, sorted(REQUIRED - actions)
    for e in entries:
        if e.action.startswith(("admin.created", "admin.chairs_set", "admin.password_reset", "admin.totp_reset", "admin.disabled")):
            assert e.actor_type in ("system", "admin")
    web = [e for e in entries if e.action in ("payment.recorded", "export.users_csv", "price.added", "user.merged")]
    assert all(e.actor_type == "admin" and e.actor_id and e.source_ip for e in web)
    login_failed = next(e for e in entries if e.action == "admin.login.failed")
    assert login_failed.meta["username_attempted"] == "newbie" and login_failed.meta["step"] == "password"

    dump = json.dumps([[e.action, e.actor_id, e.target_id, e.meta, e.source_ip] for e in entries])
    for secret_value in (PASSWORD, NEW_PASSWORD, "wrong password!", secret, "access-code", *(c.split("<")[0] for c in codes)):
        assert secret_value not in dump
