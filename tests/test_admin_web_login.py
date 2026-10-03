"""Admin login over HTTP: password, TOTP, recovery code, enrollment, rate limiting, cookies, CSRF."""

from __future__ import annotations

import re

from sqlalchemy import select

from app.db import read_session
from app.models import AdminSession, AdminUser, AuditLog
from app.services import admin_auth
from tests import factories
from tests.admin_support import (  # noqa: F401
    CSRF_RE, NEW_PASSWORD, PASSWORD, current_code, fast_hasher, login_as, make_real_admin, new_client, page_csrf,
)


def post_login(client, username="boss", password=PASSWORD):
    token = page_csrf(client, "/admin/login")
    return client.post("/admin/login", data={"username": username, "password": password, "csrf_token": token},
                       follow_redirects=False)


def admin_cookie(response):
    return next(c for c in response.headers.get_list("set-cookie") if c.startswith("coffee_admin="))


def test_login_page_and_csrf(client):
    r = client.get("/admin/login")
    assert r.status_code == 200 and 'name="password"' in r.text
    assert "coffee_admin_login" in r.headers["set-cookie"]
    r = client.post("/admin/login", data={"username": "boss", "password": PASSWORD, "csrf_token": "bogus"},
                    follow_redirects=False)
    assert r.status_code == 403  # login CSRF failure
    r = client.post("/admin/login", data={"username": "boss", "password": PASSWORD}, follow_redirects=False)
    assert r.status_code == 403


def test_full_login_with_totp_and_cookie_attributes(monkeypatch):
    from fastapi.testclient import TestClient
    from tests.conftest import reload_settings
    from app.main import create_app
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://testserver")
    reload_settings()
    client = TestClient(create_app(), base_url="https://testserver", raise_server_exceptions=False)
    _, secret = make_real_admin()
    r = post_login(client)
    assert r.status_code == 303 and r.headers["location"] == "/admin/totp"
    pending_cookie = admin_cookie(r)
    for attr in ("Path=/admin", "HttpOnly", "SameSite=lax", "Secure"):
        assert attr.lower() in pending_cookie.lower(), pending_cookie
    pending_token = pending_cookie.split(";")[0].split("=", 1)[1]
    client.cookies.set("coffee_admin", pending_token, path="/admin")
    assert client.get("/admin", follow_redirects=False).headers["location"] == "/admin/login"  # not yet complete
    page = client.get("/admin/totp")
    assert page.status_code == 200
    token = CSRF_RE.search(page.text).group(1)
    bad = client.post("/admin/totp", data={"code": "000000", "csrf_token": token}, follow_redirects=False)
    assert bad.status_code == 401
    ok = client.post("/admin/totp", data={"code": current_code(secret), "csrf_token": token}, follow_redirects=False)
    assert ok.status_code == 303 and ok.headers["location"] == "/admin"
    full_token = admin_cookie(ok).split(";")[0].split("=", 1)[1]
    assert full_token != pending_token  # rotated
    assert "max-age=43200" in admin_cookie(ok).lower()  # 12 hours
    client.cookies.set("coffee_admin", full_token, path="/admin")
    assert client.get("/admin").status_code == 200
    with read_session() as r:
        actions = [a.action for a in r.scalars(select(AuditLog).order_by(AuditLog.id))]
    assert actions[-3:] == ["admin.login.password_ok", "admin.login.failed", "admin.login.success"]
    assert PASSWORD not in str(actions)


def test_recovery_code_login(client):
    admin_id, _ = make_real_admin()
    from app.db import write_session
    codes = admin_auth.new_recovery_codes()
    with write_session() as w:
        w.get(AdminUser, admin_id).recovery_codes = [admin_auth._recovery_hash(c) for c in codes]
    r = post_login(client)
    client.cookies.set("coffee_admin", admin_cookie(r).split(";")[0].split("=", 1)[1], path="/admin")
    token = CSRF_RE.search(client.get("/admin/totp").text).group(1)
    ok = client.post("/admin/totp", data={"code": codes[3], "csrf_token": token}, follow_redirects=False)
    assert ok.status_code == 303 and ok.headers["location"] == "/admin"
    with read_session() as r:
        assert len(r.get(AdminUser, admin_id).recovery_codes) == 7


def test_enrollment_flow_shows_recovery_codes_once(client):
    admin_id, _ = make_real_admin(totp=False)
    r = post_login(client)
    assert r.headers["location"] == "/admin/totp/setup"
    client.cookies.set("coffee_admin", admin_cookie(r).split(";")[0].split("=", 1)[1], path="/admin")
    assert client.get("/admin/users", follow_redirects=False).status_code == 303  # nothing works before enrollment
    page = client.get("/admin/totp/setup")
    assert page.status_code == 200 and "<svg" in page.text and "otpauth" not in page.text
    token = CSRF_RE.search(page.text).group(1)
    with read_session() as r:
        secret = r.get(AdminUser, admin_id).totp_secret
    assert secret and secret.replace("", "") and " ".join(secret[i:i + 4] for i in range(0, len(secret), 4)) in page.text
    bad = client.post("/admin/totp/setup", data={"code": "123456", "csrf_token": token})
    assert bad.status_code == 401
    ok = client.post("/admin/totp/setup", data={"code": current_code(secret), "csrf_token": token})
    assert ok.status_code == 200
    codes = re.findall(r"<code>([A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4})</code>", ok.text)
    assert len(codes) == 8
    new_cookie = admin_cookie(ok).split(";")[0].split("=", 1)[1]
    client.cookies.set("coffee_admin", new_cookie, path="/admin")
    assert client.get("/admin").status_code == 200
    with read_session() as r:
        stored = r.get(AdminUser, admin_id)
        assert stored.totp_enabled and not set(codes) & set(stored.recovery_codes)
        assert [a.action for a in r.scalars(select(AuditLog)) if a.action == "admin.totp_enrolled"]


def test_web_rate_limit_after_five_failures(client):
    make_real_admin()
    for _ in range(5):
        assert post_login(client, password="wrong wrong wrong").status_code == 401
    assert post_login(client).status_code == 429  # even the right password
    other = new_client(client.app)
    assert post_login(other, username="somebody else").status_code == 401  # other username: own bucket


def test_logout_revokes_session(client, app):
    admin_id, _ = make_real_admin()
    csrf = login_as(client, admin_id)
    cookie = client.cookies.get("coffee_admin")
    r = client.post("/admin/logout", data={"csrf_token": csrf}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/admin/login"
    stale = new_client(app)
    stale.cookies.set("coffee_admin", cookie, path="/admin")
    assert stale.get("/admin", follow_redirects=False).status_code == 303
    with read_session() as r:
        assert "admin.logout" in [a.action for a in r.scalars(select(AuditLog))]


def test_csrf_required_on_admin_post(client, db, chair, price):
    admin_id, _ = make_real_admin()
    user = factories.make_user(db, "Alice", chair)
    login_as(client, admin_id)
    for token in (None, "bogus"):
        data = {"amount": "5.00"} | ({"csrf_token": token} if token else {})
        r = client.post(f"/admin/users/{user.id}/payment", data=data, follow_redirects=False)
        assert r.status_code == 403
    from app.models import PaymentEvent
    with read_session() as r:
        assert r.scalar(select(__import__("sqlalchemy").func.count()).select_from(PaymentEvent)) == 0


def test_csrf_token_of_another_session_is_rejected(client, app, db, chair, price):
    a, _ = make_real_admin(username="a")
    b, _ = make_real_admin(username="b")
    user = factories.make_user(db, "Alice", chair)
    login_as(client, a)
    other_csrf = login_as(new_client(app), b)
    r = client.post(f"/admin/users/{user.id}/payment", data={"amount": "5", "csrf_token": other_csrf},
                    follow_redirects=False)
    assert r.status_code == 403


def test_normal_user_session_cannot_reach_admin(client, db, chair, login):
    user = factories.make_user(db, "Alice", chair)
    login(user)
    for path in ("/admin", "/admin/users", "/admin/chairs", "/admin/audit"):
        r = client.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/admin/login"
    # even a user token planted in the admin cookie is worthless
    client.cookies.set("coffee_admin", client.cookies.get("coffee_session"), path="/admin")
    assert client.get("/admin", follow_redirects=False).status_code == 303


def test_disabled_admin_session_stops_working(client):
    admin_id, _ = make_real_admin()
    login_as(client, admin_id)
    assert client.get("/admin").status_code == 200
    from app.db import write_session
    with write_session() as w:
        admin_auth.set_admin_active(w, w.get(AdminUser, admin_id), False)
    assert client.get("/admin", follow_redirects=False).status_code == 303


def test_password_change_revokes_other_sessions(client, app):
    admin_id, _ = make_real_admin()
    csrf = login_as(client, admin_id)
    other = new_client(app)
    login_as(other, admin_id)
    assert other.get("/admin").status_code == 200
    r = client.post("/admin/account/password", follow_redirects=False,
                    data={"current_password": "not right at all", "new_password": NEW_PASSWORD,
                          "new_password2": NEW_PASSWORD, "csrf_token": csrf})
    assert "err=wrong_password" in r.headers["location"]
    r = client.post("/admin/account/password", follow_redirects=False,
                    data={"current_password": PASSWORD, "new_password": "short", "new_password2": "short",
                          "csrf_token": csrf})
    assert "err=password_weak" in r.headers["location"]
    r = client.post("/admin/account/password", follow_redirects=False,
                    data={"current_password": PASSWORD, "new_password": NEW_PASSWORD, "new_password2": NEW_PASSWORD,
                          "csrf_token": csrf})
    assert "msg=password_changed" in r.headers["location"]
    assert client.get("/admin").status_code == 200
    assert other.get("/admin", follow_redirects=False).status_code == 303
    with read_session() as r:
        assert admin_auth.verify_password(r.get(AdminUser, admin_id).password_hash, NEW_PASSWORD)
        assert "admin.password_changed" in [a.action for a in r.scalars(select(AuditLog))]


def test_revoke_other_sessions_button(client, app):
    admin_id, _ = make_real_admin()
    csrf = login_as(client, admin_id)
    other = new_client(app)
    login_as(other, admin_id)
    r = client.post("/admin/account/sessions/revoke", data={"csrf_token": csrf}, follow_redirects=False)
    assert "msg=sessions_revoked" in r.headers["location"]
    assert other.get("/admin", follow_redirects=False).status_code == 303 and client.get("/admin").status_code == 200


def test_bootstrap_on_app_start(monkeypatch):
    from fastapi.testclient import TestClient
    from tests.conftest import reload_settings
    from app.main import create_app
    monkeypatch.setenv("ADMIN_BOOTSTRAP_USERNAME", "first")
    monkeypatch.setenv("ADMIN_BOOTSTRAP_PASSWORD", PASSWORD)
    reload_settings()
    with TestClient(create_app()):
        pass
    with TestClient(create_app()):  # second start: ignored, still one admin
        pass
    with read_session() as r:
        assert [a.username for a in admin_auth.list_admins(r)] == ["first"]
