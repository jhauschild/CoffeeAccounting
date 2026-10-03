"""Security review (brief 06): XSS in every template, CSV formula injection, SQL injection via
search/sort/filter params, header injection, request size, static path traversal, unsafe
deserialization, headers/CSP, fail-closed configuration and secret leakage."""

from __future__ import annotations

import csv
import io
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import DEV_SECRET_KEY, Settings
from app.db import get_engine
from app.main import create_app
from app.services import admin_auth, ledger
from app.db import write_session
from tests import factories
from tests.admin_support import fast_hasher, login_as  # noqa: F401
from tests.conftest import ROOT, reload_settings
from tests.test_platform_web import PROD_ENV
from tests.user_support import field, pass_gate

XSS = '"><svg/onload=alert(1)><script>x</script>'
MARKERS = ("<svg/onload", "<script>x")


def _admin(db, **kw):
    """Factory admin with TOTP marked enabled, so `login_as` yields a complete session."""
    admin = factories.make_admin(db, **kw)
    admin.totp_enabled, admin.totp_secret = True, "JBSWY3DPEHPK3PXP"
    db.commit()
    return admin


def _clean(html: str) -> bool:
    return not any(m in html for m in MARKERS)


@pytest.fixture
def poisoned(db, price):
    """Every user/admin-controlled text field carries an XSS payload."""
    chair = factories.make_chair(db, short_name="X<s>'\"", full_name=XSS)
    victim = factories.make_user(db, XSS, chair=chair)
    admin = _admin(db, role="global", username="adm" + XSS)
    factories.add_events(db, victim, "single")
    factories.make_payment(db, victim, admin, 120, note=XSS)
    with write_session() as w:
        ledger.add_adjustment(w, admin=w.get(type(admin), admin.id), user_id=victim.id, quantity=1, note=XSS)
        from app.services import prices
        prices.add_price(w, price_per_shot_cents=55, admin_id=admin.id, note=XSS)
    db.expire_all()
    return {"chair": chair, "user": victim, "admin": admin}


def test_xss_payloads_escaped_in_every_page(client, db, poisoned, login, app):
    victim = poisoned["user"]
    login(victim)
    event_id = ledger.recent_consumption(db, victim.id, 5)[-1].id
    user_pages = ["/", "/account", "/account/edit", f"/coffee/done/{event_id}", "/profiles", "/profiles?q=" + XSS,
                  "/register", "/join", "/privacy", "/coffee/single"]
    for p in user_pages:
        r = client.get(p)
        assert r.status_code == 200 and _clean(r.text), p
    # registration form echo and duplicate warning
    page = client.get("/register")
    r = client.post("/register", data={"csrf_token": field(page.text, "csrf_token"), "privacy_ack": "",
                                       "registration_token": field(page.text, "registration_token"),
                                       "display_name": XSS, "chair_id": str(poisoned["chair"].id)})
    assert _clean(r.text)
    ac = TestClient(app, raise_server_exceptions=False)
    csrf = login_as(ac, poisoned["admin"].id)
    uid = victim.id
    admin_pages = ["/admin", "/admin/users", "/admin/users?q=" + XSS, f"/admin/users/{uid}",
                   f"/admin/users/{uid}/merge?q=a", "/admin/audit", "/admin/chairs", "/admin/prices",
                   "/admin/exports", "/admin/account", "/admin/qr", "/admin/users?err=" + XSS, "/admin?msg=" + XSS]
    for p in admin_pages:
        r = ac.get(p)
        assert r.status_code == 200 and _clean(r.text), p
    assert _clean(ac.post("/admin/qr", data={"csrf_token": csrf, "line": XSS}).text)
    assert _clean(ac.get("/admin/qr/single.svg").text)


@pytest.mark.parametrize("evil", ["=HYPERLINK(\"http://x\")", "+1+1", "-1+1", "@SUM(A1)", " =1+1", "=1;2\"3"])
def test_csv_exports_neutralize_formulas(app, db, price, evil):
    chair = factories.make_chair(db, short_name=evil[:20], full_name=evil)
    u = factories.make_user(db, evil, chair=chair)
    admin = _admin(db, role="global", username=evil)
    factories.add_events(db, u, "single")
    factories.make_payment(db, u, admin, 100, note=evil)
    c = TestClient(app, raise_server_exceptions=False)
    login_as(c, admin.id)
    for url in ("/admin/users/export.csv", "/admin/exports/ledger.csv"):
        r = c.get(url)
        assert r.status_code == 200 and r.headers["content-disposition"].startswith('attachment; filename="')
        rows = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig")), delimiter=";"))
        width = len(rows[0])
        for row in rows[1:]:
            assert len(row) == width, row  # quoting kept the structure
            for cell in row:
                if evil.strip() in cell:
                    assert cell.startswith("'"), (url, cell)


SQLI = ["' OR '1'='1", "%", "_", "\\", "a' --", "1); DROP TABLE users; --", "\" OR 1=1 --"]


@pytest.mark.parametrize("payload", SQLI)
def test_sql_injection_attempts_are_inert(client, db, user, gate_cookie, app, payload):
    r = client.get("/profiles", params={"q": payload})
    assert r.status_code == 200 and "Alice" not in r.text  # no wildcard / tautology match
    admin = _admin(db, role="global")
    c = TestClient(app, raise_server_exceptions=False)
    login_as(c, admin.id)
    for params in ({"q": payload}, {"sort": payload}, {"dir": payload[:4]}, {"status": payload[:10]},
                   {"chair": payload}, {"page": payload}):
        r = c.get("/admin/users", params=params, follow_redirects=False)
        assert r.status_code in (200, 400, 404), (params, r.status_code)
    for url, params in (("/admin/audit", {"action": payload}), ("/admin/exports/ledger.csv", {"from": payload[:10]}),
                        ("/admin/users/export.csv", {"q": payload})):
        assert c.get(url, params=params, follow_redirects=False).status_code in (200, 303, 400, 404)
    assert c.get("/admin/users", params={"q": "%"}).text.count("Alice") == 0


def test_no_header_injection_via_params(app, db):
    admin = _admin(db, role="global")
    c = TestClient(app, raise_server_exceptions=False)
    login_as(c, admin.id)
    r = c.get("/admin/users/export.csv", params={"q": "x\r\nSet-Cookie: pwn=1", "sort": "name\r\nX-Evil: 1"})
    assert "pwn" not in r.headers.get("set-cookie", "") and "x-evil" not in r.headers
    r = c.get("/admin/users", params={"msg": "x\r\nX-Evil: 1"}, follow_redirects=False)
    assert "x-evil" not in r.headers


def test_chunked_body_over_limit_rejected(client, gate_cookie):
    def body():
        for _ in range(100):
            yield b"display_name=" + b"A" * 1024 + b"&"

    r = client.post("/register", content=body(), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 413


@pytest.mark.parametrize("path", ["/static/../app/config.py", "/static/%2e%2e/app/config.py",
                                  "/static/..%2fapp%2fconfig.py", "/static/%2e%2e%2f%2e%2e%2fetc/passwd",
                                  "/static//etc/passwd", "/static/..\\app\\config.py"])
def test_static_path_traversal(client, path):
    r = client.get(path)
    assert r.status_code in (400, 404) and "SECRET_KEY" not in r.text and "root:" not in r.text


def test_no_unsafe_deserialization_or_shell_in_app():
    bad = re.compile(r"\b(pickle|marshal|shelve|yaml\.load|eval\(|exec\(|os\.system|subprocess|shell=True)")
    hits = [f"{p}:{i}" for p in (ROOT / "app").rglob("*.py")
            for i, line in enumerate(p.read_text().splitlines(), 1) if bad.search(line)]
    assert hits == []


def test_csp_strict_on_every_kind_of_response(client, db, user, login):
    login(user)
    for path in ("/", "/account", "/static/app.css", "/nope", "/admin/login", "/admin", "/coffee/single"):
        r = client.get(path, follow_redirects=False)
        csp = r.headers["content-security-policy"]
        assert "unsafe-inline" not in csp and "unsafe-eval" not in csp and "default-src 'self'" in csp, path
        assert "frame-ancestors 'none'" in csp and r.headers["x-content-type-options"] == "nosniff"
    r = client.post("/coffee/single", data={"token": "x"}, headers={"Origin": "https://evil.example"})
    assert "unsafe-inline" not in r.headers["content-security-policy"]


def test_production_error_page_has_no_details(monkeypatch, db):
    for k, v in PROD_ENV.items():
        monkeypatch.setenv(k, v)
    reload_settings()
    with TestClient(create_app(), base_url="https://coffee.example.org", raise_server_exceptions=False) as c:
        for path, expect in (("/coffee/done/" + "1" * 32, 303), ("/coffee/espresso", 404), ("/openapi.json", 404)):
            r = c.get(path, follow_redirects=False)
            assert r.status_code == expect and "Traceback" not in r.text and "sqlalchemy" not in r.text.lower()
        assert c.post("/admin/users/x/payment", data={"amount": "1"}, follow_redirects=False).status_code == 303


@pytest.mark.xfail(strict=True, reason="FINDING: ENVIRONMENT defaults to development; an https deployment that forgets "
                                        "it silently runs with the published DEV_SECRET_KEY/DEV_ACCESS_CODE")
def test_public_https_deployment_without_environment_fails_closed(monkeypatch):
    for key in ("ENVIRONMENT", "SECRET_KEY", "ACCESS_CODE"):
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(ValueError):
        s = Settings(_env_file=None, public_base_url="https://coffee.example.org")
        assert s.secret_key == DEV_SECRET_KEY  # what happens today: forgeable gate/CSRF/scan tokens


@pytest.mark.xfail(strict=True, reason="FINDING: engine created without hide_parameters; DB errors are logged "
                                        "(main._transient/_unexpected) with bound parameters such as admin "
                                        "csrf_secret, TOTP secret or token hashes")
def test_database_errors_do_not_carry_bound_parameters_into_logs():
    assert get_engine().hide_parameters is True


def test_secrets_absent_from_audit_metadata(app, db, chair):
    """Full admin lifecycle; no password, TOTP secret, recovery code, token or csrf secret in audit rows."""
    from sqlalchemy import select
    from app.models import AdminSession, AdminUser, AuditLog
    from tests.admin_support import PASSWORD, current_code, make_real_admin

    admin_id, secret = make_real_admin()
    c = TestClient(app, raise_server_exceptions=False)
    page = c.get("/admin/login")
    c.post("/admin/login", data={"csrf_token": field(page.text, "csrf_token"), "username": "boss", "password": "bad!"})
    c.post("/admin/login", data={"csrf_token": field(page.text, "csrf_token"), "username": "boss",
                                 "password": PASSWORD})
    c.post("/admin/totp", data={"csrf_token": field(c.get("/admin/totp").text, "csrf_token"),
                                "code": current_code(secret)})
    with write_session() as w:
        admin_auth.reset_totp(w, w.get(AdminUser, admin_id))
        sessions = [(s.token_hash, s.csrf_secret) for s in w.scalars(select(AdminSession))]
        dump = repr([(a.action, a.meta) for a in w.scalars(select(AuditLog))])
    assert "admin.login.success" in dump
    for needle in [PASSWORD, "bad!", secret, current_code(secret), *[x for pair in sessions for x in pair]]:
        assert needle not in dump
    assert Path(ROOT / ".gitignore").read_text().count(".env") >= 1
