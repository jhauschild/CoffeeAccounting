"""Security review (brief 06): access gate and session attacks.

Regression tests pass; demonstrations of real weaknesses are `xfail(strict=True)`.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db import read_session
from app.main import create_app
from app.models import AuditLog, RateLimitEvent, User, UserSession
from app.services import gate, ratelimit, signing
from app.services.admin_auth import ADMIN_COOKIE
from app.services.sessions import SESSION_COOKIE
from app.timeutil import utcnow
from app.web import tokens
from tests import factories
from tests.admin_support import fast_hasher, login_as, make_real_admin, PASSWORD  # noqa: F401
from tests.conftest import reload_settings
from tests.test_platform_web import PROD_ENV
from tests.user_support import ACCESS_CODE, counts, field, pass_gate, register, scan


def _anon(app, ip="203.0.113.7"):
    return TestClient(app, raise_server_exceptions=False, client=(ip, 40000))


# ----- gate bypass ------------------------------------------------------------------------------
def test_onboarding_unreachable_without_gate(client, db, user):
    before = counts(db)
    for path in ("/register", "/profiles", "/profiles?q=Ali", "/profiles?q=%25"):
        r = client.get(path, follow_redirects=False)
        assert (r.status_code, r.headers.get("location")) == (303, "/join"), path
    # POSTs: no gate, no session -> nothing created, and no profile name leaks
    for path, data in (("/register", {"display_name": "X", "chair_id": str(user.chair_id), "privacy_ack": "1"}),
                       ("/profiles/select", {"user_id": str(user.id)})):
        r = client.post(path, data=data, follow_redirects=False)
        assert r.status_code in (303, 403) and SESSION_COOKIE not in r.headers.get("set-cookie", "")
        assert "Alice" not in r.text
    assert counts(db) == {**before, "RateLimitEvent": counts(db)["RateLimitEvent"]}


@pytest.mark.parametrize("variant", ["other_purpose", "tampered", "expired", "old_code", "garbage", "unsigned"])
def test_forged_gate_cookie_rejected(client, monkeypatch, variant):
    now = utcnow()
    good = gate.make_gate_cookie()
    if variant == "other_purpose":  # a scan token is HMAC-signed with the same SECRET_KEY
        value = tokens.make_scan_token("single")
    elif variant == "tampered":
        raw, sig = good.split(".")
        value = raw + "." + ("A" if sig[0] != "A" else "B") + sig[1:]
    elif variant == "expired":
        value = gate.make_gate_cookie(now=now - timedelta(seconds=gate.GATE_MAX_AGE + 5))
    elif variant == "old_code":  # cookie minted before ACCESS_CODE was rotated
        monkeypatch.setenv("ACCESS_CODE", "previous-access-code")
        reload_settings()
        value = gate.make_gate_cookie()
        monkeypatch.setenv("ACCESS_CODE", ACCESS_CODE)
        reload_settings()
    elif variant == "garbage":
        value = "eyJnIjoxLCJpYXQiOjk5OTk5OTk5OTl9.x"
    else:
        value = signing._b64e(b'{"g":1,"iat":%d}' % int(now.timestamp()))
    client.cookies.set(gate.GATE_COOKIE, value)
    r = client.get("/profiles", follow_redirects=False)
    assert (r.status_code, r.headers.get("location")) == (303, "/join")


def test_access_code_never_leaks(client, db, caplog, global_admin):
    caplog.set_level(logging.DEBUG)
    client.post("/join", data={"code": "wrong-code-123"})
    pass_gate(client)
    cookie = client.cookies.get(gate.GATE_COOKIE)
    assert ACCESS_CODE not in signing._b64d(cookie.split(".")[0]).decode()
    pages = [client.get(p).text for p in ("/", "/join", "/privacy", "/register", "/profiles", "/coffee/single")]
    csrf = login_as(client, global_admin.id)
    pages.append(client.get("/admin/qr").text)
    assert all(ACCESS_CODE not in p for p in pages)
    with read_session() as r:
        dump = repr([(a.action, a.meta) for a in r.scalars(select(AuditLog))])
        dump += repr([(e.bucket, e.key) for e in r.scalars(select(RateLimitEvent))])
    assert ACCESS_CODE not in dump and "wrong-code-123" not in dump
    assert ACCESS_CODE not in caplog.text and "wrong-code-123" not in caplog.text
    assert csrf  # (admin QR page rendered for an admin)


def test_access_code_failures_limited_and_not_reset_by_success(app, db):
    c = _anon(app)
    for _ in range(ratelimit.ACCESS_CODE_FAILURES[1]):
        assert c.post("/join", data={"code": "nope-nope"}).status_code == 403
    r = c.post("/join", data={"code": ACCESS_CODE}, follow_redirects=False)
    assert r.status_code == 429 and gate.GATE_COOKIE not in r.headers.get("set-cookie", "")


def test_access_code_limiter_is_atomic_under_concurrency(app, db, monkeypatch):
    bucket, limit, window = ratelimit.ACCESS_CODE_FAILURES
    with __import__("app.db", fromlist=["write_session"]).write_session() as w:
        for _ in range(limit - 1):  # one guess left
            ratelimit.record_hit(w, bucket, "203.0.113.7")
    parallel = 6
    barrier = threading.Barrier(parallel, timeout=5)
    evaluated = []
    real = gate.check_access_code

    def slow_check(code):
        evaluated.append(code)
        try:
            barrier.wait()
        except threading.BrokenBarrierError:
            pass
        return real(code)

    monkeypatch.setattr(gate, "check_access_code", slow_check)
    with ThreadPoolExecutor(parallel) as pool:
        list(pool.map(lambda i: _anon(app).post("/join", data={"code": f"guess-{i}"}), range(parallel)))
    assert len(evaluated) <= 1, f"{len(evaluated)} guesses evaluated with only 1 left in the budget"


def test_access_code_limit_covers_an_ipv6_prefix(app, db):
    for i in range(ratelimit.ACCESS_CODE_FAILURES[1]):
        _anon(app, f"2001:db8:1:2::{i + 1:x}").post("/join", data={"code": "nope-nope"})
    r = _anon(app, "2001:db8:1:2::ffff").post("/join", data={"code": "nope-nope"})
    assert r.status_code == 429


def test_spoofed_forwarded_for_ignored_without_trusted_proxy(app, db):
    c = _anon(app)
    for i in range(ratelimit.ACCESS_CODE_FAILURES[1]):
        c.post("/join", data={"code": "nope"}, headers={"X-Forwarded-For": f"198.51.100.{i}"})
    assert c.post("/join", data={"code": "nope"}, headers={"X-Forwarded-For": "198.51.100.200"}).status_code == 429


def test_spoofed_forwarded_for_left_of_trusted_proxy_ignored(app, db, monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_IPS", "10.0.0.0/8")
    reload_settings()
    proxy = TestClient(create_app(), raise_server_exceptions=False, client=("10.0.0.2", 1))
    for i in range(ratelimit.ACCESS_CODE_FAILURES[1]):  # attacker 192.0.2.9 forges a different left-most hop
        proxy.post("/join", data={"code": "nope"}, headers={"X-Forwarded-For": f"1.1.1.{i}, 192.0.2.9"})
    r = proxy.post("/join", data={"code": "nope"}, headers={"X-Forwarded-For": "8.8.8.8, 192.0.2.9"})
    assert r.status_code == 429
    with read_session() as r_:
        keys = set(r_.scalars(select(RateLimitEvent.key)))
    assert keys == {"192.0.2.9"}


# ----- sessions ---------------------------------------------------------------------------------
def _db_bytes(db_path) -> bytes:
    data = b""
    for suffix in ("", "-wal"):
        p = db_path.parent / (db_path.name + suffix)
        if p.exists():
            data += p.read_bytes()
    return data


def test_tokens_are_high_entropy_and_stored_hashed_only(client, db, chair, db_path):
    pass_gate(client)
    r = register(client, "Hash Check", chair)
    raw = r.cookies.get(SESSION_COOKIE) or client.cookies.get(SESSION_COOKIE)
    assert len(raw) >= 43 and set(raw) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    admin_id, _ = make_real_admin(totp=False)
    with TestClient(client.app, raise_server_exceptions=False) as ac:
        page = ac.get("/admin/login")
        ac.post("/admin/login", data={"csrf_token": field(page.text, "csrf_token"), "username": "boss",
                                      "password": PASSWORD}, follow_redirects=False)
        admin_raw = ac.cookies.get(ADMIN_COOKIE)
    assert admin_raw and len(admin_raw) >= 43
    with read_session() as r_:
        assert r_.scalar(select(UserSession.token_hash)) == hashlib.sha256(raw.encode()).hexdigest()
    blob = _db_bytes(db_path)
    for secret in (raw, admin_raw, PASSWORD):
        assert secret.encode() not in blob


def test_user_session_can_never_open_admin(client, db, user, login):
    raw = login(user)
    for cookies in ({SESSION_COOKIE: raw}, {SESSION_COOKIE: raw, ADMIN_COOKIE: raw}):
        client.cookies.clear()
        for k, v in cookies.items():
            client.cookies.set(k, v, path="/admin" if k == ADMIN_COOKIE else "/")
        for path in ("/admin", "/admin/users", "/admin/totp/setup", "/admin/account"):
            r = client.get(path, follow_redirects=False)
            assert (r.status_code, r.headers["location"]) == (303, "/admin/login"), path


@pytest.mark.parametrize("state", ["revoked", "expired", "inactive", "merged"])
def test_dead_sessions_are_rejected_everywhere(client, db, user, chair, price, state):
    raw = "x" * 43
    s = factories.make_session(db, user, raw_token=raw)
    if state == "revoked":
        s.revoked_at = utcnow()
    elif state == "expired":
        s.expires_at = utcnow() - timedelta(seconds=1)
    elif state == "inactive":
        user.status = "inactive"
    else:
        other = factories.make_user(db, "Target", chair=chair)
        user.status, user.merged_into_id = "merged", other.id
    db.commit()
    client.cookies.set(SESSION_COOKIE, raw)
    assert client.get("/account", follow_redirects=False).headers["location"] == "/join"
    assert client.get("/profiles", follow_redirects=False).headers["location"] == "/join"  # no gate via dead session
    r = scan(client)
    assert r.headers["location"] == "/join"  # pending, never booked to the dead session's user
    with read_session() as r_:
        assert r_.scalar(select(User.id).where(User.id == user.id)) == user.id
    assert counts(db)["ConsumptionEvent"] == 0


def test_cookies_hardened_in_production(monkeypatch, db):
    """Every Set-Cookie emitted along user and admin flows carries HttpOnly, Secure, SameSite=Lax."""
    for k, v in PROD_ENV.items():
        monkeypatch.setenv(k, v)
    reload_settings()
    chair = factories.make_chair(db, short_name="PRD")
    factories.set_price(db, 50)
    admin_id, _ = make_real_admin(totp=False)
    monkeypatch.setenv("BALANCE_TOTP_REQUIRED", "false")
    reload_settings()
    seen: list[str] = []
    with TestClient(create_app(), base_url="https://coffee.example.org") as c:
        def grab(r):
            for resp in [*r.history, r]:
                seen.extend(resp.headers.get_list("set-cookie"))
            return r
        grab(c.post("/coffee/single", data={"token": field(c.get("/coffee/single").text, "token")}))
        grab(c.post("/join", data={"code": PROD_ENV["ACCESS_CODE"]}))
        page = c.get("/register")
        grab(c.post("/register", data={"csrf_token": field(page.text, "csrf_token"), "privacy_ack": "1",
                                       "registration_token": field(page.text, "registration_token"),
                                       "display_name": "Prod", "chair_id": str(chair.id)}))
        grab(c.post("/account/leave", data={"csrf_token": field(c.get("/account").text, "csrf_token")}))
        page = grab(c.get("/admin/login"))
        grab(c.post("/admin/login", data={"csrf_token": field(page.text, "csrf_token"), "username": "boss",
                                          "password": PASSWORD}))
        grab(c.post("/admin/logout", data={"csrf_token": field(c.get("/admin/account").text, "csrf_token")}))
    names = {h.split("=", 1)[0] for h in seen}
    assert {"coffee_pending", "coffee_gate", "coffee_session", "coffee_admin_login", "coffee_admin"} <= names
    for h in seen:
        attrs = {p.strip().lower() for p in h.split(";")}
        assert {"httponly", "secure", "samesite=lax"} <= attrs, h
        if h.startswith(("coffee_admin=", "coffee_admin_login=")):
            assert "path=/admin" in attrs, h


def test_ip_key_groups_ipv6_by_64_and_leaves_ipv4_alone():
    assert ratelimit.ip_key("203.0.113.7") == "203.0.113.7"
    assert ratelimit.ip_key("2001:db8:1:2::1") == ratelimit.ip_key("2001:db8:1:2:ffff:eeee:dddd:cccc") == "2001:db8:1:2::/64"
    assert ratelimit.ip_key("2001:db8:1:3::1") != ratelimit.ip_key("2001:db8:1:2::1")
    assert ratelimit.ip_key("::ffff:203.0.113.7") == "203.0.113.7"
    assert ratelimit.ip_key("unknown") == "unknown"
