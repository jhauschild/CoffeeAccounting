"""Security review (brief 06): sign-in limits and session attacks.

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

from app.db import read_session, write_session
from app.main import create_app
from app.models import AuditLog, RateLimitEvent, User, UserSession
from app.services import passwords, ratelimit
from app.services.admin_auth import ADMIN_COOKIE
from app.services.sessions import SESSION_COOKIE
from app.timeutil import utcnow
from tests import factories
from tests.admin_support import fast_hasher, login_as, make_real_admin, PASSWORD as ADMIN_PASSWORD  # noqa: F401
from tests.conftest import reload_settings
from tests.test_platform_web import PROD_ENV
from tests.user_support import PASSWORD, counts, field, make_account, scan, sign_in

PER_USER = ratelimit.LOGIN_FAILURES[1]
PER_IP = ratelimit.LOGIN_FAILURES_IP[1]


def _anon(app, ip="203.0.113.7"):
    return TestClient(app, raise_server_exceptions=False, client=(ip, 40000))


def _try(c, username="nobody", password="wrong-password", **kw):
    page = c.get("/login")
    return c.post("/login", data={"csrf_token": field(page.text, "csrf_token"), "username": username,
                                  "password": password}, follow_redirects=False, **kw)


# ----- sign-in limits ----------------------------------------------------------------------------
def test_failures_per_username_and_ip_are_limited(app, db, chair):
    account = make_account(db, "Limited", chair)
    c = _anon(app)
    for _ in range(PER_USER):
        assert _try(c, account.username).status_code == 401
    # The budget is spent: even the CORRECT password is refused now, and nothing more is recorded.
    r = _try(c, account.username, PASSWORD)
    assert r.status_code == 429 and SESSION_COOKIE not in r.headers.get("set-cookie", "")
    with read_session() as r_:
        assert len(list(r_.scalars(select(RateLimitEvent).where(RateLimitEvent.bucket == "login")))) == PER_USER
    # Another username from the same IP is not blocked by the per-username budget.
    other = make_account(db, "Other", chair)
    assert _try(c, other.username, PASSWORD).status_code == 303


def test_failures_per_ip_cap_covers_every_username(app, db):
    c = _anon(app)
    for i in range(PER_IP):
        assert _try(c, f"user{i}").status_code == 401
    assert _try(c, "someone-else").status_code == 429


def test_successful_sign_in_records_no_failure(app, db, chair):
    account = make_account(db, "Fine", chair)
    c = _anon(app)
    for _ in range(PER_USER + 3):
        assert sign_in(c, account).status_code == 303
    with read_session() as r_:
        assert not list(r_.scalars(select(RateLimitEvent).where(RateLimitEvent.bucket.in_(["login", "login_ip"]))))


def test_login_limiter_is_atomic_under_concurrency(app, db, monkeypatch):
    bucket, limit, window = ratelimit.LOGIN_FAILURES
    with write_session() as w:
        for _ in range(limit - 1):  # one guess left for username "ghost" from this IP
            ratelimit.record_hit(w, bucket, "ghost|203.0.113.7")
    parallel = 6
    barrier = threading.Barrier(parallel, timeout=5)
    evaluated = []
    real = passwords.verify_dummy

    def slow_check(password):
        evaluated.append(password)
        try:
            barrier.wait()
        except threading.BrokenBarrierError:
            pass
        return real(password)

    monkeypatch.setattr(passwords, "verify_dummy", slow_check)
    clients = [_anon(app) for _ in range(parallel)]
    tokens_ = [field(c.get("/login").text, "csrf_token") for c in clients]
    with ThreadPoolExecutor(parallel) as pool:
        list(pool.map(lambda i: clients[i].post("/login", data={"csrf_token": tokens_[i], "username": "ghost",
                                                                "password": f"guess-{i}"}), range(parallel)))
    assert len(evaluated) <= 1, f"{len(evaluated)} guesses evaluated with only 1 left in the budget"
    with read_session() as r_:
        assert len(list(r_.scalars(select(RateLimitEvent).where(RateLimitEvent.bucket == bucket)))) == limit


def test_login_limit_covers_an_ipv6_prefix(app, db):
    for i in range(PER_IP):
        _try(_anon(app, f"2001:db8:1:2::{i + 1:x}"), f"user{i}")
    assert _try(_anon(app, "2001:db8:1:2::ffff"), "another").status_code == 429


def test_spoofed_forwarded_for_ignored_without_trusted_proxy(app, db):
    c = _anon(app)
    for i in range(PER_IP):
        _try(c, f"user{i}", headers={"X-Forwarded-For": f"198.51.100.{i}"})
    assert _try(c, "x", headers={"X-Forwarded-For": "198.51.100.200"}).status_code == 429


def test_spoofed_forwarded_for_left_of_trusted_proxy_ignored(app, db, monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_IPS", "10.0.0.0/8")
    reload_settings()
    proxy = TestClient(create_app(), raise_server_exceptions=False, client=("10.0.0.2", 1))
    for i in range(PER_IP):  # attacker 192.0.2.9 forges a different left-most hop
        _try(proxy, f"user{i}", headers={"X-Forwarded-For": f"1.1.1.{i}, 192.0.2.9"})
    assert _try(proxy, "x", headers={"X-Forwarded-For": "8.8.8.8, 192.0.2.9"}).status_code == 429
    with read_session() as r_:
        keys = {k.split("|")[-1] for k in r_.scalars(select(RateLimitEvent.key)) if k}
    assert keys == {"192.0.2.9"}


def test_password_never_leaks(client, db, chair, caplog):
    account = make_account(db, "Quiet", chair)
    caplog.set_level(logging.DEBUG)
    wrong = "this-is-not-the-password-123"
    _try(client, account.username, wrong)
    assert sign_in(client, account).status_code == 303
    with read_session() as r:
        dump = repr([(a.action, a.meta) for a in r.scalars(select(AuditLog))])
        dump += repr([(e.bucket, e.key) for e in r.scalars(select(RateLimitEvent))])
    for secret in (PASSWORD, wrong):
        assert secret not in dump and secret not in caplog.text


def test_failed_sign_in_responses_do_not_reveal_which_part_was_wrong(app, db, chair):
    account = make_account(db, "Same", chair)
    gone = make_account(db, "Gone", chair)
    with write_session() as w:
        w.get(User, gone.id).status = "inactive"
    answers = set()
    for n, (name, password) in enumerate(((account.username, "wrong-password"), ("no-such-user", PASSWORD),
                                          (gone.username, PASSWORD), ("", ""))):
        r = _try(_anon(app, f"198.51.100.{n + 1}"), name, password)
        answers.add((r.status_code, r.text.count("Username or password is not correct"),
                     "coffee_session" in r.headers.get("set-cookie", "")))
    assert answers == {(401, 1, False)}


# ----- sessions ---------------------------------------------------------------------------------
def _db_bytes(db_path) -> bytes:
    data = b""
    for suffix in ("", "-wal"):
        p = db_path.parent / (db_path.name + suffix)
        if p.exists():
            data += p.read_bytes()
    return data


def test_tokens_are_high_entropy_and_stored_hashed_only(client, db, chair, db_path):
    r = sign_in(client, make_account(db, "Hash Check", chair))
    raw = r.cookies.get(SESSION_COOKIE) or client.cookies.get(SESSION_COOKIE)
    assert len(raw) >= 43 and set(raw) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    admin_id, _ = make_real_admin(totp=False)
    with TestClient(client.app, raise_server_exceptions=False) as ac:
        page = ac.get("/admin/login")
        ac.post("/admin/login", data={"csrf_token": field(page.text, "csrf_token"), "username": "boss",
                                      "password": ADMIN_PASSWORD}, follow_redirects=False)
        admin_raw = ac.cookies.get(ADMIN_COOKIE)
    assert admin_raw and len(admin_raw) >= 43
    with read_session() as r_:
        assert r_.scalar(select(UserSession.token_hash)) == hashlib.sha256(raw.encode()).hexdigest()
    blob = _db_bytes(db_path)
    for secret in (raw, admin_raw, ADMIN_PASSWORD, PASSWORD):
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
    assert client.get("/account", follow_redirects=False).headers["location"] == "/login"
    r = scan(client)
    assert r.headers["location"] == "/login"  # pending, never booked to the dead session's user
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
    account = make_account(db, "Prod", chair, username="produser")
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
        page = grab(c.get("/login"))
        grab(c.post("/login", data={"csrf_token": field(page.text, "csrf_token"), "username": account.username,
                                    "password": PASSWORD}))
        grab(c.post("/logout", data={"csrf_token": field(c.get("/account").text, "csrf_token")}))
        page = grab(c.get("/admin/login"))
        grab(c.post("/admin/login", data={"csrf_token": field(page.text, "csrf_token"), "username": "boss",
                                          "password": ADMIN_PASSWORD}))
        grab(c.post("/admin/logout", data={"csrf_token": field(c.get("/admin/account").text, "csrf_token")}))
    names = {h.split("=", 1)[0] for h in seen}
    assert {"coffee_pending", "coffee_csrf", "coffee_session", "coffee_admin_login", "coffee_admin"} <= names
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
