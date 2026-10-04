"""Security review (brief 06): admin authentication attacks (gaps not covered by test_admin_*)."""

from __future__ import annotations

import re
import sqlite3

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.db import read_session, write_session
from app.main import create_app
from app.models import AdminUser, AuditLog
from app.services import admin_auth, passwords
from app.timeutil import utcnow
from tests.admin_support import PASSWORD, make_real_admin
from tests.conftest import reload_settings
from tests.user_support import field

@pytest.fixture
def fast():
    """The cheap Argon2 parameters come from the ARGON2_* test settings (tests/conftest.py)."""
    return None


def _client(app, ip="198.51.100.20"):
    return TestClient(app, raise_server_exceptions=False, client=(ip, 1))


def _password_step(c, username="boss", password=PASSWORD):
    page = c.get("/admin/login")
    return c.post("/admin/login", data={"csrf_token": field(page.text, "csrf_token"), "username": username,
                                        "password": password}, follow_redirects=False)


def _enrol_code(c, code):
    return c.post("/admin/totp/setup", data={"csrf_token": field(c.get("/admin/totp/setup").text, "csrf_token"),
                                              "code": code}, follow_redirects=False)


def _audit_count(**where) -> int:
    with read_session() as r:
        q = select(func.count()).select_from(AuditLog)
        for k, v in where.items():
            q = q.where(getattr(AuditLog, k) == v)
        return r.scalar(q)


def test_argon2id_parameters_in_production_code(monkeypatch):
    for name, value in (("ARGON2_TIME_COST", "3"), ("ARGON2_MEMORY_COST_KIB", "65536"), ("ARGON2_PARALLELISM", "4")):
        monkeypatch.setenv(name, value)  # the production defaults (the tests lower them)
    reload_settings()
    h = admin_auth.hash_password("a sufficiently long one")
    assert h.startswith("$argon2id$v=19$m=65536,t=3,p=4$")


def test_username_enumeration_same_work_and_same_answer(app, fast, monkeypatch):
    make_real_admin(username="boss")
    make_real_admin(username="gone")
    with write_session() as w:
        admin_auth.get_by_username(w, "gone").active = False
    verifies = []
    real_verify = passwords.verify_password  # real and decoy checks both end here
    monkeypatch.setattr(passwords, "verify_password", lambda h, p: (verifies.append(1), real_verify(h, p))[1])
    answers = []
    for username in ("boss", "nobody-here", "gone"):
        verifies.clear()
        r = _password_step(_client(app, ip=f"198.51.100.{len(answers) + 1}"), username, "wrong password!!")
        body = re.sub(r'name="csrf_token" value="[^"]*"', "", r.text).replace(username, "U")
        answers.append((r.status_code, body, sorted(r.cookies.keys())))
        assert len(verifies) == 1, username
    assert answers[0] == answers[1] == answers[2]


def test_enrolment_code_window_and_replay_protection(app, fast, monkeypatch):
    admin_id, _ = make_real_admin(totp=False)
    c = _client(app, "198.51.100.31")
    assert _password_step(c).headers["location"] == "/admin"
    with write_session() as w:
        secret = admin_auth.begin_enrollment(w, w.get(AdminUser, admin_id))
    totp = pyotp.TOTP(secret)
    now = utcnow().timestamp()
    for far in (totp.at(now - 90), totp.at(now + 90)):  # outside the +/-1 step window
        assert _enrol_code(c, far).status_code == 401
    code = totp.at(now)
    assert _enrol_code(c, code).status_code == 200
    with write_session() as w:  # the accepted code is burnt for 120 s, whatever asks next
        assert not admin_auth._totp_matches(w, w.get(AdminUser, admin_id), code, utcnow())


def test_bootstrap_env_ignored_once_an_admin_exists(monkeypatch, fast, db):
    monkeypatch.setenv("ADMIN_BOOTSTRAP_USERNAME", "first")
    monkeypatch.setenv("ADMIN_BOOTSTRAP_PASSWORD", "bootstrap password 1")
    reload_settings()
    with TestClient(create_app()):
        pass
    with write_session() as w:
        first = admin_auth.get_by_username(w, "first")
        assert first is not None
        first.active = False  # even with the only admin disabled, the env must not mint a new one
    monkeypatch.setenv("ADMIN_BOOTSTRAP_USERNAME", "second")
    monkeypatch.setenv("ADMIN_BOOTSTRAP_PASSWORD", "attacker password 2")
    reload_settings()
    with TestClient(create_app()):
        pass
    with read_session() as r:
        assert r.scalar(select(func.count()).select_from(AdminUser)) == 1


def test_wrong_current_password_on_change_counts_as_login_failure(app, fast):
    make_real_admin()
    from tests.admin_support import login_as
    with read_session() as r:
        admin_id = admin_auth.get_by_username(r, "boss").id
    c = _client(app)
    csrf = login_as(c, admin_id)
    for _ in range(5):
        assert c.post("/admin/account/password", follow_redirects=False, data={"csrf_token": csrf, "current_password": "guess guess guess",
                                                "new_password": "x" * 14, "new_password2": "x" * 14}
                      ).headers["location"].endswith("err=wrong_password")
    assert _password_step(_client(app)).status_code == 429  # same username + IP bucket


def test_login_does_not_hold_the_write_lock_while_hashing(fast, db_path, monkeypatch):
    make_real_admin()
    lock_free = []

    def probe(password_hash, password):
        con = sqlite3.connect(db_path, timeout=0)
        try:
            con.execute("BEGIN IMMEDIATE")
            con.rollback()
            lock_free.append(True)
        except sqlite3.OperationalError:
            lock_free.append(False)
        finally:
            con.close()
        return False

    monkeypatch.setattr(passwords, "verify_password", probe)
    admin_auth.start_login(username="boss", password="whatever", ip="203.0.113.1")  # as admin_login.login_submit
    admin_auth.start_login(username="no-such-admin", password="whatever", ip="203.0.113.1")
    assert lock_free == [True, True]


def test_anonymous_login_flood_cannot_grow_audit_log_without_bound(app, fast):
    c = _client(app)
    page = c.get("/admin/login")
    token = field(page.text, "csrf_token")
    before = _audit_count()
    for i in range(60):
        username = "boss" if i < 30 else f"user{i}"  # 30x the same name (rate-limited), 30 rotating names
        c.post("/admin/login", data={"csrf_token": token, "username": username, "password": "x"})
    assert _audit_count() - before <= 20


def test_rate_limited_login_does_not_verify_password(app, fast, monkeypatch):
    make_real_admin()
    c = _client(app)
    for _ in range(5):
        _password_step(c, password="wrong wrong wrong")
    calls = []
    monkeypatch.setattr(passwords, "verify_password", lambda *a: calls.append(1) or True)
    assert _password_step(c).status_code == 429 and calls == []


def test_group_admin_enumeration_same_work_and_same_answer(app, fast, chair, monkeypatch):
    """Unknown names, plain members, inactive group admins and group admins all look alike on a wrong password."""
    from tests import factories
    from tests.admin_support import login_name
    ok_id, _ = make_real_admin(role="chair", chairs=[chair], username="ga1")
    off_id, _ = make_real_admin(role="chair", chairs=[chair], username="ga2")
    with write_session() as w:
        w.get(AdminUser, off_id).user.status = "inactive"
        factories.make_member(w, username="plainmember", chair=chair, commit=False)
    verifies = []
    real_verify = passwords.verify_password
    monkeypatch.setattr(passwords, "verify_password", lambda h, p: (verifies.append(1), real_verify(h, p))[1])
    answers = []
    for username in (login_name(ok_id), "nobody-here", login_name(off_id), "plainmember"):
        verifies.clear()
        r = _password_step(_client(app, ip=f"198.51.100.{len(answers) + 60}"), username, "wrong password!!")
        body = re.sub(r'name="csrf_token" value="[^"]*"', "", r.text).replace(username, "U")
        answers.append((r.status_code, body, sorted(r.cookies.keys())))
        assert len(verifies) == 1, username
    assert answers[0] == answers[1] == answers[2] == answers[3]
