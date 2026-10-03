"""Admin accounts, passwords, TOTP, recovery codes, sessions, rate limiting (service level)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from app.db import read_session, write_session
from app.models import AdminSession, AdminUser, AuditLog
from app.services import admin_auth, ratelimit
from app.services.errors import Conflict, InvalidInput
from app.timeutil import utcnow
from tests import factories
from tests.admin_support import NEW_PASSWORD, PASSWORD, current_code, fast_hasher, make_real_admin  # noqa: F401

IP = "203.0.113.7"


def audit_actions():
    with read_session() as r:
        return [a.action for a in r.scalars(select(AuditLog).order_by(AuditLog.id))]


def login(username="boss", password=PASSWORD, ip=IP, old=None):
    with write_session() as w:
        out = admin_auth.start_login(w, username=username, password=password, ip=ip, old_raw_token=old)
        w.expunge_all()
    return out


def test_password_policy_and_argon2id():
    with pytest.raises(InvalidInput):
        admin_auth.hash_password("short")
    h = admin_auth.hash_password(PASSWORD)
    assert h.startswith("$argon2id$")
    assert admin_auth.verify_password(h, PASSWORD)
    assert not admin_auth.verify_password(h, PASSWORD + "x")
    assert not admin_auth.verify_password("!", PASSWORD)  # disabled hash never matches


def test_create_admin_rules(chair, other_chair):
    with write_session() as w:
        with pytest.raises(InvalidInput):
            admin_auth.create_admin(w, username="c", password=PASSWORD, role="chair")  # needs a chair
    with write_session() as w:
        with pytest.raises(InvalidInput):
            admin_auth.create_admin(w, username="g", password=PASSWORD, role="global", chairs=[chair.id])
    with write_session() as w:
        admin_auth.create_admin(w, username="Boss", password=PASSWORD, role="global")
    with write_session() as w:
        with pytest.raises(Conflict):
            admin_auth.create_admin(w, username=" boss ", password=PASSWORD, role="global")
    assert audit_actions() == ["admin.created"]


def test_bootstrap_only_without_admins(monkeypatch, settings_env):
    from tests.conftest import reload_settings
    monkeypatch.setenv("ADMIN_BOOTSTRAP_USERNAME", "first")
    monkeypatch.setenv("ADMIN_BOOTSTRAP_PASSWORD", PASSWORD)
    reload_settings()
    with write_session() as w:
        assert admin_auth.bootstrap_admin(w).username == "first"
    with write_session() as w:
        assert admin_auth.bootstrap_admin(w) is None  # ignored once an admin exists
        assert len(admin_auth.list_admins(w)) == 1


def test_login_wrong_password_unknown_user_and_audit():
    make_real_admin()
    assert login(password="wrong password!!").status == "invalid"
    assert login(username="nobody").status == "invalid"
    ok = login()
    assert ok.status == "ok" and ok.stage == "totp" and not ok.session.totp_verified
    acts = audit_actions()
    assert acts.count("admin.login.failed") == 2 and "admin.login.password_ok" in acts
    with read_session() as r:
        meta = r.scalars(select(AuditLog).where(AuditLog.action == "admin.login.failed")).first().meta
    assert meta["step"] == "password" and "wrong password" not in str(meta)


def test_session_stores_only_token_hash():
    make_real_admin()
    out = login()
    with read_session() as r:
        row = r.scalars(select(AdminSession)).one()
        assert row.token_hash == admin_auth.hash_token(out.raw_token) != out.raw_token


def test_totp_step_full_session_and_rotation():
    _, secret = make_real_admin()
    first = login()
    with write_session() as w:
        pending = w.get(AdminSession, first.session.id)
        admin = w.get(AdminUser, pending.admin_id)
        out = admin_auth.verify_second_factor(w, session=pending, admin=admin, code=current_code(secret), ip=IP)
        w.expunge_all()
    assert out.status == "ok" and out.session.totp_verified
    assert out.raw_token != first.raw_token
    with read_session() as r:
        assert admin_auth.resolve_session(r, first.raw_token) is None  # pending token rotated away
        s, a = admin_auth.resolve_session(r, out.raw_token)
        assert admin_auth.is_complete(s, a)
        assert s.expires_at - s.created_at == timedelta(hours=12)
    assert "admin.login.success" in audit_actions()


def test_totp_wrong_code_replay_and_recovery_code():
    admin_id, secret = make_real_admin()
    with write_session() as w:  # give the admin recovery codes
        admin = w.get(AdminUser, admin_id)
        codes = admin_auth.new_recovery_codes()
        admin.recovery_codes = [admin_auth._recovery_hash(c) for c in codes]

    def second(code):
        pending = login()
        with write_session() as w:
            s = w.get(AdminSession, pending.session.id)
            out = admin_auth.verify_second_factor(w, session=s, admin=w.get(AdminUser, admin_id), code=code, ip=IP)
            w.expunge_all()
        return out

    assert second("000000").status == "invalid"
    good = current_code(secret)
    assert second(good).status == "ok"
    assert second(good).status == "invalid"  # same code cannot be replayed
    out = second(codes[0].lower())  # case/dash insensitive
    assert out.status == "ok"
    assert second(codes[0]).status == "invalid"  # single use
    with read_session() as r:
        assert len(r.get(AdminUser, admin_id).recovery_codes) == 7
    acts = audit_actions()
    assert "admin.recovery_code_used" in acts and "admin.login.failed" in acts


def test_recovery_codes_are_not_stored_in_clear():
    admin_id, secret = make_real_admin(totp=False)
    with write_session() as w:
        admin = w.get(AdminUser, admin_id)
        admin_auth.begin_enrollment(w, admin)
        secret = admin.totp_secret
        s, raw = admin_auth._new_session(w, admin, verified=False, now=utcnow())
        out = admin_auth.complete_enrollment(w, session=s, admin=admin, code=current_code(secret), ip=IP)
        codes = out.recovery_codes
        stored = list(admin.recovery_codes)
    assert out.status == "ok" and len(codes) == 8 and len(set(codes)) == 8
    assert not set(codes) & set(stored) and all(len(h) == 64 for h in stored)


def test_login_rate_limit_covers_password_and_totp(chair):
    admin_id, secret = make_real_admin()
    for _ in range(3):
        assert login(password="nope nope nope!").status == "invalid"
    pending = login()
    assert pending.status == "ok"
    with write_session() as w:  # two TOTP failures -> 5 failures in total
        for _ in range(2):
            out = admin_auth.verify_second_factor(w, session=w.get(AdminSession, pending.session.id),
                                                  admin=w.get(AdminUser, admin_id), code="111111", ip=IP)
            assert out.status == "invalid"
    assert login().status == "limited"  # even the right password is refused now
    with write_session() as w:
        out = admin_auth.verify_second_factor(w, session=w.get(AdminSession, pending.session.id),
                                              admin=w.get(AdminUser, admin_id), code=current_code(secret), ip=IP)
    assert out.status == "limited"
    assert login(ip="198.51.100.9").status == "ok"  # other IP unaffected
    assert "admin.login.rate_limited" in audit_actions()
    bucket, limit, window = ratelimit.ADMIN_LOGIN_FAILURES
    assert limit == 5 and window == 900


def test_totp_not_required_gives_full_session_directly(monkeypatch):
    from tests.conftest import reload_settings
    monkeypatch.setenv("ADMIN_TOTP_REQUIRED", "false")
    reload_settings()
    make_real_admin(totp=False)
    out = login()
    assert out.stage == "done" and out.session.totp_verified


def test_totp_required_forces_enrollment_stage():
    make_real_admin(totp=False)
    out = login()
    assert out.stage == "enroll"
    with read_session() as r:
        s, a = admin_auth.resolve_session(r, out.raw_token)
        assert not admin_auth.is_complete(s, a)


def test_pending_session_expires_quickly():
    make_real_admin()
    out = login()
    with read_session() as r:
        assert admin_auth.resolve_session(r, out.raw_token) is not None
        assert admin_auth.resolve_session(r, out.raw_token, now=utcnow() + timedelta(minutes=11)) is None


def test_login_rotates_previous_cookie_session(monkeypatch):
    from tests.conftest import reload_settings
    monkeypatch.setenv("ADMIN_TOTP_REQUIRED", "false")
    reload_settings()
    make_real_admin(totp=False)
    a = login()
    b = login(old=a.raw_token)
    with read_session() as r:
        assert admin_auth.resolve_session(r, a.raw_token) is None
        assert admin_auth.resolve_session(r, b.raw_token) is not None


def test_change_password_revokes_other_sessions_and_audits(monkeypatch):
    from tests.conftest import reload_settings
    monkeypatch.setenv("ADMIN_TOTP_REQUIRED", "false")
    reload_settings()
    admin_id, _ = make_real_admin(totp=False)
    one, two = login(), login()
    with write_session() as w:
        admin = w.get(AdminUser, admin_id)
        s = w.get(AdminSession, one.session.id)
        assert not admin_auth.change_password(w, session=s, admin=admin, current_password="bad bad bad bad",
                                              new_password=NEW_PASSWORD, ip=IP)
    with write_session() as w:
        admin = w.get(AdminUser, admin_id)
        with pytest.raises(InvalidInput):
            admin_auth.change_password(w, session=w.get(AdminSession, one.session.id), admin=admin,
                                       current_password=PASSWORD, new_password="short", ip=IP)
    with write_session() as w:
        admin = w.get(AdminUser, admin_id)
        assert admin_auth.change_password(w, session=w.get(AdminSession, one.session.id), admin=admin,
                                          current_password=PASSWORD, new_password=NEW_PASSWORD, ip=IP)
    with read_session() as r:
        assert admin_auth.resolve_session(r, one.raw_token) is not None
        assert admin_auth.resolve_session(r, two.raw_token) is None
    assert login(password=PASSWORD).status == "invalid" and login(password=NEW_PASSWORD).status == "ok"
    assert "admin.password_changed" in audit_actions()


def test_cli_style_management_revokes_sessions_and_audits(chair):
    admin_id, secret = make_real_admin(role="chair", chairs=[chair])
    out = login()
    with write_session() as w:
        admin = w.get(AdminUser, admin_id)
        admin_auth.reset_totp(w, admin)
    with read_session() as r:
        a = r.get(AdminUser, admin_id)
        assert not a.totp_enabled and a.totp_secret is None and a.recovery_codes == []
        assert admin_auth.resolve_session(r, out.raw_token) is None
    with write_session() as w:
        admin_auth.reset_password(w, w.get(AdminUser, admin_id), NEW_PASSWORD)
        admin_auth.set_admin_active(w, w.get(AdminUser, admin_id), False)
    assert login(password=NEW_PASSWORD).status == "invalid"  # disabled
    acts = audit_actions()
    assert {"admin.totp_reset", "admin.password_reset", "admin.disabled"} <= set(acts)


def test_set_admin_chairs(chair, other_chair):
    admin_id, _ = make_real_admin(role="chair", chairs=[chair])
    with write_session() as w:
        admin = admin_auth.set_admin_chairs(w, w.get(AdminUser, admin_id), [other_chair.id])
        assert [c.id for c in admin.chairs] == [other_chair.id]
    with write_session() as w:
        with pytest.raises(InvalidInput):
            admin_auth.set_admin_chairs(w, w.get(AdminUser, admin_id), [])
