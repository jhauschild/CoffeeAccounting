"""Admin accounts, passwords, TOTP enrolment, sessions, rate limiting (service level, v2 model)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from app.db import read_session, write_session
from app.models import AdminSession, AdminUser, AuditLog
from app.services import admin_auth, passwords, ratelimit
from app.services.errors import Conflict, InvalidInput
from app.timeutil import utcnow
from tests import factories
from tests.admin_support import (  # noqa: F401
    NEW_PASSWORD, PASSWORD, current_code, fast_hasher, login_name, make_real_admin,
)

IP = "203.0.113.7"


def audit_actions():
    with read_session() as r:
        return [a.action for a in r.scalars(select(AuditLog).order_by(AuditLog.id))]


def login(username="boss", password=PASSWORD, ip=IP, old=None):
    return admin_auth.start_login(username=username, password=password, ip=ip, old_raw_token=old)


def set_env(monkeypatch, **env):
    from tests.conftest import reload_settings
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    reload_settings()


# ----- passwords and accounts ---------------------------------------------------------------------
def test_password_policy_and_argon2id():
    with pytest.raises(InvalidInput):
        admin_auth.hash_password("short")
    h = admin_auth.hash_password(PASSWORD)
    assert h.startswith("$argon2id$")
    assert admin_auth.verify_password(h, PASSWORD)
    assert not admin_auth.verify_password(h, PASSWORD + "x")
    assert not admin_auth.verify_password("!", PASSWORD)  # disabled hash never matches


def test_create_admin_rules():
    with write_session() as w:
        with pytest.raises(InvalidInput):  # group admins are promoted members (task 4.3), not created here
            admin_auth.create_admin(w, username="c", password=PASSWORD, role="chair")
    with write_session() as w:
        with pytest.raises(InvalidInput):
            admin_auth.create_admin(w, username="x", password=PASSWORD, role="superuser")
    with write_session() as w:
        admin = admin_auth.create_admin(w, username="Boss", password=PASSWORD, role="global")
        assert admin.user_id is None and admin.totp_enabled is False
    with write_session() as w:
        with pytest.raises(Conflict):
            admin_auth.create_admin(w, username=" boss ", password=PASSWORD, role="global")
    assert audit_actions() == ["admin.created"]


def test_create_admin_refuses_a_username_held_by_a_user():
    with write_session() as w:
        factories.make_member(w, username="Taken_Name", commit=False)
    with write_session() as w:
        with pytest.raises(Conflict):
            admin_auth.create_admin(w, username="taken_name", password=PASSWORD, role="global")
    assert audit_actions() == []


def test_bootstrap_only_without_admins(monkeypatch, settings_env):
    set_env(monkeypatch, ADMIN_BOOTSTRAP_USERNAME="first", ADMIN_BOOTSTRAP_PASSWORD=PASSWORD)
    with write_session() as w:
        assert admin_auth.bootstrap_admin(w).username == "first"
    with write_session() as w:
        assert admin_auth.bootstrap_admin(w) is None  # ignored once an admin exists
        assert len(admin_auth.list_admins(w)) == 1


# ----- password login -----------------------------------------------------------------------------
def test_login_wrong_password_unknown_user_and_audit():
    make_real_admin()
    assert login(password="wrong password!!").status == "invalid"
    assert login(username="nobody").status == "invalid"
    ok = login()
    assert ok.status == "ok"
    acts = audit_actions()
    assert acts.count("admin.login.failed") == 2 and acts.count("admin.login.success") == 1
    with read_session() as r:
        meta = r.scalars(select(AuditLog).where(AuditLog.action == "admin.login.failed")).first().meta
    assert meta["step"] == "password" and "wrong password" not in str(meta)


def test_password_login_gives_full_session_without_stepup():
    make_real_admin()  # TOTP enabled, yet no second factor at login
    out = login()
    assert out.status == "ok"
    assert out.session.stepup_until is None
    with read_session() as r:
        s, a = admin_auth.resolve_session(r, out.raw_token)
        assert s.stepup_until is None and not admin_auth.has_open_stepup(s)
        assert s.expires_at - s.created_at == timedelta(hours=12)
        assert a.last_login_at is not None


def test_session_stores_only_token_hash():
    make_real_admin()
    out = login()
    with read_session() as r:
        row = r.scalars(select(AdminSession)).one()
        assert row.token_hash == admin_auth.hash_token(out.raw_token) != out.raw_token


def test_disabled_admin_cannot_login():
    admin_id, _ = make_real_admin()
    with write_session() as w:
        admin_auth.set_admin_active(w, w.get(AdminUser, admin_id), False)
    assert login().status == "invalid"


def test_login_rotates_previous_cookie_session():
    make_real_admin()
    a = login()
    b = login(old=a.raw_token)
    with read_session() as r:
        assert admin_auth.resolve_session(r, a.raw_token) is None
        assert admin_auth.resolve_session(r, b.raw_token) is not None


def test_has_open_stepup():
    make_real_admin()
    out = login()
    now = utcnow()
    with write_session() as w:
        s = w.get(AdminSession, out.session.id)
        assert not admin_auth.has_open_stepup(s, now)
        s.stepup_until = now + timedelta(seconds=60)
        assert admin_auth.has_open_stepup(s, now)
        assert not admin_auth.has_open_stepup(s, now + timedelta(seconds=61))


# ----- group admins ---------------------------------------------------------------------------------
def test_group_admin_logs_in_with_account_username_and_password(chair):
    admin_id, _ = make_real_admin(role="chair", chairs=[chair], password=PASSWORD)
    name = login_name(admin_id)
    assert name != "boss"
    out = login(username=name)
    assert out.status == "ok" and out.admin.role == "chair" and out.session.stepup_until is None
    assert login(username=name.upper()).status == "ok"  # usernames are case-insensitive
    assert login(username=name, password="wrong password!!").status == "invalid"
    assert login(username="boss").status == "invalid"  # the admin row's own name is not an identifier
    with read_session() as r:
        meta = r.scalars(select(AuditLog).where(AuditLog.action == "admin.login.success")).first().meta
    assert meta["group_admin"] is True


def test_group_admin_uses_the_account_password_not_an_admin_hash(chair):
    admin_id, _ = make_real_admin(role="chair", chairs=[chair])
    with write_session() as w:
        admin = w.get(AdminUser, admin_id)
        assert admin.password_hash is None
        admin.password_hash = admin_auth.hash_password(NEW_PASSWORD)  # a stray admin hash must not count
        name = admin.user.username
    assert login(username=name, password=NEW_PASSWORD).status == "invalid"
    assert login(username=name, password=PASSWORD).status == "ok"
    with write_session() as w:  # the account password changes: the old one stops working at once
        w.get(AdminUser, admin_id).user.password_hash = passwords.hash_password(NEW_PASSWORD)
    assert login(username=name, password=PASSWORD).status == "invalid"
    assert login(username=name, password=NEW_PASSWORD).status == "ok"


@pytest.mark.parametrize("change", ["inactive_user", "unverified_user", "admin_disabled", "no_hash"])
def test_group_admin_login_refused_when_account_unusable(chair, change):
    admin_id, _ = make_real_admin(role="chair", chairs=[chair])
    name = login_name(admin_id)
    with write_session() as w:
        admin = w.get(AdminUser, admin_id)
        if change == "inactive_user":
            admin.user.status = "inactive"
        elif change == "unverified_user":
            admin.user.verified_at = None
        elif change == "admin_disabled":
            admin.active = False
        else:
            admin.user.password_hash = "!"
    assert login(username=name).status == "invalid"


def test_existing_group_admin_session_dies_when_user_becomes_inactive(chair):
    admin_id, _ = make_real_admin(role="chair", chairs=[chair])
    out = login(username=login_name(admin_id))
    with read_session() as r:
        assert admin_auth.resolve_session(r, out.raw_token) is not None
    with write_session() as w:
        w.get(AdminUser, admin_id).user.status = "inactive"
    with read_session() as r:
        assert admin_auth.resolve_session(r, out.raw_token) is None


def test_a_plain_member_is_not_an_admin(chair):
    with write_session() as w:
        member = factories.make_member(w, username="plainmember", chair=chair, password_hash=passwords.hash_password(PASSWORD), commit=False)
    assert login(username=member.username).status == "invalid"
    assert audit_actions() == ["admin.login.failed"]


def test_group_admin_password_cannot_be_reset_by_the_cli_admin_command(chair):
    admin_id, _ = make_real_admin(role="chair", chairs=[chair])
    with write_session() as w:
        with pytest.raises(InvalidInput):
            admin_auth.reset_password(w, w.get(AdminUser, admin_id), NEW_PASSWORD)


def test_group_admin_change_password_changes_the_account_password(chair):
    admin_id, _ = make_real_admin(role="chair", chairs=[chair])
    name = login_name(admin_id)
    one, two = login(username=name), login(username=name)
    with write_session() as w:
        admin = w.get(AdminUser, admin_id)
        with pytest.raises(InvalidInput):  # the account policy applies (10 characters minimum)
            admin_auth.change_password(w, session=w.get(AdminSession, one.session.id), admin=admin,
                                       current_password=PASSWORD, new_password="short", ip=IP)
    with write_session() as w:
        admin = w.get(AdminUser, admin_id)
        assert admin_auth.change_password(w, session=w.get(AdminSession, one.session.id), admin=admin,
                                          current_password=PASSWORD, new_password=NEW_PASSWORD, ip=IP)
    with read_session() as r:
        assert admin_auth.resolve_session(r, one.raw_token) is not None
        assert admin_auth.resolve_session(r, two.raw_token) is None
        assert r.get(AdminUser, admin_id).password_hash is None
        user = r.get(AdminUser, admin_id).user
        assert passwords.verify_password(user.password_hash, NEW_PASSWORD)


# ----- TOTP enrolment ------------------------------------------------------------------------------
def test_enrolment_required_follows_balance_totp_required(monkeypatch):
    admin_id, _ = make_real_admin(totp=False)
    with read_session() as r:
        admin = r.get(AdminUser, admin_id)
        assert not admin_auth.enrolment_required(admin)  # development default: BALANCE_TOTP_REQUIRED false
    set_env(monkeypatch, BALANCE_TOTP_REQUIRED="true")
    with read_session() as r:
        admin = r.get(AdminUser, admin_id)
        assert admin_auth.enrolment_required(admin)
        admin.totp_enabled = True
        assert not admin_auth.enrolment_required(admin)


def test_complete_enrollment_enables_totp_and_opens_stepup_window():
    admin_id, _ = make_real_admin(totp=False)
    out = login()
    assert out.session.stepup_until is None
    with write_session() as w:
        admin = w.get(AdminUser, admin_id)
        secret = admin_auth.begin_enrollment(w, admin)
        before = utcnow()
        res = admin_auth.complete_enrollment(w, session=w.get(AdminSession, out.session.id), admin=admin,
                                             code=current_code(secret), ip=IP)
        codes = res.recovery_codes
    assert res.status == "ok" and len(codes) == 8 and len(set(codes)) == 8
    assert res.raw_token is None  # the session is kept, not rotated
    with read_session() as r:
        s, a = admin_auth.resolve_session(r, out.raw_token)
        assert a.totp_enabled
        assert admin_auth.has_open_stepup(s)
        window = (s.stepup_until - before).total_seconds()
        assert 295 <= window <= 301  # STEPUP_WINDOW_SECONDS default 300
        assert not admin_auth.has_open_stepup(s, utcnow() + timedelta(seconds=301))
        stored = list(a.recovery_codes)
    assert not set(codes) & set(stored) and all(len(h) == 64 for h in stored)
    assert "admin.totp_enrolled" in audit_actions()


def test_enrollment_wrong_code_and_replay_protection():
    admin_id, _ = make_real_admin(totp=False)
    out = login()
    with write_session() as w:
        admin = w.get(AdminUser, admin_id)
        secret = admin_auth.begin_enrollment(w, admin)
        bad = admin_auth.complete_enrollment(w, session=w.get(AdminSession, out.session.id), admin=admin,
                                             code="000000", ip=IP)
    assert bad.status == "invalid"
    with read_session() as r:
        assert not r.get(AdminUser, admin_id).totp_enabled
    code = current_code(secret)
    with write_session() as w:
        admin = w.get(AdminUser, admin_id)
        assert admin_auth.complete_enrollment(w, session=w.get(AdminSession, out.session.id), admin=admin,
                                              code=code, ip=IP).status == "ok"
    # the same code cannot be used again within 120 s (as a TOTP match)
    with write_session() as w:
        admin = w.get(AdminUser, admin_id)
        assert not admin_auth._totp_matches(w, admin, code, utcnow())
    with write_session() as w:
        with pytest.raises(Conflict):  # already enrolled
            admin_auth.complete_enrollment(w, session=w.get(AdminSession, out.session.id),
                                           admin=w.get(AdminUser, admin_id), code=current_code(secret, 1), ip=IP)
        with pytest.raises(Conflict):
            admin_auth.begin_enrollment(w, w.get(AdminUser, admin_id))


def test_totp_replay_window_is_120_seconds():
    admin_id, secret = make_real_admin()
    code = current_code(secret)
    now = utcnow()
    with write_session() as w:
        admin = w.get(AdminUser, admin_id)
        assert admin_auth._totp_matches(w, admin, code, now)
        assert not admin_auth._totp_matches(w, admin, code, now + timedelta(seconds=30))


def test_recovery_codes_are_single_use_and_normalised():
    admin_id, _ = make_real_admin()
    codes = admin_auth.new_recovery_codes()
    with write_session() as w:
        admin = w.get(AdminUser, admin_id)
        admin.recovery_codes = [admin_auth._recovery_hash(c) for c in codes]
        assert admin_auth._consume_recovery_code(admin, codes[0].lower().replace("-", " "))
        assert not admin_auth._consume_recovery_code(admin, codes[0])
        assert len(admin.recovery_codes) == 7


def test_enrollment_failures_share_the_login_rate_limit(chair):
    admin_id, _ = make_real_admin(totp=False)
    out = login()
    with write_session() as w:
        admin = w.get(AdminUser, admin_id)
        secret = admin_auth.begin_enrollment(w, admin)
    for _ in range(4):
        assert login(password="nope nope nope!").status == "invalid"
    with write_session() as w:  # the 5th failure of this username+IP is a wrong enrolment code
        res = admin_auth.complete_enrollment(w, session=w.get(AdminSession, out.session.id),
                                             admin=w.get(AdminUser, admin_id), code="111111", ip=IP)
        assert res.status == "invalid"
    with write_session() as w:
        res = admin_auth.complete_enrollment(w, session=w.get(AdminSession, out.session.id),
                                             admin=w.get(AdminUser, admin_id), code=current_code(secret), ip=IP)
        assert res.status == "limited"


# ----- rate limiting, sessions, management ------------------------------------------------------------
def test_login_rate_limit_and_audit():
    make_real_admin()
    for _ in range(5):
        assert login(password="nope nope nope!").status == "invalid"
    assert login().status == "limited"  # even the right password is refused now
    assert login(ip="198.51.100.9").status == "ok"  # other IP unaffected
    acts = audit_actions()
    assert acts.count("admin.login.rate_limited") == 1  # audited once per window
    bucket, limit, window = ratelimit.ADMIN_LOGIN_FAILURES
    assert limit == 5 and window == 900


def test_group_admin_login_rate_limit_is_per_account_username(chair):
    admin_id, _ = make_real_admin(role="chair", chairs=[chair])
    name = login_name(admin_id)
    for _ in range(5):
        assert login(username=name, password="nope nope nope!").status == "invalid"
    assert login(username=name).status == "limited"


def test_ip_cap_across_usernames_and_success_releases_the_counted_attempt():
    make_real_admin()
    for _ in range(4):
        assert login(password="wrong wrong wrong").status == "invalid"
    assert login().status == "ok"  # success is not a failure: it does not count against the budget
    assert login(password="wrong wrong wrong").status == "invalid"  # still under the 5/username+IP cap
    for i in range(15 - 5):
        assert login(username=f"nobody{i}", ip=IP).status == "invalid"
    assert login(username="nobody-else", ip=IP).status == "limited"  # per-IP cap across usernames
    assert login(username="nobody-else", ip="203.0.113.99").status == "invalid"  # other IPs unaffected


def test_unknown_username_runs_a_dummy_hash(monkeypatch):
    make_real_admin()
    calls = []
    real = passwords.verify_dummy
    monkeypatch.setattr(passwords, "verify_dummy", lambda pw: (calls.append(pw), real(pw))[1])
    assert login(username="nobody").status == "invalid"
    assert login(password="wrong password!!").status == "invalid"
    assert calls == [PASSWORD]  # only the unknown username took the decoy path


def test_change_password_revokes_other_sessions_and_audits():
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


def test_cli_style_management_revokes_sessions_and_audits():
    admin_id, secret = make_real_admin()
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


def test_set_admin_chairs_is_gone():
    assert not hasattr(admin_auth, "set_admin_chairs")
    assert not hasattr(admin_auth, "verify_second_factor") and not hasattr(admin_auth, "is_complete")


def test_session_model_has_stepup_until_instead_of_totp_verified():
    assert hasattr(AdminSession, "stepup_until") and not hasattr(AdminSession, "totp_verified")
