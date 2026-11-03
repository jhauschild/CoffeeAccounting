"""Anonymizing deactivation: stash, Alumni N, restore via login/admin, inactivity job, authz."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import func, select

from app import cli
from app.models import AuditLog, User, UserSession
from app.services import login, mail, passwords, users
from app.services.errors import Conflict, Forbidden, InvalidCredentials
from app.timeutil import utcnow
from tests import factories
from tests.user_support import PASSWORD, field, make_account


@pytest.fixture(autouse=True)
def _memory_mail(monkeypatch):
    monkeypatch.setenv("MAIL_BACKEND", "memory")
    from tests.conftest import reload_settings

    reload_settings()
    mail.clear_outbox()
    yield
    mail.clear_outbox()


def test_self_deactivate_anonymizes_and_stashes(client, db, chair, login):
    account = make_account(db, "Self User", chair, username="selfuser")
    chair_id = account.chair_id
    original_email = account.email
    login(account)
    page = client.get("/account")
    assert page.status_code == 200 and "deactivate" in page.text
    r = client.post(
        "/account/deactivate",
        data={"csrf_token": field(page.text, "csrf_token"), "confirm": "1"},
        follow_redirects=False,
    )
    assert r.status_code == 303 and r.headers["location"].startswith("/")
    db.expire_all()
    user = db.get(User, account.id)
    assert user.status == "inactive"
    assert user.display_name.startswith("Alumni ")
    assert user.username.startswith("alumni-")
    assert user.email.startswith("anonymous-") and user.email.endswith("@example.org")
    assert user.chair_id == chair_id
    stash = users.get_identity_restore(db, user.id)
    assert stash is not None
    assert stash.username == "selfuser" and stash.email == original_email
    assert db.scalar(select(func.count()).select_from(UserSession).where(
        UserSession.user_id == user.id, UserSession.revoked_at.is_(None)
    )) == 0
    # signed out: account page needs login
    assert client.get("/account", follow_redirects=False).status_code == 303


def test_anonymous_cannot_deactivate(client):
    r = client.post("/account/deactivate", data={"confirm": "1"}, follow_redirects=False)
    assert r.status_code in (303, 401, 403)


def test_admin_deactivate_same_path(db, chair, global_admin):
    member = factories.make_member(db, "Admin Path", chair, username="adminpath",
                                   password_hash=passwords.hash_password(PASSWORD))
    chair_id = member.chair_id
    users.set_user_status(db, admin=global_admin, user_id=member.id, active=False, notify=False)
    db.commit()
    db.expire_all()
    user = db.get(User, member.id)
    assert user.status == "inactive" and user.display_name.startswith("Alumni ")
    assert user.chair_id == chair_id
    assert users.get_identity_restore(db, user.id) is not None
    meta = db.scalar(select(AuditLog.meta).where(AuditLog.action == "user.deactivated"))
    assert meta["anonymized"] is True and meta["reason"] == "admin" and "restore_until" in meta


def test_group_admin_can_deactivate_in_scope_member_not_peer_ga(db, chair, global_admin):
    ga = factories.make_admin(db, role="chair", chairs=[chair], username="ga1")
    peer = factories.make_admin(db, role="chair", chairs=[chair], username="ga2")
    member = factories.make_member(db, "In Scope", chair, username="inscope")
    users.set_user_status(db, admin=ga, user_id=member.id, active=False, notify=False)
    assert db.get(User, member.id).status == "inactive"
    with pytest.raises(Forbidden):
        users.set_user_status(db, admin=ga, user_id=peer.user_id, active=False, notify=False)
    db.rollback()
    users.set_user_status(db, admin=global_admin, user_id=peer.user_id, active=False, notify=False)
    assert db.get(User, peer.user_id).status == "inactive"


def test_login_restores_within_window(db, chair):
    account = factories.make_member(
        db, "Restore Me", chair, username="restoreme", password_hash=passwords.hash_password(PASSWORD)
    )
    chair_id, email = account.chair_id, account.email
    users.anonymize_deactivate(db, user=account, reason="self", actor_type="user", actor_id=account.id, notify=False)
    db.commit()
    assert db.get(User, account.id).username.startswith("alumni-")
    result = login.sign_in(db, username="restoreme", password=PASSWORD, ip="127.0.0.1")
    db.commit()
    user = db.get(User, account.id)
    assert user.status == "active"
    assert user.username == "restoreme" and user.email == email and user.display_name == "Restore Me"
    assert user.chair_id == chair_id
    assert users.get_identity_restore(db, user.id) is None
    assert user.last_activity_at is not None
    assert result.user.id == user.id


def test_login_fails_after_purge_expired(db, chair, capsys):
    account = factories.make_member(
        db, "Gone Forever", chair, username="goneforever", password_hash=passwords.hash_password(PASSWORD)
    )
    users.anonymize_deactivate(db, user=account, reason="admin", actor_type="admin", notify=False)
    stash = users.get_identity_restore(db, account.id)
    stash.expires_at = utcnow() - timedelta(seconds=1)
    db.commit()
    assert cli.main(["purge-expired"]) == 0
    assert "identity_restores=1" in capsys.readouterr().out
    db.rollback()
    assert users.get_identity_restore(db, account.id) is None
    with pytest.raises(InvalidCredentials):
        login.sign_in(db, username="goneforever", password=PASSWORD, ip="127.0.0.1")


def test_admin_restore_identity(db, chair, global_admin):
    account = factories.make_member(db, "Admin Restore", chair, username="adminrestore")
    users.set_user_status(db, admin=global_admin, user_id=account.id, active=False, notify=False)
    users.set_user_status(db, admin=global_admin, user_id=account.id, active=True)
    db.commit()
    user = db.get(User, account.id)
    assert user.status == "active" and user.username == "adminrestore" and user.display_name == "Admin Restore"
    assert users.get_identity_restore(db, user.id) is None


def test_restore_conflict_when_username_taken(db, chair, global_admin):
    first = factories.make_member(db, "First", chair, username="takenname",
                                  password_hash=passwords.hash_password(PASSWORD))
    users.set_user_status(db, admin=global_admin, user_id=first.id, active=False, notify=False)
    factories.make_member(db, "New Owner", chair, username="takenname")
    with pytest.raises(Conflict):
        users.restore_identity(db, user=db.get(User, first.id), actor_type="admin", actor_id=global_admin.id)


def test_concurrent_deactivate_gets_distinct_n(db, chair):
    a = factories.make_member(db, "A", chair, username="alumna")
    b = factories.make_member(db, "B", chair, username="alumnb")
    users.anonymize_deactivate(db, user=a, reason="admin", actor_type="system", notify=False)
    users.anonymize_deactivate(db, user=b, reason="admin", actor_type="system", notify=False)
    db.commit()
    names = {db.get(User, a.id).display_name, db.get(User, b.id).display_name}
    usernames = {db.get(User, a.id).username, db.get(User, b.id).username}
    assert len(names) == 2 and all(n.startswith("Alumni ") for n in names)
    assert len(usernames) == 2 and all(u.startswith("alumni-") for u in usernames)


def test_last_activity_updated_on_login(db, chair):
    account = factories.make_member(
        db, "Active", chair, username="activeone", password_hash=passwords.hash_password(PASSWORD)
    )
    old = utcnow() - timedelta(days=10)
    account.last_activity_at = old
    db.commit()
    login.sign_in(db, username="activeone", password=PASSWORD, ip="127.0.0.1")
    db.commit()
    assert db.get(User, account.id).last_activity_at > old


def test_inactivity_job_selects_and_mails(db, chair, monkeypatch, capsys):
    monkeypatch.setenv("INACTIVE_ACCOUNT_DAYS", "30")
    from tests.conftest import reload_settings

    reload_settings()
    stale = factories.make_member(
        db, "Stale", chair, username="staleone", password_hash=passwords.hash_password(PASSWORD)
    )
    fresh = factories.make_member(db, "Fresh", chair, username="freshone")
    stale.last_activity_at = utcnow() - timedelta(days=40)
    fresh.last_activity_at = utcnow() - timedelta(days=5)
    stale_email = stale.email
    stale_id, fresh_id = stale.id, fresh.id
    db.commit()
    due = users.list_inactive_due(db)
    assert {u.id for u in due} == {stale_id}
    assert cli.main(["deactivate-inactive", "--dry-run"]) == 0
    assert "would deactivate" in capsys.readouterr().out
    assert cli.main(["deactivate-inactive"]) == 0
    db.rollback()  # CLI committed in another connection; drop this session's snapshot
    assert db.get(User, stale_id).status == "inactive"
    assert db.get(User, fresh_id).status == "active"
    assert users.get_identity_restore(db, stale_id) is not None
    assert any(m.to == stale_email for m in mail.get_outbox())


def test_guest_deactivation_keeps_null_email(db, chair):
    sponsor = factories.make_member(db, "Sponsor", chair, username="sponsor1", email="sponsor1@tum.de")
    guest = factories.make_guest(db, sponsor, display_name="Guest One", username="guestone",
                                 password_hash=passwords.hash_password(PASSWORD))
    assert guest.email is None
    _user, messages = users.anonymize_deactivate(db, user=guest, reason="self", actor_type="user", notify=True)
    db.commit()
    g = db.get(User, guest.id)
    assert g.email is None and g.username.startswith("alumni-")
    assert any(m.to == "sponsor1@tum.de" for m in messages)


def test_owes_mails_user_and_group_admins(db, chair, price, global_admin):
    ga = factories.make_admin(db, role="chair", chairs=[chair], username="gaowes")
    ga_email = db.get(User, ga.user_id).email
    member = factories.make_member(db, "Owes Coffee", chair, username="owesone", email="owesone@tum.de")
    factories.add_events(db, member, ["single", "double"])  # 1.50 if price 50
    real_name = member.display_name
    _user, messages = users.anonymize_deactivate(
        db, user=member, reason="admin", actor_type="admin", actor_id=global_admin.id, notify=True
    )
    db.commit()
    assert db.get(User, member.id).display_name.startswith("Alumni ")
    tos = {m.to for m in messages}
    assert "owesone@tum.de" in tos and ga_email in tos
    user_mails = [m for m in messages if m.to == "owesone@tum.de"]
    assert any("please settle" in m.subject.lower() or "owe" in m.body.lower() for m in user_mails)
    assert any(real_name in m.body for m in messages if m.to == ga_email)
    meta = db.scalar(select(AuditLog.meta).where(AuditLog.action == "user.deactivated").order_by(AuditLog.id.desc()))
    assert meta["balance_cents"] > 0 and meta["balance_mails"]["collect_owed"] >= 1


def test_credit_mails_user_only(db, chair, price, global_admin):
    factories.make_admin(db, role="chair", chairs=[chair], username="gacredit")
    member = factories.make_member(db, "Has Credit", chair, username="creditone", email="creditone@tum.de")
    factories.make_payment(db, member, global_admin, 300)
    _user, messages = users.anonymize_deactivate(
        db, user=member, reason="self", actor_type="user", actor_id=member.id, notify=True
    )
    db.commit()
    settle = [m for m in messages if "credit to reclaim" in m.subject.lower()]
    assert len(settle) == 1 and settle[0].to == "creditone@tum.de"
    # no collect_owed mails to GAs for credit
    assert all("outstanding balance to collect" not in m.subject.lower() for m in messages)
    meta = db.scalar(select(AuditLog.meta).where(AuditLog.action == "user.deactivated").order_by(AuditLog.id.desc()))
    assert meta["balance_cents"] < 0 and meta["balance_mails"]["has_credit"] == 1 and meta["balance_mails"]["collect_owed"] == 0


def test_no_ga_escalates_to_head_notify_email(db, chair, price, global_admin, monkeypatch):
    monkeypatch.setenv("HEAD_ADMIN_NOTIFY_EMAIL", "head-ops@example.org")
    from tests.conftest import reload_settings

    reload_settings()
    member = factories.make_member(db, "Lone Owes", chair, username="loneowes", email="loneowes@tum.de")
    factories.add_events(db, member, ["single"])
    _user, messages = users.anonymize_deactivate(
        db, user=member, reason="admin", actor_type="admin", notify=True
    )
    db.commit()
    assert any(
        m.to == "head-ops@example.org" and "no active group admin" in m.body.lower() for m in messages
    )
    assert any(m.to == "loneowes@tum.de" for m in messages)
    meta = db.scalar(select(AuditLog.meta).where(AuditLog.action == "user.deactivated").order_by(AuditLog.id.desc()))
    assert meta["balance_mails"]["no_group_admin"] == 1 and meta["balance_notify_head_skipped"] is False


def test_no_ga_skips_head_when_unset(db, chair, price, global_admin):
    member = factories.make_member(db, "Skip Head", chair, username="skiphead", email="skiphead@tum.de")
    factories.add_events(db, member, ["single"])
    _user, messages = users.anonymize_deactivate(
        db, user=member, reason="admin", actor_type="admin", notify=True
    )
    db.commit()
    assert all("no group admin" not in m.subject.lower() for m in messages)  # head escalation subject
    meta = db.scalar(select(AuditLog.meta).where(AuditLog.action == "user.deactivated").order_by(AuditLog.id.desc()))
    assert meta["balance_notify_head_skipped"] is True and meta["balance_mails"]["no_group_admin"] == 0


def test_guest_owes_notifies_sponsor_and_gas(db, chair, price, global_admin):
    ga = factories.make_admin(db, role="chair", chairs=[chair], username="gaguest")
    ga_email = db.get(User, ga.user_id).email
    sponsor = factories.make_member(db, "Sponsor Two", chair, username="sponsor2", email="sponsor2@tum.de")
    guest = factories.make_guest(db, sponsor, display_name="Guest Owes", username="guestowes")
    factories.add_events(db, guest, ["double"])
    _user, messages = users.anonymize_deactivate(
        db, user=guest, reason="admin", actor_type="admin", notify=True
    )
    db.commit()
    tos = {m.to for m in messages}
    assert "sponsor2@tum.de" in tos and ga_email in tos
