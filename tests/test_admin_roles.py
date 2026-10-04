"""Task 4.3: group-admin roles (promote/demote services), the role button, /admin/admins and guest sponsor
reassignment."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app.db import read_session, write_session
from app.models import AdminSession, AdminUser, AuditLog, User
from app.services import admin_auth, groups, ledger, passwords, roles
from app.services.errors import Conflict, Forbidden, InvalidInput, NotFound, UserInactive
from tests import factories
from tests.admin_support import PASSWORD, fast_hasher, login_as, make_real_admin, new_client  # noqa: F401


# ----- fixtures -----------------------------------------------------------------------------------
@pytest.fixture
def head(db):
    return factories.make_admin(db, "global", username="boss")


@pytest.fixture
def member(db, chair):
    return factories.make_member(db, "Maria Member", chair, username="maria")


def promote(db, head, user, **kw):
    row = roles.promote_group_admin(db, head_admin=head, user_id=user.id, **kw)
    db.commit()
    return row


def audit_actions() -> list[str]:
    with read_session() as r:
        return [a.action for a in r.scalars(select(AuditLog).order_by(AuditLog.id))]


# ----- promote ------------------------------------------------------------------------------------
def test_promote_member_creates_linked_chair_admin_without_own_password(db, head, member, chair):
    row = promote(db, head, member)
    assert row.role == "chair" and row.active and row.user_id == member.id
    assert row.password_hash is None
    assert row.username == "maria" and row.username_normalized == "maria"
    assert row.recovery_codes == [] and not row.totp_enabled
    assert "admin.group_admin_promoted" in audit_actions()


def test_scope_of_a_promoted_admin_is_the_members_own_chair(db, head, member, chair, other_chair):
    from app.services import authz
    row = promote(db, head, member)
    assert authz.visible_chair_ids(db, row) == {chair.id}
    mate = factories.make_user(db, "Chair Mate", chair)
    stranger = factories.make_user(db, "Stranger", other_chair)
    authz.ensure_admin_can_access_user(db, row, mate.id)
    with pytest.raises(Forbidden):
        authz.ensure_admin_can_access_user(db, row, stranger.id)


def test_two_group_admins_in_the_same_chair(db, head, member, chair):
    second = factories.make_member(db, "Max Member", chair, username="max")
    a, b = promote(db, head, member), promote(db, head, second)
    assert a.id != b.id and a.active and b.active
    assert db.scalar(select(func.count()).select_from(AdminUser).where(AdminUser.role == "chair")) == 2


def test_guest_cannot_be_promoted(db, head, member):
    guest = factories.make_guest(db, member, "Gus Guest")
    with pytest.raises(Forbidden) as exc:
        roles.promote_group_admin(db, head_admin=head, user_id=guest.id)
    assert exc.value.context["reason"] == "not_member"
    assert db.scalar(select(func.count()).select_from(AdminUser).where(AdminUser.user_id == guest.id)) == 0


def test_inactive_unverified_and_unknown_users_cannot_be_promoted(db, head, member, chair):
    inactive = factories.make_member(db, "Ina Inactive", chair, username="ina")
    inactive.status = "inactive"
    unverified = factories.make_member(db, "Una Unverified", chair, username="una")
    unverified.verified_at = None
    db.commit()
    for user in (inactive, unverified):
        with pytest.raises(UserInactive):
            roles.promote_group_admin(db, head_admin=head, user_id=user.id)
    import uuid
    with pytest.raises(NotFound):
        roles.promote_group_admin(db, head_admin=head, user_id=uuid.uuid4())


def test_promoting_twice_is_a_conflict(db, head, member):
    promote(db, head, member)
    with pytest.raises(Conflict):
        roles.promote_group_admin(db, head_admin=head, user_id=member.id)


def test_group_admin_and_inactive_head_cannot_promote_or_demote(db, head, member, chair):
    ga = promote(db, head, member)
    other = factories.make_member(db, "Other Member", chair, username="other")
    with pytest.raises(Forbidden):
        roles.promote_group_admin(db, head_admin=ga, user_id=other.id)
    with pytest.raises(Forbidden):
        roles.demote_group_admin(db, head_admin=ga, user_id=member.id)
    head.active = False
    with pytest.raises(Forbidden):
        roles.promote_group_admin(db, head_admin=head, user_id=other.id)


def test_a_cli_admin_with_the_same_username_blocks_promotion(db, head, chair):
    factories.make_admin(db, "global", username="taken")
    user = factories.make_member(db, "Taken Name", chair, username="taken")
    with pytest.raises(Conflict) as exc:
        roles.promote_group_admin(db, head_admin=head, user_id=user.id)
    assert exc.value.context["reason"] == "username_taken"


def test_head_admin_cannot_promote_or_demote_themselves(db, chair):
    own_account = factories.make_member(db, "Boss Person", chair, username="bossy")
    boss = factories.make_admin(db, "global", username="bossy-cli")
    boss.user_id = own_account.id  # a head admin that is also linked to a member account
    db.commit()
    for fn in (roles.promote_group_admin, roles.demote_group_admin):
        with pytest.raises(Forbidden) as exc:
            fn(db, head_admin=boss, user_id=own_account.id)
        assert exc.value.context["reason"] == "self"


def test_head_admins_cannot_be_removed_through_the_role_services(db, chair):
    """The role services only ever touch group-admin rows: a head admin row (even one linked to an account) is
    refused, and the last active head admin is protected (actor == target is `self`, a different actor means a
    second head exists, and a head row is never deactivated here)."""
    account = factories.make_member(db, "Linked Head", chair, username="linked-head")
    only = factories.make_admin(db, "global", username="only-head")
    only.user_id = account.id
    other = factories.make_admin(db, "global", username="other-head")
    db.commit()
    assert roles.active_global_count(db) == 2
    with pytest.raises(Forbidden) as exc:  # the lone head removing itself
        roles.demote_group_admin(db, head_admin=only, user_id=account.id)
    assert exc.value.context["reason"] == "self"
    with pytest.raises(InvalidInput):  # another head cannot demote a head row either
        roles.demote_group_admin(db, head_admin=other, user_id=account.id)
    with pytest.raises(InvalidInput):
        roles.promote_group_admin(db, head_admin=other, user_id=account.id)
    db.commit()
    assert roles.active_global_count(db) == 2
    assert db.get(AdminUser, only.id).active is True and db.get(AdminUser, only.id).role == "global"


# ----- demote -------------------------------------------------------------------------------------
def test_demote_deactivates_revokes_sessions_and_keeps_role_and_link(db, head, member, app):
    row = promote(db, head, member)
    client = new_client(app)
    login_as(client, row.id)
    login_as(new_client(app), row.id)
    held = roles.demote_group_admin(db, head_admin=head, user_id=member.id)
    db.commit()
    assert held == 0
    with read_session() as r:
        kept = r.get(AdminUser, row.id)
        assert kept.active is False and kept.role == "chair" and kept.user_id == member.id
        sessions = list(r.scalars(select(AdminSession).where(AdminSession.admin_id == row.id)))
        assert len(sessions) == 2 and all(s.revoked_at is not None for s in sessions)
    assert client.get("/admin", follow_redirects=False).headers["location"] == "/admin/login"
    assert "admin.group_admin_demoted" in audit_actions()


def test_demote_returns_the_held_amount_and_keeps_the_former_admin_listed(db, head, member, chair, price):
    row = promote(db, head, member)
    payer = factories.make_user(db, "Payer", chair)
    ledger.add_payment(db, admin=row, user_id=payer.id, amount_cents=1500)
    groups.record_remittance(db, head_admin=head, group_admin_id=row.id, amount_cents=500, idempotency_key="k1")
    db.commit()
    assert roles.demote_group_admin(db, head_admin=head, user_id=member.id) == 1000
    db.commit()
    listed = {b.admin_id: b for b in groups.list_group_balances(db)}
    assert listed[row.id].held_cents == 1000 and listed[row.id].is_current is False
    holders = roles.list_role_holders(db, head)
    former = [g for g in holders.group_admins if g.admin_id == row.id][0]
    assert not former.active and former.held_cents == 1000


def test_demote_errors(db, head, member):
    with pytest.raises(NotFound):
        roles.demote_group_admin(db, head_admin=head, user_id=member.id)  # never a group admin
    promote(db, head, member)
    roles.demote_group_admin(db, head_admin=head, user_id=member.id)
    with pytest.raises(Conflict):
        roles.demote_group_admin(db, head_admin=head, user_id=member.id)


def test_repromotion_reactivates_the_same_row(db, head, member):
    first = promote(db, head, member)
    roles.demote_group_admin(db, head_admin=head, user_id=member.id)
    db.commit()
    again = promote(db, head, member)
    assert again.id == first.id and again.active and again.role == "chair"
    assert db.scalar(select(func.count()).select_from(AdminUser).where(AdminUser.user_id == member.id)) == 1
    assert db.scalars(select(AuditLog).where(AuditLog.action == "admin.group_admin_promoted")
                      .order_by(AuditLog.id.desc())).first().meta["reactivated"] is True


def test_promoted_member_can_sign_in_with_the_account_password(db, head, chair):
    user = factories.make_member(db, "Login Person", chair, username="loginner",
                                 password_hash=passwords.hash_password(PASSWORD))
    promote(db, head, user)
    out = admin_auth.start_login(username="loginner", password=PASSWORD, ip="127.0.0.1")
    assert out.status == "ok"
    roles_after = None
    with write_session() as w:
        roles.demote_group_admin(w, head_admin=w.get(AdminUser, head.id), user_id=user.id)
        roles_after = True
    assert roles_after
    assert admin_auth.start_login(username="loginner", password=PASSWORD, ip="127.0.0.1").status != "ok"


def test_role_changes_are_audited_with_actor_and_target(db, head, member):
    promote(db, head, member, ip="10.0.0.9")
    roles.demote_group_admin(db, head_admin=head, user_id=member.id, ip="10.0.0.9")
    db.commit()
    with read_session() as r:
        entries = list(r.scalars(select(AuditLog).where(AuditLog.action.like("admin.group_admin_%"))
                                 .order_by(AuditLog.id)))
        assert [e.action for e in entries] == ["admin.group_admin_promoted", "admin.group_admin_demoted"]
        for e in entries:
            assert e.actor_type == "admin" and e.actor_id == str(head.id)
            assert e.target_type == "user" and e.target_id == str(member.id) and e.source_ip == "10.0.0.9"


# ----- the pages ----------------------------------------------------------------------------------
@pytest.fixture
def head_client(app):
    admin_id, _ = make_real_admin(username="webboss")
    c = new_client(app)
    return c, login_as(c, admin_id)


def test_detail_page_shows_one_button_for_members_and_none_for_guests(head_client, db, member):
    c, csrf = head_client
    html = c.get(f"/admin/users/{member.id}").text
    assert "Make group admin" in html and "Remove group admin" not in html
    assert f"/admin/users/{member.id}/group-admin/promote" in html
    guest = factories.make_guest(db, member, "Gus Guest")
    guest_html = c.get(f"/admin/users/{guest.id}").text
    assert "Make group admin" not in guest_html and "Remove group admin" not in guest_html
    assert "group-admin/promote" not in guest_html


def test_promote_and_demote_through_the_page(head_client, member):
    c, csrf = head_client
    r = c.post(f"/admin/users/{member.id}/group-admin/promote", data={"csrf_token": csrf}, follow_redirects=False)
    assert r.status_code == 303 and "msg=group_admin_added" in r.headers["location"]
    html = c.get(f"/admin/users/{member.id}").text
    assert "Remove group admin" in html and "Make group admin" not in html
    with read_session() as r2:
        assert r2.scalar(select(AdminUser.active).where(AdminUser.user_id == member.id)) is True
    r = c.post(f"/admin/users/{member.id}/group-admin/demote", data={"csrf_token": csrf}, follow_redirects=False)
    assert r.status_code == 303 and "msg=group_admin_removed" in r.headers["location"]
    assert "Make group admin" in c.get(f"/admin/users/{member.id}").text


def test_role_post_needs_csrf(head_client, member):
    c, _ = head_client
    r = c.post(f"/admin/users/{member.id}/group-admin/promote", data={}, follow_redirects=False)
    assert r.status_code in (400, 403)
    with read_session() as r2:
        assert r2.scalar(select(func.count()).select_from(AdminUser).where(AdminUser.user_id == member.id)) == 0


def test_promoting_a_guest_through_the_route_is_refused_with_a_message(head_client, db, member):
    c, csrf = head_client
    guest = factories.make_guest(db, member, "Gus Guest")
    r = c.post(f"/admin/users/{guest.id}/group-admin/promote", data={"csrf_token": csrf}, follow_redirects=False)
    assert r.status_code == 303 and "err=not_member" in r.headers["location"]
    with read_session() as r2:
        assert r2.scalar(select(func.count()).select_from(AdminUser).where(AdminUser.user_id == guest.id)) == 0


def test_demotion_warns_when_the_person_still_holds_money(head_client, db, head, member, chair, price):
    c, csrf = head_client
    row = promote(db, head, member)
    payer = factories.make_user(db, "Payer", chair)
    ledger.add_payment(db, admin=row, user_id=payer.id, amount_cents=2000)
    db.commit()
    page = c.get(f"/admin/users/{member.id}").text
    assert "still holds" in page
    r = c.post(f"/admin/users/{member.id}/group-admin/demote", data={"csrf_token": csrf}, follow_redirects=False)
    assert "msg=group_admin_removed_held" in r.headers["location"]
    after = c.get(f"/admin/users/{member.id}").text
    assert "was a group admin" in after and "Still holds" in after


def test_group_admin_never_sees_the_button_and_gets_403(app, db, chair):
    admin_id, _ = make_real_admin(role="chair", chairs=[chair], username="gadm")
    c = new_client(app)
    csrf = login_as(c, admin_id)
    mate = factories.make_member(db, "Mate Member", chair, username="mate")
    html = c.get(f"/admin/users/{mate.id}").text
    assert "Make group admin" not in html and "Remove group admin" not in html
    for path in (f"/admin/users/{mate.id}/group-admin/promote", f"/admin/users/{mate.id}/group-admin/demote"):
        assert c.post(path, data={"csrf_token": csrf}, follow_redirects=False).status_code == 403
    assert c.get("/admin/admins", follow_redirects=False).status_code == 403
    with read_session() as r:
        assert r.scalar(select(func.count()).select_from(AdminUser).where(AdminUser.user_id == mate.id)) == 0


def test_admins_page_lists_head_admins_and_group_admins(head_client, db, head, member, chair, price):
    c, _ = head_client
    row = promote(db, head, member)
    former_member = factories.make_member(db, "Fiona Former", chair, username="fiona")
    promote(db, head, former_member)
    payer = factories.make_user(db, "Payer", chair)
    ledger.add_payment(db, admin=row, user_id=payer.id, amount_cents=700)
    roles.demote_group_admin(db, head_admin=head, user_id=member.id)
    db.commit()
    html = c.get("/admin/admins").text
    assert "webboss" in html  # head admin
    assert "Maria Member" in html and "former" in html  # former group admin who still holds money
    assert "Fiona Former" in html and "active" in html
    assert chair.short_name in html
    assert "/admin/groups" in html
    assert f"/admin/users/{member.id}" in html


# ----- sponsor reassignment -----------------------------------------------------------------------
@pytest.fixture
def guest_world(db, chair, other_chair):
    sponsor = factories.make_member(db, "Sven Sponsor", chair, username="sven")
    new_sponsor = factories.make_member(db, "Nora Newsponsor", other_chair, username="nora")
    guest = factories.make_guest(db, sponsor, "Gus Guest")
    return sponsor, new_sponsor, guest


def test_guest_detail_shows_the_sponsor_and_a_change_form(head_client, guest_world):
    c, _ = head_client
    sponsor, _, guest = guest_world
    html = c.get(f"/admin/users/{guest.id}").text
    assert "Sven Sponsor" in html and "Change sponsor" in html
    assert f"/admin/users/{guest.id}/sponsor" in html


def test_sponsor_search_lists_only_active_verified_members(head_client, db, guest_world, other_chair):
    c, _ = head_client
    sponsor, new_sponsor, guest = guest_world
    inactive = factories.make_member(db, "Nora Inactive", other_chair, username="nora2")
    inactive.status = "inactive"
    unverified = factories.make_member(db, "Nora Unverified", other_chair, username="nora3")
    unverified.verified_at = None
    other_guest = factories.make_guest(db, new_sponsor, "Nora Guest")
    db.commit()
    html = c.get(f"/admin/users/{guest.id}/sponsor?q=nora").text
    assert "Nora Newsponsor" in html
    for hidden in ("Nora Inactive", "Nora Unverified", "Nora Guest"):
        assert hidden not in html
    assert "Sven Sponsor" not in c.get(f"/admin/users/{guest.id}/sponsor?q=sven").text.split("Members")[-1]


def test_reassigning_a_sponsor_moves_the_guest_to_the_new_chair_and_audits(head_client, db, guest_world, other_chair):
    c, csrf = head_client
    sponsor, new_sponsor, guest = guest_world
    r = c.post(f"/admin/users/{guest.id}/sponsor", data={"csrf_token": csrf, "sponsor_id": str(new_sponsor.id)},
               follow_redirects=False)
    assert r.status_code == 303 and "msg=sponsor_changed" in r.headers["location"]
    with read_session() as r2:
        moved = r2.get(User, guest.id)
        assert moved.sponsor_id == new_sponsor.id and moved.chair_id == other_chair.id
        entry = r2.scalars(select(AuditLog).where(AuditLog.action == "guest.sponsor_reassigned")).one()
        assert entry.target_id == str(guest.id) and entry.meta["to_sponsor_id"] == str(new_sponsor.id)
        assert entry.actor_type == "admin"
    assert "Nora Newsponsor" in c.get(f"/admin/users/{guest.id}").text


def test_sponsor_change_refuses_a_guest_as_sponsor_and_non_guests(head_client, db, guest_world, member):
    c, csrf = head_client
    sponsor, new_sponsor, guest = guest_world
    other_guest = factories.make_guest(db, new_sponsor, "Other Guest")
    r = c.post(f"/admin/users/{guest.id}/sponsor", data={"csrf_token": csrf, "sponsor_id": str(other_guest.id)},
               follow_redirects=False)
    assert r.status_code == 303 and "err=invalid_input" in r.headers["location"]
    r = c.post(f"/admin/users/{sponsor.id}/sponsor", data={"csrf_token": csrf, "sponsor_id": str(new_sponsor.id)},
               follow_redirects=False)
    assert r.status_code == 303 and "err=" in r.headers["location"]
    with read_session() as r2:
        assert r2.get(User, guest.id).sponsor_id == sponsor.id
    assert c.get(f"/admin/users/{sponsor.id}/sponsor", follow_redirects=False).headers["location"].endswith(
        "err=not_a_guest")


def test_group_admin_cannot_reassign_sponsors(app, db, chair, guest_world):
    sponsor, new_sponsor, guest = guest_world
    admin_id, _ = make_real_admin(role="chair", chairs=[chair], username="gadm2")
    c = new_client(app)
    csrf = login_as(c, admin_id)
    assert c.get(f"/admin/users/{guest.id}/sponsor", follow_redirects=False).status_code == 403
    r = c.post(f"/admin/users/{guest.id}/sponsor", data={"csrf_token": csrf, "sponsor_id": str(new_sponsor.id)},
               follow_redirects=False)
    assert r.status_code == 403
    html = c.get(f"/admin/users/{guest.id}").text
    assert "Change sponsor" not in html
    with read_session() as r2:
        assert r2.get(User, guest.id).sponsor_id == sponsor.id
