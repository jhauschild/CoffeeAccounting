"""Users, chairs, merge, audit, authorization helpers."""

import uuid

import pytest
from sqlalchemy import select

from app.models import AuditLog, ConsumptionEvent, PaymentEvent, User, UserSession
from app.services import audit, authz, chairs, ledger, users
from app.services.errors import Conflict, Forbidden, InvalidInput, NotFound, UserInactive
from tests import factories


@pytest.mark.parametrize(
    "raw,expected",
    [("Müller", "mueller"), ("  Jörg   Straße ", "joerg strasse"), ("ÄÖÜ", "aeoeue"), ("José Núñez", "jose nunez"),
     ("Łukasz Østergård", "lukasz ostergard"), ("Müller", "mueller"), ("ANNA", "anna")],
)
def test_normalize_name(raw, expected):
    assert users.normalize_name(raw) == expected


def test_search_finds_umlaut_names_both_ways(db, chair, other_chair):
    factories.make_user(db, "Müller", chair=chair)
    factories.make_user(db, "Mueller", chair=other_chair)
    factories.make_user(db, "Muster", chair=chair)
    for q in ("muller", "mueller", "Müller", " MÜL "):
        found = users.search_profiles(db, q)
        assert sorted((p.display_name, p.chair_short_name) for p in found) == [("Mueller", "CHB"), ("Müller", "CHA")]
    assert len(users.search_profiles(db, "")) == 3
    assert users.search_profiles(db, "%") == [] and users.search_profiles(db, "_") == []


def test_search_lists_only_active_profiles_with_chair(db, chair):
    factories.make_user(db, "Ina Active", chair=chair)
    factories.make_user(db, "Ina Inactive", chair=chair, status="inactive")
    found = users.search_profiles(db, "ina")
    assert [p.display_name for p in found] == ["Ina Active"]
    assert set(vars(found[0])) == {"id", "display_name", "chair_id", "chair_short_name", "chair_full_name"}


def test_create_user_validation(db, chair):
    u = users.create_user(db, display_name="  Grace   Hopper ", chair_id=chair.id)
    assert (u.display_name, u.normalized_name, u.status) == ("Grace Hopper", "grace hopper", "active")
    assert [p.id for p in users.find_same_name(db, display_name="grace HOPPER", chair_id=chair.id)] == [u.id]
    for name in ("", "   ", "x" * 61, "bad\x00name", "rtl‮name"):
        with pytest.raises(InvalidInput):
            users.create_user(db, display_name=name, chair_id=chair.id)
    inactive = factories.make_chair(db, active=False)
    for cid in (inactive.id, uuid.uuid4(), None):
        with pytest.raises(InvalidInput):
            users.create_user(db, display_name="Ok", chair_id=cid)


def test_user_chair_change_audited(db, user, other_chair):
    users.update_profile(db, user_id=user.id, display_name="Alice B", chair_id=other_chair.id, actor_type="user")
    assert (user.display_name, user.chair_id, user.chair.short_name) == ("Alice B", other_chair.id, "CHB")
    entry = db.scalars(select(AuditLog).where(AuditLog.action == "user.chair_changed")).one()
    assert (entry.actor_type, entry.actor_id, entry.target_id) == ("user", str(user.id), str(user.id))
    assert entry.meta["to_chair_id"] == str(other_chair.id)
    # name-only edits by the user are not audited; no-op chair "change" is not audited
    users.update_profile(db, user_id=user.id, chair_id=other_chair.id, actor_type="user")
    assert db.scalar(select(AuditLog.id).where(AuditLog.action == "user.updated")) is None
    assert len(db.scalars(select(AuditLog).where(AuditLog.action == "user.chair_changed")).all()) == 1


def test_admin_profile_edits_scope_and_audit(db, user, chair, other_chair, chair_admin, global_admin):
    users.update_profile(db, user_id=user.id, display_name="Alicia", actor_type="admin", actor_id=chair_admin.id)
    with pytest.raises(Forbidden):  # chair admins cannot change chairs
        users.update_profile(db, user_id=user.id, chair_id=other_chair.id, actor_type="admin",
                             actor_id=chair_admin.id)
    users.update_profile(db, user_id=user.id, chair_id=other_chair.id, actor_type="admin", actor_id=global_admin.id)
    with pytest.raises(Forbidden):  # now out of the chair admin's scope
        users.update_profile(db, user_id=user.id, display_name="X", actor_type="admin", actor_id=chair_admin.id)
    rows = db.scalars(select(AuditLog).order_by(AuditLog.id)).all()
    assert [(r.action, r.actor_type) for r in rows] == [("user.updated", "admin"), ("user.chair_changed", "admin")]


def test_inactive_user_cannot_edit_profile(db, user):
    user.status = "inactive"
    with pytest.raises(UserInactive):
        users.update_profile(db, user_id=user.id, display_name="New", actor_type="user")


def test_set_user_status(db, user, chair_admin, other_chair):
    users.set_user_status(db, admin=chair_admin, user_id=user.id, active=False)
    assert user.status == "inactive"
    users.set_user_status(db, admin=chair_admin, user_id=user.id, active=True)
    actions = db.scalars(select(AuditLog.action).order_by(AuditLog.id)).all()
    assert actions == ["user.deactivated", "user.reactivated"]
    outsider = factories.make_user(db, "Out", chair=other_chair)
    with pytest.raises(Forbidden):
        users.set_user_status(db, admin=chair_admin, user_id=outsider.id, active=False)
    with pytest.raises(NotFound):
        users.set_user_status(db, admin=chair_admin, user_id=uuid.uuid4(), active=False)


def _ledger_snapshot(db):
    rows = db.execute(select(ConsumptionEvent.__table__)).all() + db.execute(select(PaymentEvent.__table__)).all()
    return sorted(map(tuple, rows), key=str)


def test_merge_moves_no_events_and_totals_follow(db, chair, other_chair, price, global_admin):
    target = factories.make_user(db, "Anna", chair=chair)
    dup = factories.make_user(db, "Anna (phone)", chair=other_chair)
    older = factories.make_user(db, "Anna old", chair=chair)
    factories.add_events(db, target, ["single"])
    factories.add_events(db, dup, ["double", "double"])
    factories.add_events(db, older, ["single"])
    factories.make_payment(db, dup, global_admin, 300)
    users.merge_users(db, admin=global_admin, duplicate_id=older.id, target_id=dup.id)
    assert ledger.get_totals(db, dup.id).consumed_shots == 5
    s1 = factories.make_session(db, dup)
    db.commit()
    before = _ledger_snapshot(db)

    users.merge_users(db, admin=global_admin, duplicate_id=dup.id, target_id=target.id)
    db.commit()
    db.expire_all()
    assert _ledger_snapshot(db) == before  # no event modified or moved
    t = ledger.get_totals(db, target.id)
    assert (t.consumed_shots, t.consumed_amount_cents, t.paid_amount_cents, t.balance_cents) == (6, 300, 300, 0)
    assert ledger.get_totals(db, dup.id) == t and ledger.get_totals(db, older.id) == t
    assert db.get(User, older.id).merged_into_id == target.id  # earlier merge re-pointed
    assert db.get(User, dup.id).status == "merged"
    assert db.get(UserSession, s1.id).revoked_at is not None
    assert len(ledger.recent_consumption(db, target.id)) == 4
    assert [p.display_name for p in users.search_profiles(db, "anna")] == ["Anna"]
    entry = db.scalars(select(AuditLog).where(AuditLog.action == "user.merged",
                                              AuditLog.target_id == str(dup.id))).one()
    assert entry.meta["merged_into_id"] == str(target.id) and entry.meta["repointed_ids"] == [str(older.id)]


def test_merge_rules(db, chair, global_admin, chair_admin):
    a = factories.make_user(db, "A", chair=chair)
    b = factories.make_user(db, "B", chair=chair)
    with pytest.raises(Forbidden):
        users.merge_users(db, admin=chair_admin, duplicate_id=a.id, target_id=b.id)
    with pytest.raises(InvalidInput):
        users.merge_users(db, admin=global_admin, duplicate_id=a.id, target_id=a.id)
    users.merge_users(db, admin=global_admin, duplicate_id=a.id, target_id=b.id)
    with pytest.raises(Conflict):
        users.merge_users(db, admin=global_admin, duplicate_id=a.id, target_id=b.id)
    with pytest.raises(Conflict):  # cannot merge into a merged profile
        users.merge_users(db, admin=global_admin, duplicate_id=b.id, target_id=a.id)
    with pytest.raises(Conflict):
        users.update_profile(db, user_id=a.id, display_name="x", actor_type="user")
    with pytest.raises(Conflict):
        users.set_user_status(db, admin=global_admin, user_id=a.id, active=True)


def test_chairs_management(db, global_admin, chair_admin):
    c = chairs.create_chair(db, admin=global_admin, full_name="Chair of Robotics", short_name="ROB")
    with pytest.raises(Conflict):
        chairs.create_chair(db, admin=global_admin, full_name="Other", short_name="rob")
    with pytest.raises(Forbidden):
        chairs.create_chair(db, admin=chair_admin, full_name="X", short_name="X")
    with pytest.raises(Forbidden):
        chairs.set_chair_active(db, admin=chair_admin, chair_id=c.id, active=False)
    with pytest.raises(InvalidInput):
        chairs.create_chair(db, admin=global_admin, full_name="", short_name="E")
    chairs.rename_chair(db, admin=global_admin, chair_id=c.id, full_name="Robotics Chair")
    chairs.set_chair_active(db, admin=global_admin, chair_id=c.id, active=False)
    assert c.id not in {x.id for x in chairs.list_chairs(db, active_only=True)}
    chairs.set_chair_active(db, admin=None, chair_id=c.id, active=True)  # CLI / system actor
    assert chairs.get_chair_by_short_name(db, " rob ").id == c.id
    rows = db.scalars(select(AuditLog).order_by(AuditLog.id)).all()
    assert [(r.action, r.actor_type) for r in rows] == [
        ("chair.created", "admin"), ("chair.renamed", "admin"), ("chair.deactivated", "admin"),
        ("chair.reactivated", "system"),
    ]


def test_authz_helpers(db, user, chair, other_chair, chair_admin, global_admin):
    assert authz.visible_chair_ids(db, global_admin) is None
    assert authz.visible_chair_ids(db, chair_admin) == {chair.id}
    authz.ensure_admin_can_access_user(db, chair_admin, user.id)
    outsider = factories.make_user(db, "Out", chair=other_chair)
    with pytest.raises(Forbidden):
        authz.ensure_admin_can_access_user(db, chair_admin, outsider.id)
    authz.ensure_admin_can_access_user(db, global_admin, outsider.id)
    with pytest.raises(NotFound):
        authz.ensure_admin_can_access_user(db, global_admin, uuid.uuid4())
    global_admin.active = False
    with pytest.raises(Forbidden):
        authz.visible_chair_ids(db, global_admin)


def test_audit_log_rejects_secret_metadata(db):
    with pytest.raises(ValueError):
        audit.log(db, actor_type="admin", action="admin.login", metadata={"password": "x"})
    with pytest.raises(ValueError):
        audit.log(db, actor_type="admin", action="admin.login", metadata={"step": {"totp_code": "123456"}})
    with pytest.raises(ValueError):
        audit.log(db, actor_type="robot", action="x")
    e = audit.log(db, actor_type="admin", actor_id=uuid.uuid4(), action="admin.login_failed",
                  metadata={"username": "bob", "step": "totp"}, ip="203.0.113.9")
    assert e.meta == {"username": "bob", "step": "totp"} and e.source_ip == "203.0.113.9"
