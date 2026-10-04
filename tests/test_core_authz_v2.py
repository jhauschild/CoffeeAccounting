"""v2 authz: a group admin's scope is the chair of the linked user account (task 1.5)."""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from app.models import AdminUser, ConsumptionEvent, PaymentEvent
from app.services import authz, ledger, users
from app.services.errors import Conflict, Forbidden, NotFound
from app.timeutil import utcnow
from tests import factories as f


@pytest.fixture
def ga(db, chair, price):
    return f.make_admin(db, role="chair", chairs=[chair])


def test_visible_chair_ids_is_exactly_the_linked_users_chair(db, ga, chair, other_chair, global_admin):
    assert authz.visible_chair_ids(db, ga) == {chair.id} == {ga.user.chair_id}
    assert authz.visible_chair_ids(db, global_admin) is None
    other = f.make_admin(db, role="chair", chairs=[other_chair])
    assert authz.visible_chair_ids(db, other) == {other_chair.id}


def test_scope_follows_a_chair_change_of_the_linked_user(db, ga, chair, other_chair, global_admin):
    assert authz.visible_chair_ids(db, ga) == {chair.id}
    with pytest.raises(Forbidden):  # F4/M3: update_profile refuses it while the role is active
        users.update_profile(db, actor_type="admin", actor_id=global_admin.id, user_id=ga.user_id,
                             chair_id=other_chair.id)
    db.query(type(ga.user)).filter_by(id=ga.user_id).update({"chair_id": other_chair.id})  # e.g. legacy data
    db.expire_all()
    assert authz.visible_chair_ids(db, ga) == {other_chair.id}
    outsider = f.make_user(db, "Was Inside", chair)
    with pytest.raises(Forbidden):
        authz.ensure_admin_can_access_user(db, ga, outsider.id)


def test_scope_is_read_from_the_database_not_a_cached_relationship(db, ga, chair, other_chair):
    assert ga.user.chair_id == chair.id  # relationship loaded
    db.query(type(ga.user)).filter_by(id=ga.user_id).update({"chair_id": other_chair.id})
    assert authz.visible_chair_ids(db, ga) == {other_chair.id}


def test_inactive_and_unlinked_admins_have_no_scope(db, ga, chair):
    ga.active = False
    with pytest.raises(Forbidden):
        authz.visible_chair_ids(db, ga)
    with pytest.raises(Forbidden):
        authz.ensure_admin_can_access_chair(db, ga, chair.id)
    with pytest.raises(Forbidden):
        authz.ensure_admin_can_access_user(db, ga, uuid.uuid4())
    ga.active = True
    ga.user_id = None  # cannot exist (CHECK) but must fail closed if it ever does
    assert authz.visible_chair_ids(db, ga) == set()
    with pytest.raises(Forbidden):
        authz.ensure_admin_can_access_chair(db, ga, chair.id)


def test_ensure_admin_can_access_user_uses_the_scope(db, ga, chair, other_chair, global_admin):
    inside = f.make_user(db, "Inside", chair)
    guest = f.make_guest(db, inside, "Inside Guest")
    outside = f.make_user(db, "Outside", other_chair)
    authz.ensure_admin_can_access_user(db, ga, inside.id)
    authz.ensure_admin_can_access_user(db, ga, guest.id)
    authz.ensure_admin_can_access_user(db, ga, ga.user_id)  # own account is in scope (balance rule is separate)
    with pytest.raises(Forbidden):
        authz.ensure_admin_can_access_user(db, ga, outside.id)
    with pytest.raises(NotFound):
        authz.ensure_admin_can_access_user(db, ga, uuid.uuid4())
    authz.ensure_admin_can_access_user(db, global_admin, outside.id)
    with pytest.raises(Forbidden):
        authz.ensure_admin_can_access_chair(db, ga, other_chair.id)
    authz.ensure_admin_can_access_chair(db, ga, chair.id)


def test_group_admin_cannot_change_balance_of_the_account_linked_to_themselves(db, ga, chair, global_admin):
    now = utcnow()
    own_event = f.add_events(db, ga.user, "single")[0]
    with pytest.raises(Forbidden):
        ledger.add_payment(db, admin=ga, user_id=ga.user_id, amount_cents=100, idempotency_key="own-1")
    with pytest.raises(Forbidden):
        ledger.add_adjustment(db, admin=ga, user_id=ga.user_id, quantity=1)
    with pytest.raises(Forbidden):
        ledger.admin_reverse_event(db, admin=ga, event_id=own_event.id)
    with pytest.raises(Forbidden):
        ledger.set_balance(db, admin=ga, user_id=ga.user_id, target_balance_cents=0, idempotency_key="own-2")
    assert db.query(PaymentEvent).count() == 0
    assert db.query(ConsumptionEvent).count() == 1
    # the head admin may post to a group admin's own account
    ledger.add_payment(db, admin=global_admin, user_id=ga.user_id, amount_cents=10, idempotency_key="head-1",
                       now=now)
    # ... and the group admin may still act on other members of the chair
    other = f.make_user(db, "Colleague", chair)
    payment = ledger.add_payment(db, admin=ga, user_id=other.id, amount_cents=200, idempotency_key="col-1")
    assert payment.collector_admin_id == ga.id


def test_own_account_rule_holds_through_a_merged_duplicate(db, ga, chair, global_admin):
    dup = f.make_user(db, "Gina Duplicate", chair)
    dup_event = f.add_events(db, dup, "single")[0]
    users.merge_users(db, admin=global_admin, duplicate_id=dup.id, target_id=ga.user_id)
    db.commit()
    with pytest.raises(Conflict):  # a merged profile cannot be posted to at all
        ledger.add_payment(db, admin=ga, user_id=dup.id, amount_cents=50, idempotency_key="dup-1")
    with pytest.raises(Forbidden):  # its old events count for the admin's own account
        ledger.admin_reverse_event(db, admin=ga, event_id=dup_event.id)
    with pytest.raises(Forbidden):
        ledger.add_payment(db, admin=ga, user_id=ga.user_id, amount_cents=50, idempotency_key="dup-2")


def test_group_admin_cannot_act_outside_the_own_chair(db, ga, other_chair, price):
    outsider = f.make_user(db, "Elsewhere", other_chair)
    event = f.add_events(db, outsider, "single", at=utcnow() - timedelta(days=1))[0]
    with pytest.raises(Forbidden):
        ledger.add_payment(db, admin=ga, user_id=outsider.id, amount_cents=50, idempotency_key="out-1")
    with pytest.raises(Forbidden):
        ledger.add_adjustment(db, admin=ga, user_id=outsider.id, quantity=1)
    with pytest.raises(Forbidden):
        ledger.admin_reverse_event(db, admin=ga, event_id=event.id)


def test_demoted_group_admin_loses_all_access(db, ga, chair):
    inside = f.make_user(db, "Inside", chair)
    db.query(AdminUser).filter_by(id=ga.id).update({"active": False})
    db.refresh(ga)
    with pytest.raises(Forbidden):
        ledger.add_payment(db, admin=ga, user_id=inside.id, amount_cents=50, idempotency_key="dem-1")
