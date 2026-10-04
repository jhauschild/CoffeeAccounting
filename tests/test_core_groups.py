"""Group balances, chair roll-up and remittances (task 1.4)."""

import uuid

import pytest
from sqlalchemy import func, select

from app.models import AuditLog, GroupRemittance
from app.services import groups, ledger
from app.services.errors import (
    Conflict,
    Forbidden,
    InvalidAmount,
    InvalidInput,
    NotFound,
)
from tests import factories


@pytest.fixture
def ga(db, chair):
    return factories.make_admin(db, role="chair", chairs=[chair], username="ga1")


@pytest.fixture
def payer(db, chair):
    return factories.make_user(db, "Payer", chair=chair)


def pay(db, admin, user, cents, **kw):
    p = ledger.add_payment(db, admin=admin, user_id=user.id, amount_cents=cents, **kw)
    db.commit()
    return p


def remit(db, head, ga, cents, key=None, **kw):
    r = groups.record_remittance(db, head_admin=head, group_admin_id=ga.id, amount_cents=cents,
                                 idempotency_key=key or uuid.uuid4().hex, **kw)
    db.commit()
    return r


def test_collected_and_held_basic(db, ga, payer, global_admin):
    assert groups.collected(db, ga.id) == 0 and groups.held(db, ga.id) == 0
    pay(db, ga, payer, 1000)
    pay(db, ga, payer, 500)
    pay(db, ga, payer, -200)  # paid back reduces collected
    assert groups.collected(db, ga.id) == 1300
    remit(db, global_admin, ga, 800)
    assert groups.held(db, ga.id) == 500
    remit(db, global_admin, ga, -100)  # signed: negative remittance raises held again
    assert groups.held(db, ga.id) == 600


def test_bookkeeping_and_other_collectors_never_count(db, ga, payer, global_admin, price):
    factories.add_events(db, payer, ["double"])
    ledger.set_balance(db, admin=global_admin, user_id=payer.id, target_balance_cents=0, idempotency_key="sb1")
    db.commit()
    pay(db, global_admin, payer, 700)  # collected by the head admin, not a group admin
    pay(db, ga, payer, 300)
    assert groups.collected(db, ga.id) == 300
    assert groups.collected(db, global_admin.id) == 700
    assert [r.admin_id for r in groups.list_group_balances(db)] == [ga.id]
    assert [r.collected_cents for r in groups.chair_rollup(db)] == [300]


def test_correction_keeps_collector(db, ga, payer, global_admin):
    p = pay(db, ga, payer, 1000)
    pay(db, global_admin, payer, -1000, correction_of_id=p.id)  # head admin corrects: still ga's money
    assert groups.collected(db, ga.id) == 0
    assert groups.collected(db, global_admin.id) == 0


def test_list_group_balances_rows_and_negative_flag(db, chair, other_chair, global_admin, payer):
    a = factories.make_admin(db, role="chair", chairs=[chair], username="aaa")
    b = factories.make_admin(db, role="chair", chairs=[other_chair], username="bbb")
    pay(db, a, payer, 1000)
    remit(db, global_admin, a, 400)
    remit(db, global_admin, b, 250)
    rows = {r.admin_id: r for r in groups.list_group_balances(db)}
    assert set(rows) == {a.id, b.id}
    ra, rb = rows[a.id], rows[b.id]
    assert (ra.collected_cents, ra.remitted_cents, ra.held_cents) == (1000, 400, 600)
    assert ra.is_current and not ra.negative and ra.chair_short_name == "CHA"
    assert (rb.collected_cents, rb.remitted_cents, rb.held_cents) == (0, 250, -250)
    assert rb.negative and rb.chair_id == other_chair.id
    assert groups.held(db, b.id) == -250


def test_former_group_admin_listed_while_holding_and_after_settling(db, ga, payer, global_admin):
    pay(db, ga, payer, 1000)
    ga.active = False
    db.commit()
    (row,) = groups.list_group_balances(db)
    assert row.admin_id == ga.id and row.is_current is False and row.held_cents == 1000
    remit(db, global_admin, ga, 1000)  # a former admin can still be settled
    assert groups.held(db, ga.id) == 0
    # L-4: a former admin with any collection or remittance event stays listed even with held 0
    (row,) = groups.list_group_balances(db)
    assert row.admin_id == ga.id and row.is_current is False and row.held_cents == 0
    # a current admin with nothing to show stays listed
    ga.active = True
    db.commit()
    assert [r.is_current for r in groups.list_group_balances(db)] == [True]


def test_chair_rollup_uses_chair_at_event_time(db, chair, other_chair, payer, global_admin):
    ga = factories.make_admin(db, role="chair", chairs=[chair], username="mover")
    pay(db, ga, payer, 1000)  # payment chair = CHA (payer's chair)
    remit(db, global_admin, ga, 300)  # remittance chair = CHA (ga's linked user)
    # the group admin's person moves to another chair later (after demotion)
    ga.active = False
    ga.user.chair_id = other_chair.id
    db.commit()
    other_payer = factories.make_user(db, "Other", chair=other_chair)
    ga2 = factories.make_admin(db, role="chair", chairs=[other_chair], username="resident")
    pay(db, ga2, other_payer, 50)
    remit(db, global_admin, ga, 200)  # now recorded under CHB
    roll = {r.chair_short_name: r for r in groups.chair_rollup(db)}
    assert (roll["CHA"].collected_cents, roll["CHA"].remitted_cents, roll["CHA"].held_cents) == (1000, 300, 700)
    assert (roll["CHB"].collected_cents, roll["CHB"].remitted_cents, roll["CHB"].held_cents) == (50, 200, -150)
    assert roll["CHB"].negative and not roll["CHA"].negative
    # per admin total is unaffected by the chair move
    assert groups.held(db, ga.id) == 500


def test_chair_rollup_excludes_non_group_collectors(db, chair, payer, global_admin):
    pay(db, global_admin, payer, 900)
    assert groups.chair_rollup(db) == []


def test_record_remittance_basic_and_audit(db, ga, global_admin, chair):
    r = remit(db, global_admin, ga, 1234, key="k1", note="  handed   over ")
    assert (r.group_admin_id, r.chair_id, r.amount_cents) == (ga.id, chair.id, 1234)
    assert r.recorded_by_admin_id == global_admin.id and r.note == "handed over"
    entry = db.scalars(select(AuditLog).where(AuditLog.action == "remittance.recorded")).one()
    assert entry.actor_id == str(global_admin.id) and entry.target_id == str(ga.id)
    assert entry.meta["amount_cents"] == 1234 and entry.meta["remittance_id"] == str(r.id)


def test_record_remittance_authorisation_and_targets(db, ga, chair_admin, global_admin, payer):
    with pytest.raises(Forbidden):
        groups.record_remittance(db, head_admin=chair_admin, group_admin_id=ga.id, amount_cents=100,
                                 idempotency_key="x")
    global_admin.active = False
    with pytest.raises(Forbidden):
        groups.record_remittance(db, head_admin=global_admin, group_admin_id=ga.id, amount_cents=100,
                                 idempotency_key="x")
    global_admin.active = True
    other_global = factories.make_admin(db, role="global")
    with pytest.raises(InvalidInput):
        groups.record_remittance(db, head_admin=global_admin, group_admin_id=other_global.id, amount_cents=1,
                                 idempotency_key="x")
    with pytest.raises(NotFound):
        groups.record_remittance(db, head_admin=global_admin, group_admin_id=uuid.uuid4(), amount_cents=1,
                                 idempotency_key="x")
    assert db.scalar(select(func.count()).select_from(GroupRemittance)) == 0


@pytest.mark.parametrize("amount", [0, True, 1.5, "10", 10**9])
def test_record_remittance_amount_validation(db, ga, global_admin, amount):
    with pytest.raises(InvalidAmount):
        groups.record_remittance(db, head_admin=global_admin, group_admin_id=ga.id, amount_cents=amount,
                                 idempotency_key="k")


@pytest.mark.parametrize("key", ["", "x" * 81, None])
def test_record_remittance_key_validation(db, ga, global_admin, key):
    with pytest.raises(InvalidInput):
        groups.record_remittance(db, head_admin=global_admin, group_admin_id=ga.id, amount_cents=5,
                                 idempotency_key=key)


def test_record_remittance_to_former_admin_allowed(db, ga, global_admin):
    ga.active = False
    db.commit()
    assert remit(db, global_admin, ga, 100).amount_cents == 100


def test_idempotency(db, ga, global_admin, chair):
    first = remit(db, global_admin, ga, 500, key="same")
    again = groups.record_remittance(db, head_admin=global_admin, group_admin_id=ga.id, amount_cents=500,
                                     idempotency_key="same", note="a different note is fine")
    assert again.id == first.id
    assert db.scalar(select(func.count()).select_from(GroupRemittance)) == 1
    assert db.scalar(select(func.count()).where(AuditLog.action == "remittance.recorded")) == 1
    with pytest.raises(Conflict):
        groups.record_remittance(db, head_admin=global_admin, group_admin_id=ga.id, amount_cents=501,
                                 idempotency_key="same")
    other = factories.make_admin(db, role="chair", chairs=[chair], username="ga2")
    with pytest.raises(Conflict):
        groups.record_remittance(db, head_admin=global_admin, group_admin_id=other.id, amount_cents=500,
                                 idempotency_key="same")


def test_correction_rules(db, ga, chair, global_admin):
    other = factories.make_admin(db, role="chair", chairs=[chair], username="ga2")
    r1 = remit(db, global_admin, ga, 500, key="r1")
    r_other = remit(db, global_admin, other, 100, key="ro")
    with pytest.raises(NotFound):
        groups.record_remittance(db, head_admin=global_admin, group_admin_id=ga.id, amount_cents=-500,
                                 idempotency_key="c0", correction_of_id=uuid.uuid4())
    with pytest.raises(Conflict):  # another group admin's entry
        groups.record_remittance(db, head_admin=global_admin, group_admin_id=ga.id, amount_cents=-100,
                                 idempotency_key="c1", correction_of_id=r_other.id)
    c = remit(db, global_admin, ga, -500, key="c2", correction_of_id=r1.id)
    assert c.correction_of_id == r1.id and groups.held(db, ga.id) == 0
    assert db.scalars(select(AuditLog).where(AuditLog.action == "remittance.corrected")).one().meta[
        "correction_of_id"] == str(r1.id)
    with pytest.raises(Conflict):  # at most one correction per entry
        groups.record_remittance(db, head_admin=global_admin, group_admin_id=ga.id, amount_cents=-1,
                                 idempotency_key="c3", correction_of_id=r1.id)
    with pytest.raises(Conflict):  # a correction cannot itself be corrected
        groups.record_remittance(db, head_admin=global_admin, group_admin_id=ga.id, amount_cents=500,
                                 idempotency_key="c4", correction_of_id=c.id)
    # retry of the first correction returns the same row
    assert remit(db, global_admin, ga, -500, key="c2", correction_of_id=r1.id).id == c.id
    with pytest.raises(Conflict):  # same key, different correction target
        groups.record_remittance(db, head_admin=global_admin, group_admin_id=ga.id, amount_cents=-500,
                                 idempotency_key="c2")


def test_correction_keeps_original_chair(db, chair, other_chair, global_admin):
    ga = factories.make_admin(db, role="chair", chairs=[chair], username="mv")
    r1 = remit(db, global_admin, ga, 500, key="r1")
    ga.active = False
    ga.user.chair_id = other_chair.id
    db.commit()
    c = remit(db, global_admin, ga, -500, key="c1", correction_of_id=r1.id)
    assert c.chair_id == chair.id
    assert {r.chair_id: r.remitted_cents for r in groups.chair_rollup(db)} == {chair.id: 0}


def test_services_do_not_commit(db, ga, global_admin, engine):
    from sqlalchemy.orm import Session

    db.commit()
    groups.record_remittance(db, head_admin=global_admin, group_admin_id=ga.id, amount_cents=10,
                             idempotency_key="nc")
    db.rollback()
    with Session(engine) as other:
        assert other.scalar(select(func.count()).select_from(GroupRemittance)) == 0
