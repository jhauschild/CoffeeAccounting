"""Price history: snapshot at insert time, changes, future dating, backdating, no price."""

from datetime import timedelta

import pytest
from sqlalchemy import func, select

from app.models import AuditLog, ConsumptionEvent, Price
from app.services import ledger, prices
from app.services.errors import Conflict, Forbidden, InvalidAmount, InvalidInput, NoPriceConfigured
from app.timeutil import utcnow
from tests import factories


def test_event_uses_price_in_effect_and_later_change_leaves_it_untouched(db, user, global_admin):
    now = utcnow()
    factories.set_price(db, 50, effective_from=now - timedelta(days=2))
    first = ledger.record_coffee(db, user_id=user.id, kind="double", nonce="n1", now=now - timedelta(days=1)).event
    assert (first.quantity, first.unit_price_cents, first.amount_cents) == (2, 50, 100)
    new_price = prices.add_price(db, price_per_shot_cents=70, admin_id=global_admin.id, now=now)
    second = ledger.record_coffee(db, user_id=user.id, kind="single", nonce="n2", now=now + timedelta(seconds=1)).event
    db.commit()
    assert (second.unit_price_cents, second.amount_cents, second.price_id) == (70, 70, new_price.id)
    db.expire_all()
    first = db.get(ConsumptionEvent, first.id)
    assert (first.unit_price_cents, first.amount_cents) == (50, 100)


def test_future_dated_price_takes_effect_only_at_effective_from(db, user, price, global_admin):
    now = utcnow()
    start = now + timedelta(hours=2)
    future = prices.add_price(db, price_per_shot_cents=80, effective_from=start, admin_id=global_admin.id, now=now)
    assert prices.get_price_in_effect(db, now).id == price.id
    assert prices.get_price_in_effect(db, start - timedelta(microseconds=1)).id == price.id
    assert prices.get_price_in_effect(db, start).id == future.id
    early = ledger.record_coffee(db, user_id=user.id, kind="single", nonce="a", now=start - timedelta(minutes=1))
    late = ledger.record_coffee(db, user_id=user.id, kind="single", nonce="b", now=start)
    assert (early.event.amount_cents, late.event.amount_cents) == (50, 80)
    assert [p.id for p in prices.list_prices(db)] == [future.id, price.id]


def test_backdated_price_rejected(db, global_admin):
    now = utcnow()
    with pytest.raises(InvalidInput):
        prices.add_price(db, price_per_shot_cents=10, effective_from=now - timedelta(seconds=1),
                         admin_id=global_admin.id, now=now)
    with pytest.raises(InvalidInput):  # naive datetimes are rejected
        prices.add_price(db, price_per_shot_cents=10, effective_from=now.replace(tzinfo=None),
                         admin_id=global_admin.id, now=now)


@pytest.mark.parametrize("cents", [-1, 1.5, True, "50", 100_01])
def test_invalid_price_values(db, global_admin, cents):
    with pytest.raises(InvalidAmount):
        prices.add_price(db, price_per_shot_cents=cents, admin_id=global_admin.id)


def test_duplicate_effective_from_conflicts(db, global_admin):
    now = utcnow()
    prices.add_price(db, price_per_shot_cents=10, effective_from=now, admin_id=global_admin.id, now=now)
    with pytest.raises(Conflict):
        prices.add_price(db, price_per_shot_cents=20, effective_from=now, admin_id=global_admin.id, now=now)


def test_no_price_configured_records_nothing(db, user):
    with pytest.raises(NoPriceConfigured):
        ledger.record_coffee(db, user_id=user.id, kind="single", nonce="x")
    # A price that only starts in the future does not count either.
    factories.set_price(db, 50, effective_from=utcnow() + timedelta(hours=1))
    with pytest.raises(NoPriceConfigured):
        ledger.record_coffee(db, user_id=user.id, kind="double", nonce="y")
    assert db.scalar(select(func.count()).select_from(ConsumptionEvent)) == 0


def test_price_changes_are_global_only_and_audited(db, chair_admin, global_admin):
    with pytest.raises(Forbidden):
        prices.add_price(db, price_per_shot_cents=10, admin_id=chair_admin.id)
    global_admin.active = False
    db.flush()
    with pytest.raises(Forbidden):
        prices.add_price(db, price_per_shot_cents=10, admin_id=global_admin.id)
    global_admin.active = True
    p = prices.add_price(db, price_per_shot_cents=10, admin_id=global_admin.id, note="  new   beans ")
    assert p.note == "new beans" and p.created_by_admin_id == global_admin.id
    entry = db.scalars(select(AuditLog).where(AuditLog.action == "price.added")).one()
    assert (entry.actor_type, entry.actor_id, entry.target_id) == ("admin", str(global_admin.id), str(p.id))
    assert entry.meta["price_per_shot_cents"] == 10


def test_cli_price_is_system_actor(db):
    p = prices.add_price(db, price_per_shot_cents=40, admin_id=None)
    entry = db.scalars(select(AuditLog).where(AuditLog.action == "price.added")).one()
    assert entry.actor_type == "system" and p.created_by_admin_id is None


def test_reversal_after_price_change_returns_original_amount(db, user, price, global_admin):
    now = utcnow()
    orig = ledger.record_coffee(db, user_id=user.id, kind="double", nonce="d", session_id=None,
                                now=now - timedelta(minutes=10)).event
    prices.add_price(db, price_per_shot_cents=99, admin_id=global_admin.id, now=now - timedelta(minutes=5))
    rev = ledger.admin_reverse_event(db, admin=global_admin, event_id=orig.id, now=now)
    assert (rev.quantity, rev.unit_price_cents, rev.amount_cents) == (-2, 50, -100)
    assert db.scalars(select(Price)).all()  # price rows untouched
