"""v2 ledger: collector, bookkeeping payments, set_balance, month shots, own-balance rule."""

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy import func, select

from app.models import PaymentEvent
from app.services import ledger
from app.services import users as users_service
from app.services.errors import Conflict, Forbidden, InvalidAmount, InvalidInput
from app.timeutil import utcnow
from tests import factories


@pytest.fixture
def head(db):
    return factories.make_admin(db)


@pytest.fixture
def member(db):
    return factories.make_member(db)


@pytest.fixture
def old_price(db):
    # Effective far in the past so backdated test events find a price.
    return factories.set_price(db, 50, effective_from=datetime(2020, 1, 1, tzinfo=UTC))


def n_payments(db):
    return db.scalar(select(func.count()).select_from(PaymentEvent))


# ----- collector --------------------------------------------------------------------------
def test_cash_payment_sets_collector_to_recording_admin(db, head, member):
    p = ledger.add_payment(db, admin=head, user_id=member.id, amount_cents=500)
    assert (p.kind, p.collector_admin_id, p.admin_id) == ("cash", head.id, head.id)


def test_group_admin_cash_payment_collector_is_group_admin(db, member):
    ga = factories.make_admin(db, role="chair", chairs=[member.chair])
    p = ledger.add_payment(db, admin=ga, user_id=member.id, amount_cents=500)
    assert p.collector_admin_id == ga.id


def test_correction_copies_collector_even_when_head_records_it(db, head, member):
    ga = factories.make_admin(db, role="chair", chairs=[member.chair])
    orig = ledger.add_payment(db, admin=ga, user_id=member.id, amount_cents=500)
    corr = ledger.add_payment(db, admin=head, user_id=member.id, amount_cents=-500, correction_of_id=orig.id)
    assert corr.collector_admin_id == ga.id
    assert corr.admin_id == head.id
    assert corr.kind == "cash"


def test_correction_ignores_requested_kind(db, head, member):
    orig = ledger.add_payment(db, admin=head, user_id=member.id, amount_cents=500)
    corr = ledger.add_payment(db, admin=head, user_id=member.id, amount_cents=-500, correction_of_id=orig.id,
                              kind="bookkeeping")
    assert (corr.kind, corr.collector_admin_id) == ("cash", head.id)


def test_bookkeeping_never_sets_collector(db, head, member):
    p = ledger.add_payment(db, admin=head, user_id=member.id, amount_cents=500, kind="bookkeeping")
    assert (p.kind, p.collector_admin_id) == ("bookkeeping", None)
    corr = ledger.add_payment(db, admin=head, user_id=member.id, amount_cents=-500, correction_of_id=p.id)
    assert (corr.kind, corr.collector_admin_id) == ("bookkeeping", None)


def test_bookkeeping_requires_head_admin(db, member):
    ga = factories.make_admin(db, role="chair", chairs=[member.chair])
    with pytest.raises(Forbidden):
        ledger.add_payment(db, admin=ga, user_id=member.id, amount_cents=500, kind="bookkeeping")
    assert n_payments(db) == 0


def test_invalid_kind_rejected(db, head, member):
    with pytest.raises(InvalidInput):
        ledger.add_payment(db, admin=head, user_id=member.id, amount_cents=500, kind="gift")


# ----- idempotency ------------------------------------------------------------------------
def test_double_submit_books_once(db, head, member):
    a = ledger.add_payment(db, admin=head, user_id=member.id, amount_cents=500, idempotency_key="k1")
    db.commit()
    b = ledger.add_payment(db, admin=head, user_id=member.id, amount_cents=500, idempotency_key="k1")
    assert b.id == a.id
    assert n_payments(db) == 1
    assert db.scalar(select(func.sum(PaymentEvent.amount_cents))) == 500


def test_idempotent_retry_of_a_correction(db, head, member):
    orig = ledger.add_payment(db, admin=head, user_id=member.id, amount_cents=500)
    a = ledger.add_payment(db, admin=head, user_id=member.id, amount_cents=-500, correction_of_id=orig.id,
                           idempotency_key="c1")
    b = ledger.add_payment(db, admin=head, user_id=member.id, amount_cents=-500, correction_of_id=orig.id,
                           idempotency_key="c1")
    assert a.id == b.id and n_payments(db) == 2


def test_key_reused_for_other_payment_conflicts(db, head, member):
    other = factories.make_member(db)
    ledger.add_payment(db, admin=head, user_id=member.id, amount_cents=500, idempotency_key="k1")
    with pytest.raises(Conflict):
        ledger.add_payment(db, admin=head, user_id=other.id, amount_cents=500, idempotency_key="k1")
    with pytest.raises(Conflict):
        ledger.add_payment(db, admin=head, user_id=member.id, amount_cents=700, idempotency_key="k1")
    assert n_payments(db) == 1


def test_bad_idempotency_key_rejected(db, head, member):
    with pytest.raises(InvalidInput):
        ledger.add_payment(db, admin=head, user_id=member.id, amount_cents=500, idempotency_key="x" * 81)


# ----- set_balance ------------------------------------------------------------------------
def test_set_balance_up_and_down(db, head, member, old_price):
    factories.add_events(db, member, ["single", "double"])  # consumed 150
    assert ledger.get_totals(db, member.id).balance_cents == 150

    # Lower the debt to 40: books a payment of 110.
    p = ledger.set_balance(db, admin=head, user_id=member.id, target_balance_cents=40, idempotency_key="s1",
                           note="agreed")
    assert (p.kind, p.collector_admin_id, p.amount_cents, p.admin_id) == ("bookkeeping", None, 110, head.id)
    assert ledger.get_totals(db, member.id).balance_cents == 40

    # Raise to a credit of 25: payment of 40 - (-25) = 65.
    q = ledger.set_balance(db, admin=head, user_id=member.id, target_balance_cents=-25, idempotency_key="s2")
    assert q.amount_cents == 65
    assert ledger.get_totals(db, member.id).balance_cents == -25

    # Back up to owing 100: negative booking of -125.
    r = ledger.set_balance(db, admin=head, user_id=member.id, target_balance_cents=100, idempotency_key="s3")
    assert r.amount_cents == -125
    assert ledger.get_totals(db, member.id).balance_cents == 100
    assert n_payments(db) == 3  # append-only: three new rows, none edited


def test_set_balance_is_idempotent(db, head, member, old_price):
    factories.add_events(db, member, "single")
    a = ledger.set_balance(db, admin=head, user_id=member.id, target_balance_cents=0, idempotency_key="s1")
    b = ledger.set_balance(db, admin=head, user_id=member.id, target_balance_cents=0, idempotency_key="s1")
    assert a.id == b.id and n_payments(db) == 1
    assert ledger.get_totals(db, member.id).balance_cents == 0


def test_set_balance_zero_difference_raises(db, head, member, old_price):
    with pytest.raises(InvalidAmount):
        ledger.set_balance(db, admin=head, user_id=member.id, target_balance_cents=0, idempotency_key="s1")
    assert n_payments(db) == 0


def test_set_balance_head_only(db, member, old_price):
    ga = factories.make_admin(db, role="chair", chairs=[member.chair])
    with pytest.raises(Forbidden):
        ledger.set_balance(db, admin=ga, user_id=member.id, target_balance_cents=100, idempotency_key="s1")
    assert n_payments(db) == 0


def test_set_balance_validation(db, head, member, old_price):
    with pytest.raises(InvalidAmount):
        ledger.set_balance(db, admin=head, user_id=member.id, target_balance_cents=1.5, idempotency_key="s1")
    with pytest.raises(InvalidInput):
        ledger.set_balance(db, admin=head, user_id=member.id, target_balance_cents=10, idempotency_key="")


def test_set_balance_counts_merged_profiles(db, head, member, old_price):
    dup = factories.make_user(db, "Dup", chair=member.chair)
    factories.add_events(db, dup, "double")  # 100 on the duplicate
    users_service.merge_users(db, admin=head, duplicate_id=dup.id, target_id=member.id)
    db.commit()
    p = ledger.set_balance(db, admin=head, user_id=member.id, target_balance_cents=0, idempotency_key="s1")
    assert p.amount_cents == 100 and p.user_id == member.id
    assert ledger.get_totals(db, dup.id).balance_cents == 0


# ----- totals -----------------------------------------------------------------------------
def test_totals_count_both_payment_kinds(db, head, member, old_price):
    factories.add_events(db, member, ["double", "double"])  # 200
    ledger.add_payment(db, admin=head, user_id=member.id, amount_cents=60)
    ledger.add_payment(db, admin=head, user_id=member.id, amount_cents=40, kind="bookkeeping")
    t = ledger.get_totals(db, member.id)
    assert (t.paid_amount_cents, t.balance_cents) == (100, 100)
    assert len(ledger.recent_payments(db, member.id)) == 2


# ----- month shots ------------------------------------------------------------------------
def berlin(y, m, d, hh, mm):
    return datetime(y, m, d, hh, mm, tzinfo=ZoneInfo("Europe/Berlin")).astimezone(UTC)


def test_month_shots_basic_and_other_users_excluded(db, member, old_price):
    other = factories.make_member(db)
    now = berlin(2026, 5, 15, 12, 0)
    factories.add_events(db, member, ["single", "double"], at=berlin(2026, 5, 2, 9, 0))
    factories.add_events(db, other, "double", at=berlin(2026, 5, 2, 9, 0))
    factories.add_events(db, member, "single", at=berlin(2026, 4, 30, 9, 0))
    assert ledger.get_month_shots(db, member.id, now=now) == 3
    assert ledger.get_month_shots(db, other.id, now=now) == 2
    assert ledger.get_month_shots(db, member.id, now=berlin(2026, 6, 1, 0, 0)) == 0


def test_month_shots_default_now(db, member, old_price):
    local = utcnow().astimezone(ZoneInfo("Europe/Berlin"))
    if local.day == 1 and local.hour == 0:
        pytest.skip("too close to a month boundary")
    factories.add_events(db, member, "double", at=utcnow())
    assert ledger.get_month_shots(db, member.id) == 2


def test_month_shots_reversal_nets_out(db, head, member, old_price):
    ev = factories.add_events(db, member, ["double", "single"], at=berlin(2026, 5, 10, 9, 0))
    ledger.admin_reverse_event(db, admin=head, event_id=ev[0].id, now=berlin(2026, 5, 10, 10, 0))
    assert ledger.get_month_shots(db, member.id, now=berlin(2026, 5, 20, 0, 0)) == 1


def test_month_shots_includes_adjustments_and_merged_profiles(db, head, member, old_price):
    dup = factories.make_user(db, "Dup", chair=member.chair)
    factories.add_events(db, dup, "double", at=berlin(2026, 5, 3, 9, 0))
    ledger.add_adjustment(db, admin=head, user_id=dup.id, quantity=3, now=berlin(2026, 5, 4, 9, 0))
    users_service.merge_users(db, admin=head, duplicate_id=dup.id, target_id=member.id)
    now = berlin(2026, 5, 20, 0, 0)
    assert ledger.get_month_shots(db, member.id, now=now) == 5
    assert ledger.get_month_shots(db, dup.id, now=now) == 5


@pytest.mark.parametrize(
    "last_day, first_day",
    [
        ((2026, 1, 31), (2026, 2, 1)),    # plain winter month end
        ((2026, 3, 31), (2026, 4, 1)),    # month after DST start (CEST): 00:30 local is still Mar 31 in UTC
        ((2026, 10, 31), (2026, 11, 1)),  # month after DST end (CET)
        ((2026, 12, 31), (2027, 1, 1)),   # year boundary
    ],
)
def test_month_shots_local_month_boundary(db, member, old_price, last_day, first_day):
    late = berlin(*last_day, 23, 30)   # last local minutes of the month
    early = berlin(*first_day, 0, 30)  # first local minutes of the next month
    factories.add_events(db, member, "single", at=late)
    factories.add_events(db, member, "double", at=early)
    assert ledger.get_month_shots(db, member.id, now=late) == 1
    assert ledger.get_month_shots(db, member.id, now=early) == 2
    # "now" at the very start of the new month, and 29 minutes after `late`, stay in their month.
    assert ledger.get_month_shots(db, member.id, now=berlin(*first_day, 0, 0)) == 2
    assert ledger.get_month_shots(db, member.id, now=late + timedelta(minutes=29)) == 1


def test_month_shots_dst_month_includes_both_ends(db, member, old_price):
    # March 2026 has 743 local hours (DST starts on the 29th); both ends still count.
    factories.add_events(db, member, "single", at=berlin(2026, 3, 1, 0, 0))
    factories.add_events(db, member, "single", at=berlin(2026, 3, 31, 23, 59))
    factories.add_events(db, member, "single", at=berlin(2026, 2, 28, 23, 59))
    assert ledger.get_month_shots(db, member.id, now=berlin(2026, 3, 15, 12, 0)) == 2


# ----- own-balance rule -------------------------------------------------------------------
@pytest.fixture
def ga(db):
    return factories.make_admin(db, role="chair")


def test_group_admin_cannot_touch_own_account(db, ga, old_price):
    own = ga.user
    ev = factories.add_events(db, own, "single")[0]
    with pytest.raises(Forbidden):
        ledger.add_payment(db, admin=ga, user_id=own.id, amount_cents=100)
    with pytest.raises(Forbidden):
        ledger.add_adjustment(db, admin=ga, user_id=own.id, quantity=1)
    with pytest.raises(Forbidden):
        ledger.admin_reverse_event(db, admin=ga, event_id=ev.id)
    with pytest.raises(Forbidden):
        ledger.set_balance(db, admin=ga, user_id=own.id, target_balance_cents=0, idempotency_key="s1")
    assert n_payments(db) == 0


def test_group_admin_can_still_serve_other_members_of_group(db, ga, old_price):
    other = factories.make_member(db, chair=ga.user.chair)
    p = ledger.add_payment(db, admin=ga, user_id=other.id, amount_cents=100)
    assert p.collector_admin_id == ga.id
    ledger.add_adjustment(db, admin=ga, user_id=other.id, quantity=1)


def test_head_admin_may_act_on_own_linked_account(db, head, member, old_price):
    head.user_id = member.id
    db.commit()
    p = ledger.add_payment(db, admin=head, user_id=member.id, amount_cents=100)
    assert p.collector_admin_id == head.id
    ledger.add_adjustment(db, admin=head, user_id=member.id, quantity=1)
    ledger.set_balance(db, admin=head, user_id=member.id, target_balance_cents=0, idempotency_key="s1")
