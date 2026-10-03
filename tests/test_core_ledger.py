"""Ledger behaviour: idempotency, undo, admin actions, scope checks, totals."""

import threading
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from app.db import write_session
from app.models import AuditLog, ConsumptionEvent, PaymentEvent
from app.services import ledger
from app.services.errors import (
    AlreadyReversed,
    Conflict,
    Forbidden,
    InvalidAmount,
    InvalidInput,
    NoPriceConfigured,
    NotFound,
    RateLimited,
    UndoNotAllowed,
    UserInactive,
)
from app.timeutil import utcnow
from tests import factories
from tests.conftest import reload_settings


def count(db, model=ConsumptionEvent):
    return db.scalar(select(func.count()).select_from(model))


def run_threads(n, fn):
    barrier = threading.Barrier(n)
    results, errors = [], []

    def worker():
        barrier.wait()
        try:
            results.append(fn())
        except Exception as exc:  # noqa: BLE001 - collected for assertions
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    return results, errors


# ----- recording -----------------------------------------------------------------------------
def test_single_and_double_snapshot(db, user, price):
    s = ledger.record_coffee(db, user_id=user.id, kind="single", nonce="n1").event
    d = ledger.record_coffee(db, user_id=user.id, kind="double", nonce="n2").event
    assert (s.type, s.quantity, s.amount_cents, s.chair_id) == ("single", 1, 50, user.chair_id)
    assert (d.type, d.quantity, d.amount_cents, d.price_id) == ("double", 2, 100, price.id)


def test_invalid_kind_and_nonce(db, user, price):
    with pytest.raises(InvalidInput):
        ledger.record_coffee(db, user_id=user.id, kind="reversal", nonce="n")
    with pytest.raises(InvalidInput):
        ledger.record_coffee(db, user_id=user.id, kind="single", nonce="")


def test_same_nonce_returns_existing_event_even_for_other_user(db, user, price, chair):
    other = factories.make_user(db, "Bob", chair=chair)
    first = ledger.record_coffee(db, user_id=user.id, kind="single", nonce="same")
    again = ledger.record_coffee(db, user_id=user.id, kind="single", nonce="same")
    replay = ledger.record_coffee(db, user_id=other.id, kind="double", nonce="same")
    assert first.created and not again.created and not replay.created
    assert again.event.id == replay.event.id == first.event.id
    assert replay.event.user_id == user.id
    assert count(db) == 1


def test_unique_violation_fallback_returns_existing(db, user, price, monkeypatch):
    """If another transaction inserted the nonce after our lookup, the savepoint catches it."""
    existing = ledger.record_coffee(db, user_id=user.id, kind="single", nonce="race").event
    real = ledger._event_by_key
    calls = []

    def first_miss(session, key):
        calls.append(key)
        return None if len(calls) == 1 else real(session, key)

    monkeypatch.setattr(ledger, "_event_by_key", first_miss)
    result = ledger.record_coffee(db, user_id=user.id, kind="single", nonce="race")
    assert not result.created and result.event.id == existing.id and count(db) == 1


def test_concurrent_same_nonce_creates_one_event(db, user, price):
    def go():
        with write_session() as s:
            r = ledger.record_coffee(s, user_id=user.id, kind="double", nonce="concurrent")
            return r.created, r.event.id

    results, errors = run_threads(8, go)
    assert not errors
    assert sum(created for created, _ in results) == 1
    assert len({eid for _, eid in results}) == 1
    assert count(db) == 1


def test_two_scans_two_events(db, user, price):
    factories.add_events(db, user, ["single", "single"])
    assert count(db) == 2


def test_inactive_and_merged_users_cannot_record(db, user, price, chair):
    user.status = "inactive"
    db.commit()
    with pytest.raises(UserInactive):
        ledger.record_coffee(db, user_id=user.id, kind="single", nonce="x")
    target = factories.make_user(db, "Target", chair=chair)
    user.status, user.merged_into_id = "merged", target.id
    db.commit()
    with pytest.raises(UserInactive):
        ledger.record_coffee(db, user_id=user.id, kind="single", nonce="y")
    with pytest.raises(NotFound):
        ledger.record_coffee(db, user_id=uuid.uuid4(), kind="single", nonce="z")
    assert count(db) == 0


def test_deactivated_between_page_load_and_post(db, user, price, global_admin):
    from app.services.users import set_user_status

    with write_session() as s:
        set_user_status(s, admin=s.get(type(global_admin), global_admin.id), user_id=user.id, active=False)
    with pytest.raises(UserInactive):
        with write_session() as s:
            ledger.record_coffee(s, user_id=user.id, kind="single", nonce="late")
    assert count(db) == 0


def test_per_session_hourly_cap(db, user, price, monkeypatch):
    monkeypatch.setenv("MAX_COFFEES_PER_SESSION_PER_HOUR", "2")
    reload_settings()
    sid, now = uuid.uuid4(), utcnow()
    factories.add_events(db, user, ["single", "double"], at=now - timedelta(minutes=30), session_id=sid)
    with pytest.raises(RateLimited):
        ledger.record_coffee(db, user_id=user.id, kind="single", nonce="third", session_id=sid, now=now)
    ledger.record_coffee(db, user_id=user.id, kind="single", nonce="other", session_id=uuid.uuid4(), now=now)
    later = now + timedelta(minutes=31)
    assert ledger.record_coffee(db, user_id=user.id, kind="single", nonce="later", session_id=sid, now=later).created


# ----- undo ----------------------------------------------------------------------------------
@pytest.fixture
def scanned(db, user, price):
    sid, t0 = uuid.uuid4(), utcnow()
    event = ledger.record_coffee(db, user_id=user.id, kind="double", nonce="u1", session_id=sid, now=t0).event
    db.commit()
    return event, sid, t0


def test_undo_within_window(db, user, scanned, global_admin):
    event, sid, t0 = scanned
    factories.set_price(db, 90, effective_from=t0 + timedelta(seconds=1))  # undo ignores the current price
    assert ledger.latest_undoable_event(db, user_id=user.id, session_id=sid, now=t0).id == event.id
    rev = ledger.undo_coffee(db, user_id=user.id, session_id=sid, event_id=event.id, now=t0 + timedelta(seconds=299))
    assert (rev.type, rev.quantity, rev.unit_price_cents, rev.amount_cents) == ("reversal", -2, 50, -100)
    assert rev.reversal_of_id == event.id and rev.session_id == sid and rev.chair_id == event.chair_id
    assert ledger.latest_undoable_event(db, user_id=user.id, session_id=sid, now=t0) is None
    assert ledger.get_totals(db, user.id).consumed_shots == 0
    with pytest.raises(AlreadyReversed):
        ledger.undo_coffee(db, user_id=user.id, session_id=sid, event_id=event.id, now=t0)
    with pytest.raises(UndoNotAllowed):  # a reversal is never undoable
        ledger.undo_coffee(db, user_id=user.id, session_id=sid, event_id=rev.id, now=t0)
    with pytest.raises(Conflict):
        ledger.admin_reverse_event(db, admin=global_admin, event_id=rev.id)


def test_undo_after_window_expired(db, user, scanned):
    event, sid, t0 = scanned
    late = t0 + timedelta(seconds=301)
    assert ledger.latest_undoable_event(db, user_id=user.id, session_id=sid, now=late) is None
    with pytest.raises(UndoNotAllowed):
        ledger.undo_coffee(db, user_id=user.id, session_id=sid, event_id=event.id, now=late)


def test_undo_requires_same_user_and_session(db, user, scanned, chair):
    event, sid, t0 = scanned
    other = factories.make_user(db, "Mallory", chair=chair)
    for uid, s in ((other.id, sid), (user.id, uuid.uuid4()), (user.id, None)):
        with pytest.raises(UndoNotAllowed):
            ledger.undo_coffee(db, user_id=uid, session_id=s, event_id=event.id, now=t0)
    with pytest.raises(NotFound):
        ledger.undo_coffee(db, user_id=user.id, session_id=sid, event_id=uuid.uuid4(), now=t0)
    assert ledger.latest_undoable_event(db, user_id=other.id, session_id=sid, now=t0) is None


def test_only_most_recent_coffee_is_undoable(db, user, scanned):
    event, sid, t0 = scanned
    newer = ledger.record_coffee(db, user_id=user.id, kind="single", nonce="u2", session_id=sid,
                                 now=t0 + timedelta(seconds=5)).event
    with pytest.raises(UndoNotAllowed):
        ledger.undo_coffee(db, user_id=user.id, session_id=sid, event_id=event.id, now=t0 + timedelta(seconds=6))
    ledger.undo_coffee(db, user_id=user.id, session_id=sid, event_id=newer.id, now=t0 + timedelta(seconds=6))
    # After undoing the newest, the older one does not become undoable.
    assert ledger.latest_undoable_event(db, user_id=user.id, session_id=sid, now=t0 + timedelta(seconds=7)) is None


def test_inactive_user_cannot_undo(db, user, scanned):
    event, sid, t0 = scanned
    user.status = "inactive"
    db.commit()
    with pytest.raises(UserInactive):
        ledger.undo_coffee(db, user_id=user.id, session_id=sid, event_id=event.id, now=t0)


def test_concurrent_undos_produce_one_reversal(db, user, scanned):
    event, sid, t0 = scanned

    def go():
        with write_session() as s:
            return ledger.undo_coffee(s, user_id=user.id, session_id=sid, event_id=event.id, now=t0).id

    results, errors = run_threads(6, go)
    assert len(results) == 1
    assert errors and all(isinstance(e, AlreadyReversed) for e in errors)
    assert db.scalar(select(func.count()).where(ConsumptionEvent.reversal_of_id == event.id)) == 1


def test_concurrent_admin_reversals_produce_one_reversal(db, user, scanned, global_admin):
    event, _, _ = scanned
    from app.models import AdminUser

    def go():
        with write_session() as s:
            return ledger.admin_reverse_event(s, admin=s.get(AdminUser, global_admin.id), event_id=event.id).id

    results, errors = run_threads(6, go)
    assert len(results) == 1 and all(isinstance(e, AlreadyReversed) for e in errors)


# ----- admin actions and scope -------------------------------------------------------------
def test_admin_reverse_audited_and_once(db, user, scanned, chair_admin):
    event, _, _ = scanned
    rev = ledger.admin_reverse_event(db, admin=chair_admin, event_id=event.id, note="wrong button")
    assert rev.admin_id == chair_admin.id and rev.note == "wrong button" and rev.amount_cents == -100
    with pytest.raises(AlreadyReversed):
        ledger.admin_reverse_event(db, admin=chair_admin, event_id=event.id)
    entry = db.scalars(select(AuditLog).where(AuditLog.action == "event.reversed")).one()
    assert entry.target_id == str(event.id) and entry.actor_id == str(chair_admin.id)


def test_adjustment_prefill_and_override(db, user, price, global_admin):
    assert ledger.adjustment_default_amount(db, 3) == 150
    a = ledger.add_adjustment(db, admin=global_admin, user_id=user.id, quantity=3, note="missed scans")
    assert (a.type, a.quantity, a.amount_cents, a.unit_price_cents) == ("adjustment", 3, 150, 50)
    b = ledger.add_adjustment(db, admin=global_admin, user_id=user.id, quantity=2, amount_cents=0)
    c = ledger.add_adjustment(db, admin=global_admin, user_id=user.id, quantity=-1, amount_cents=-40)
    assert (b.amount_cents, c.amount_cents) == (0, -40)
    with pytest.raises(InvalidAmount):
        ledger.add_adjustment(db, admin=global_admin, user_id=user.id, quantity=1, amount_cents=-1)
    with pytest.raises(InvalidAmount):
        ledger.add_adjustment(db, admin=global_admin, user_id=user.id, quantity=0)
    assert db.scalar(select(func.count()).where(AuditLog.action == "event.adjustment")) == 3
    rev = ledger.admin_reverse_event(db, admin=global_admin, event_id=a.id)
    assert (rev.quantity, rev.amount_cents) == (-3, -150)


def test_adjustment_without_price_needs_explicit_amount(db, user, global_admin):
    with pytest.raises(NoPriceConfigured):
        ledger.add_adjustment(db, admin=global_admin, user_id=user.id, quantity=1)
    a = ledger.add_adjustment(db, admin=global_admin, user_id=user.id, quantity=1, amount_cents=60)
    assert (a.unit_price_cents, a.price_id) == (0, None)


def test_payment_and_correction(db, user, global_admin):
    p = ledger.add_payment(db, admin=global_admin, user_id=user.id, amount_cents=1000, note="cash")
    corr = ledger.add_payment(db, admin=global_admin, user_id=user.id, amount_cents=-1000, correction_of_id=p.id)
    assert corr.correction_of_id == p.id and corr.chair_id == user.chair_id
    with pytest.raises(Conflict):
        ledger.add_payment(db, admin=global_admin, user_id=user.id, amount_cents=-1000, correction_of_id=p.id)
    with pytest.raises(InvalidAmount):
        ledger.add_payment(db, admin=global_admin, user_id=user.id, amount_cents=0)
    with pytest.raises(InvalidAmount):
        ledger.add_payment(db, admin=global_admin, user_id=user.id, amount_cents=12.5)
    with pytest.raises(NotFound):
        ledger.add_payment(db, admin=global_admin, user_id=user.id, amount_cents=5, correction_of_id=uuid.uuid4())
    actions = db.scalars(select(AuditLog.action).where(AuditLog.target_id == str(user.id))).all()
    assert actions == ["payment.recorded", "payment.corrected"]
    assert ledger.get_totals(db, user.id).paid_amount_cents == 0


def test_correction_must_belong_to_same_user(db, user, chair, global_admin):
    other = factories.make_user(db, "Other", chair=chair)
    p = ledger.add_payment(db, admin=global_admin, user_id=other.id, amount_cents=500)
    with pytest.raises(Conflict):
        ledger.add_payment(db, admin=global_admin, user_id=user.id, amount_cents=-500, correction_of_id=p.id)


def test_chair_admin_scope(db, user, price, chair_admin, other_chair, global_admin):
    outsider = factories.make_user(db, "Outsider", chair=other_chair)
    ev = factories.add_events(db, outsider, "single")[0]
    ledger.add_payment(db, admin=chair_admin, user_id=user.id, amount_cents=100)
    ledger.add_adjustment(db, admin=chair_admin, user_id=user.id, quantity=1)
    calls = [
        lambda: ledger.add_payment(db, admin=chair_admin, user_id=outsider.id, amount_cents=100),
        lambda: ledger.add_adjustment(db, admin=chair_admin, user_id=outsider.id, quantity=1),
        lambda: ledger.admin_reverse_event(db, admin=chair_admin, event_id=ev.id),
    ]
    for call in calls:
        with pytest.raises(Forbidden):
            call()
    chair_admin.active = False
    with pytest.raises(Forbidden):
        ledger.add_payment(db, admin=chair_admin, user_id=user.id, amount_cents=100)
    ledger.add_payment(db, admin=global_admin, user_id=outsider.id, amount_cents=100)


def test_admin_actions_on_merged_profile_rejected(db, user, chair, price, global_admin):
    target = factories.make_user(db, "Target", chair=chair)
    user.status, user.merged_into_id = "merged", target.id
    db.flush()
    with pytest.raises(Conflict):
        ledger.add_payment(db, admin=global_admin, user_id=user.id, amount_cents=100)
    with pytest.raises(Conflict):
        ledger.add_adjustment(db, admin=global_admin, user_id=user.id, quantity=1)


# ----- totals --------------------------------------------------------------------------------
def test_totals_with_credit_consumed_at_later_prices(db, user, global_admin):
    now = utcnow()
    factories.set_price(db, 50, effective_from=now - timedelta(days=10))
    factories.make_payment(db, user, global_admin, 500, at=now - timedelta(days=9))
    assert ledger.get_totals(db, user.id) == ledger.Totals(0, 0, 500, -500)  # credit
    factories.add_events(db, user, ["double"], at=now - timedelta(days=8))
    factories.set_price(db, 80, effective_from=now - timedelta(days=5))
    factories.add_events(db, user, ["single", "double"], at=now - timedelta(days=4))
    t = ledger.get_totals(db, user.id)
    assert t == ledger.Totals(consumed_shots=5, consumed_amount_cents=100 + 80 + 160, paid_amount_cents=500,
                              balance_cents=340 - 500)
    rev_target = ledger.recent_consumption(db, user.id, limit=1)[0]
    ledger.admin_reverse_event(db, admin=global_admin, event_id=rev_target.id)
    t2 = ledger.get_totals(db, user.id)
    assert (t2.consumed_shots, t2.consumed_amount_cents, t2.balance_cents) == (3, 180, -320)
    assert len(ledger.recent_consumption(db, user.id)) == 4
    assert len(ledger.recent_payments(db, user.id)) == 1


def test_totals_for_unknown_user_are_zero(db):
    assert ledger.get_totals(db, uuid.uuid4()) == ledger.Totals(0, 0, 0, 0)


def test_reversed_ids_helper(db, user, scanned, global_admin):
    event, _, _ = scanned
    assert ledger.reversed_ids(db, [event.id]) == set() and ledger.reversed_ids(db, []) == set()
    ledger.admin_reverse_event(db, admin=global_admin, event_id=event.id)
    assert ledger.reversed_ids(db, [event.id]) == {event.id} and ledger.is_reversed(db, event.id)
    assert count(db, PaymentEvent) == 0
