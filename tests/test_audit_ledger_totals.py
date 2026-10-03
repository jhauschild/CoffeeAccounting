"""ledger-audit: totals, sign rules, large values, payment corrections under concurrency."""

from __future__ import annotations

import threading
import uuid

import pytest

from app.db import write_session
from app.models import AdminUser, PaymentEvent
from app.services import ledger
from app.services.checker import check_ledger
from app.services.errors import Conflict, InvalidAmount
from tests import factories
from tests.user_support import event_id_from, post_scan


def test_negative_payments_and_corrections_sum_with_signs(db, user, price, global_admin):
    factories.add_events(db, user, ["double", "double"])  # 200 consumed
    pay = factories.make_payment(db, user, global_admin, 1000)
    ledger.add_payment(db, admin=global_admin, user_id=user.id, amount_cents=-1000, correction_of_id=pay.id)
    refund = factories.make_payment(db, user, global_admin, -250)  # money paid back to the user
    corr = ledger.add_payment(db, admin=global_admin, user_id=user.id, amount_cents=250, correction_of_id=refund.id)
    # a correction can itself be corrected once (no rule forbids it); each payment at most once
    ledger.add_payment(db, admin=global_admin, user_id=user.id, amount_cents=-250, correction_of_id=corr.id)
    db.commit()
    t = ledger.get_totals(db, user.id)
    assert (t.consumed_amount_cents, t.paid_amount_cents, t.balance_cents) == (200, -250, 450)
    assert check_ledger(db).ok


@pytest.mark.parametrize("amount", [0, True, 1.5, "100", 10 ** 12])
def test_invalid_payment_amounts_rejected(db, user, global_admin, amount):
    with pytest.raises(InvalidAmount):
        ledger.add_payment(db, admin=global_admin, user_id=user.id, amount_cents=amount)


def test_concurrent_corrections_of_one_payment_record_one(db, user, global_admin):
    pay = factories.make_payment(db, user, global_admin, 700)

    def go():
        with write_session() as w:
            return ledger.add_payment(w, admin=w.get(AdminUser, global_admin.id), user_id=user.id,
                                      amount_cents=-700, correction_of_id=pay.id).id

    barrier = threading.Barrier(5)
    results, errors = [], []

    def worker():
        barrier.wait()
        try:
            results.append(go())
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert len(results) == 1 and all(isinstance(e, Conflict) for e in errors), errors
    db.expire_all()
    assert db.query(PaymentEvent).filter(PaymentEvent.correction_of_id == pay.id).count() == 1
    assert ledger.get_totals(db, user.id).paid_amount_cents == 0


def test_large_values_stay_exact(client, db, user, global_admin, login):
    factories.set_price(db, 100_00)  # max price per shot
    for _ in range(50):
        factories.make_payment(db, user, global_admin, ledger.MAX_AMOUNT_CENTS, commit=False)
    ledger.add_adjustment(db, admin=global_admin, user_id=user.id, quantity=ledger.MAX_ADJUSTMENT_SHOTS)
    ledger.add_adjustment(db, admin=global_admin, user_id=user.id, quantity=7,
                          amount_cents=ledger.MAX_AMOUNT_CENTS)
    db.commit()
    paid = 50 * ledger.MAX_AMOUNT_CENTS
    consumed = ledger.MAX_ADJUSTMENT_SHOTS * 100_00 + ledger.MAX_AMOUNT_CENTS
    t = ledger.get_totals(db, user.id)
    assert t == ledger.Totals(1007, consumed, paid, consumed - paid)
    assert all(isinstance(v, int) for v in (t.consumed_amount_cents, t.paid_amount_cents, t.balance_cents))
    login(user)
    page = client.get("/account")
    assert page.status_code == 200 and "48900000.00" in page.text  # credit shown exactly, no float artefacts


def test_credit_is_consumed_exactly_and_reversal_restores_it(client, db, user, global_admin, login):
    factories.set_price(db, 33)
    factories.make_payment(db, user, global_admin, 100)
    login(user)
    eid = event_id_from(post_scan(client, "double"))  # 66
    event_id_from(post_scan(client, "single"))  # 33 -> balance -1 (credit 0.01)
    db.expire_all()
    assert ledger.get_totals(db, user.id).balance_cents == -1
    ev = ledger.admin_reverse_event(db, admin=global_admin, event_id=uuid.UUID(eid))
    db.commit()
    assert ev.amount_cents == -66
    assert ledger.get_totals(db, user.id).balance_cents == -67
