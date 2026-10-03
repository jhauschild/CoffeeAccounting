"""ledger-audit: `check-ledger` must catch every corruption that can be injected with raw SQL.

Triggers/constraints/FKs are disabled only in the per-test scratch copy of the database.
Complements tests/test_core_checker_cli.py (different corruption kinds).
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import uuid
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from app.models import PaymentEvent
from app.services import ledger, users
from app.services.checker import check_ledger
from app.timeutil import utcnow
from tests import factories

ROOT = Path(__file__).resolve().parent.parent
TS = "%Y-%m-%d %H:%M:%S.%f"
NO_CHECKS = "PRAGMA ignore_check_constraints = ON"
NO_FK = "PRAGMA foreign_keys = OFF"


@pytest.fixture
def seed(db, chair, other_chair, global_admin):
    now = utcnow()
    p50 = factories.set_price(db, 50, effective_from=now - timedelta(days=5))
    alice = factories.make_user(db, "Alice", chair=chair)
    bob = factories.make_user(db, "Bob", chair=other_chair)
    carol = factories.make_user(db, "Carol", chair=chair)
    (single,) = factories.add_events(db, alice, ["single"], at=now - timedelta(days=4))
    p70 = factories.set_price(db, 70, effective_from=now - timedelta(days=3))
    (double,) = factories.add_events(db, bob, ["double"], at=now - timedelta(days=2))
    adj = ledger.add_adjustment(db, admin=global_admin, user_id=bob.id, quantity=1)
    pay = factories.make_payment(db, alice, global_admin, 1000)
    users.merge_users(db, admin=global_admin, duplicate_id=carol.id, target_id=alice.id)
    db.commit()
    assert check_ledger(db).ok
    return dict(now=now, p50=p50, p70=p70, alice=alice, bob=bob, carol=carol, single=single, double=double, adj=adj,
                pay=pay, admin=global_admin)


def raw(db_path, *statements):
    con = sqlite3.connect(db_path, isolation_level=None)
    try:
        for stmt in statements:
            con.execute(*stmt) if isinstance(stmt, tuple) else con.execute(stmt)
    finally:
        con.close()


def ev(s, **kw):
    row = dict(id=uuid.uuid4().hex, user_id=s["alice"].id.hex, chair_id=s["alice"].chair_id.hex, quantity=1,
               type="single", unit_price_cents=50, amount_cents=50, price_id=s["p50"].id.hex,
               idempotency_key=uuid.uuid4().hex, reversal_of_id=None, admin_id=None,
               created_at=(s["now"] - timedelta(days=4, hours=1)).strftime(TS))
    row.update(kw)
    return (f"INSERT INTO consumption_events ({', '.join(row)}) VALUES ({', '.join('?' * len(row))})",
            tuple(row.values()))


def pay(s, **kw):
    row = dict(id=uuid.uuid4().hex, user_id=s["alice"].id.hex, chair_id=s["alice"].chair_id.hex, amount_cents=100,
               admin_id=s["admin"].id.hex, correction_of_id=None, created_at=s["now"].strftime(TS))
    row.update(kw)
    return (f"INSERT INTO payment_events ({', '.join(row)}) VALUES ({', '.join('?' * len(row))})",
            tuple(row.values()))


def rev_of(s, original, **kw):
    base = dict(type="reversal", quantity=-original.quantity, amount_cents=-original.amount_cents,
                unit_price_cents=original.unit_price_cents, price_id=original.price_id.hex if original.price_id else None,
                reversal_of_id=original.id.hex, user_id=original.user_id.hex, chair_id=original.chair_id.hex,
                created_at=s["now"].strftime(TS))
    base.update(kw)
    return ev(s, **base)


CORRUPTIONS = {
    "no_price_at_time": lambda s: [ev(s, created_at="2000-01-01 00:00:00.000000")],
    "price_row_mismatch": lambda s: [  # the 70 price is silently backdated before Alice's coffee
        "DROP TRIGGER prices_no_update",
        ("UPDATE prices SET effective_from = ? WHERE id = ?",
         ((s["now"] - timedelta(days=4, hours=2)).strftime(TS), s["p70"].id.hex))],
    "orphan_price": lambda s: [NO_FK, ev(s, price_id=uuid.uuid4().hex)],
    "orphan_chair": lambda s: [NO_FK, ev(s, chair_id=uuid.uuid4().hex)],
    "event_type": lambda s: [NO_CHECKS, ev(s, type="bogus")],
    "sign_mismatch": lambda s: [NO_CHECKS, ev(s, type="adjustment", quantity=1, amount_cents=-5,
                                              admin_id=s["admin"].id.hex)],
    "adjustment_admin": lambda s: [NO_CHECKS, ev(s, type="adjustment", admin_id=None)],
    "unexpected_reversal_ref": lambda s: [NO_CHECKS, ev(s, reversal_of_id=s["double"].id.hex)],
    "zero_quantity": lambda s: [NO_CHECKS, ev(s, type="adjustment", quantity=0, amount_cents=0,
                                              admin_id=s["admin"].id.hex)],
    "zero_amount": lambda s: [NO_CHECKS, rev_of(s, s["single"], amount_cents=0)],
    "reversal_user": lambda s: [rev_of(s, s["single"], user_id=s["bob"].id.hex, chair_id=s["bob"].chair_id.hex)],
    "reversal_unit_price": lambda s: [rev_of(s, s["single"], unit_price_cents=70)],
    "reversal_quantity": lambda s: [NO_CHECKS, rev_of(s, s["single"], quantity=1, amount_cents=50)],
    "reversal_without_original": lambda s: [NO_CHECKS, ev(s, type="reversal", quantity=-1, amount_cents=-50)],
    "merge_state": lambda s: [NO_CHECKS, ("UPDATE users SET status = 'merged' WHERE id = ?", (s["bob"].id.hex,))],
    "merge_orphan": lambda s: [NO_FK, ("UPDATE users SET merged_into_id = ? WHERE id = ?",
                                       (uuid.uuid4().hex, s["carol"].id.hex))],
    "user_status": lambda s: [NO_CHECKS, ("UPDATE users SET status = 'zombie' WHERE id = ?", (s["bob"].id.hex,))],
    "zero_payment": lambda s: [NO_CHECKS, pay(s, amount_cents=0)],
    "orphan_correction": lambda s: [NO_FK, pay(s, correction_of_id=uuid.uuid4().hex)],
    "double_correction": lambda s: ["DROP INDEX uq_payment_events_correction_of_id",
                                    pay(s, amount_cents=-1000, correction_of_id=s["pay"].id.hex),
                                    pay(s, amount_cents=-1000, correction_of_id=s["pay"].id.hex)],
    "amount_mismatch": lambda s: [  # a recorded single silently re-priced to 1 cent
        "DROP TRIGGER consumption_events_no_update", NO_CHECKS,
        ("UPDATE consumption_events SET amount_cents = 1 WHERE id = ?", (s["single"].id.hex,))],
}


@pytest.mark.parametrize("code", sorted(CORRUPTIONS))
def test_check_ledger_detects_injected_corruption(db, db_path, seed, code):
    raw(db_path, *CORRUPTIONS[code](seed))
    db.rollback()  # new snapshot (WAL)
    found = {p.code for p in check_ledger(db).problems}
    assert code in found, found


def test_cli_exit_code_on_corruption(db_path, seed):
    raw(db_path, NO_CHECKS, pay(seed, amount_cents=0))
    env = dict(os.environ)
    result = subprocess.run([sys.executable, "-m", "app.cli", "check-ledger"], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=60)
    assert result.returncode != 0 and "zero_payment" in result.stdout + result.stderr


# ----- gaps: corruption that changes totals but is not reported --------------------------------
@pytest.mark.xfail(strict=True, reason="GAP(low): check-ledger does not compare a reversal's chair_id with the "
                                       "original's, so per-chair totals can silently stop netting out")
def test_reversal_with_different_chair_is_reported(db, db_path, seed):
    raw(db_path, rev_of(seed, seed["single"], chair_id=seed["bob"].chair_id.hex))
    db.rollback()  # new snapshot (WAL)
    assert not check_ledger(db).ok


@pytest.mark.xfail(strict=True, reason="GAP(low): check-ledger does not verify that a payment correction belongs "
                                       "to the same effective user as the corrected payment")
def test_correction_for_another_users_payment_is_reported(db, db_path, seed):
    raw(db_path, pay(seed, user_id=seed["bob"].id.hex, chair_id=seed["bob"].chair_id.hex, amount_cents=-1000,
                     correction_of_id=seed["pay"].id.hex))
    db.rollback()  # new snapshot (WAL)
    assert db.scalar(select(PaymentEvent.id).where(PaymentEvent.correction_of_id == seed["pay"].id)) is not None
    assert not check_ledger(db).ok
