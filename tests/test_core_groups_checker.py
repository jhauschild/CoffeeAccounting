"""check-ledger additions of task 1.4: collectors, remittance corrections, group balances."""

import sqlite3
import uuid

import pytest

from app import cli
from app.services import groups, ledger
from app.services.checker import check_ledger
from tests import factories

TS = "2026-01-01 00:00:00.000000"


def raw(db_path, *statements):
    con = sqlite3.connect(db_path, isolation_level=None)
    try:
        for stmt in statements:
            if isinstance(stmt, tuple):
                con.execute(*stmt)
            else:
                con.execute(stmt)
    finally:
        con.close()


def codes(db):
    db.expire_all()
    return {p.code for p in check_ledger(db).problems}


@pytest.fixture
def seeded(db, chair, other_chair, global_admin):
    factories.set_price(db, 50)
    ga = factories.make_admin(db, role="chair", chairs=[chair], username="ga1")
    ga2 = factories.make_admin(db, role="chair", chairs=[other_chair], username="ga2")
    alice = factories.make_user(db, "Alice", chair=chair)
    bob = factories.make_user(db, "Bob", chair=other_chair)
    cash = ledger.add_payment(db, admin=ga, user_id=alice.id, amount_cents=1000)
    corr = ledger.add_payment(db, admin=global_admin, user_id=alice.id, amount_cents=-300, correction_of_id=cash.id)
    cash2 = ledger.add_payment(db, admin=ga2, user_id=bob.id, amount_cents=400)
    book = ledger.add_payment(db, admin=global_admin, user_id=alice.id, amount_cents=250, kind="bookkeeping")
    r1 = groups.record_remittance(db, head_admin=global_admin, group_admin_id=ga.id, amount_cents=500,
                                  idempotency_key="r1")
    c1 = groups.record_remittance(db, head_admin=global_admin, group_admin_id=ga.id, amount_cents=-500,
                                  idempotency_key="c1", correction_of_id=r1.id)
    r2 = groups.record_remittance(db, head_admin=global_admin, group_admin_id=ga.id, amount_cents=200,
                                  idempotency_key="r2")
    db.commit()
    return dict(ga=ga, ga2=ga2, global_admin=global_admin, chair=chair, other_chair=other_chair, alice=alice,
                cash=cash, corr=corr, cash2=cash2, book=book, r1=r1, c1=c1, r2=r2)


def _rem_insert(s, **kw):
    row = dict(id=uuid.uuid4().hex, group_admin_id=s["ga"].id.hex, chair_id=s["chair"].id.hex, amount_cents=10,
               recorded_by_admin_id=s["global_admin"].id.hex, correction_of_id=None,
               idempotency_key=uuid.uuid4().hex, note=None, created_at=TS)
    row.update(kw)
    cols = ", ".join(row)
    return (f"INSERT INTO group_remittances ({cols}) VALUES ({', '.join('?' * len(row))})", tuple(row.values()))


UNLOCK = "DROP TRIGGER payment_events_no_update"

CORRUPTIONS = {
    "cash_without_collector": lambda s: [
        UNLOCK, ("UPDATE payment_events SET collector_admin_id = NULL WHERE id = ?", (s["cash2"].id.hex,))],
    "bookkeeping_with_collector": lambda s: [
        UNLOCK, ("UPDATE payment_events SET collector_admin_id = ? WHERE id = ?",
                 (s["ga"].id.hex, s["book"].id.hex))],
    "correction_collector": lambda s: [
        UNLOCK, ("UPDATE payment_events SET collector_admin_id = ? WHERE id = ?",
                 (s["global_admin"].id.hex, s["corr"].id.hex))],
    "correction_kind": lambda s: [
        UNLOCK, ("UPDATE payment_events SET kind = 'bookkeeping', collector_admin_id = ? WHERE id = ?",
                 (s["ga"].id.hex, s["corr"].id.hex))],
    "orphan_collector": lambda s: [
        "PRAGMA foreign_keys = OFF", UNLOCK,
        ("UPDATE payment_events SET collector_admin_id = ? WHERE id = ?", (uuid.uuid4().hex, s["cash2"].id.hex))],
    "payment_kind": lambda s: [
        "PRAGMA ignore_check_constraints = ON", UNLOCK,
        ("UPDATE payment_events SET kind = 'gift' WHERE id = ?", (s["cash2"].id.hex,))],
    "remittance_admin": lambda s: [
        "PRAGMA foreign_keys = OFF", _rem_insert(s, group_admin_id=uuid.uuid4().hex)],
    "remittance_admin_role": lambda s: [_rem_insert(s, group_admin_id=s["global_admin"].id.hex)],
    "remittance_recorder": lambda s: [_rem_insert(s, recorded_by_admin_id=s["ga2"].id.hex)],
    "zero_remittance": lambda s: ["PRAGMA ignore_check_constraints = ON", _rem_insert(s, amount_cents=0)],
    "remittance_correction_orphan": lambda s: [
        "PRAGMA foreign_keys = OFF", _rem_insert(s, correction_of_id=uuid.uuid4().hex)],
    "remittance_correction_admin": lambda s: [
        _rem_insert(s, group_admin_id=s["ga2"].id.hex, correction_of_id=s["r2"].id.hex)],
    "remittance_correction_of_correction": lambda s: [_rem_insert(s, correction_of_id=s["c1"].id.hex)],
    "double_remittance_correction": lambda s: [
        "DROP INDEX uq_group_remittances_correction_of_id", _rem_insert(s, correction_of_id=s["r1"].id.hex)],
    "remittance_correction_self": lambda s: [
        "PRAGMA ignore_check_constraints = ON",
        _rem_insert(s, id="0" * 32, correction_of_id="0" * 32)],
}


def test_clean_seed_passes_and_balances_are_right(db, seeded, capsys):
    report = check_ledger(db)
    assert report.ok, report.problems
    assert report.notes == [] and report.remittances == 3
    assert groups.collected(db, seeded["ga"].id) == 700 and groups.held(db, seeded["ga"].id) == 500
    assert groups.collected(db, seeded["ga2"].id) == 400
    assert cli.main(["check-ledger"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("OK:") and "NOTE" not in out


@pytest.mark.parametrize("code", sorted(CORRUPTIONS))
def test_check_ledger_detects_seeded_corruption(db, db_path, seeded, code, capsys):
    raw(db_path, *CORRUPTIONS[code](seeded))
    assert code in codes(db)
    assert cli.main(["check-ledger"]) == 1
    out = capsys.readouterr()
    assert f"[{code}]" in out.out and "FAILED" in out.err


def test_group_balance_mismatch_detected(db, seeded, monkeypatch):
    real = groups.collected
    monkeypatch.setattr(groups, "collected", lambda d, aid: real(d, aid) + 1)
    assert "group_balance_mismatch" in codes(db)


def test_chair_rollup_mismatch_detected(db, seeded, monkeypatch):
    real = groups.chair_rollup
    monkeypatch.setattr(groups, "chair_rollup", lambda d: real(d)[1:])
    found = [p for p in check_ledger(db).problems if p.code == "group_balance_mismatch"]
    assert found and "chair" in found[0].message


def test_correct_rows_do_not_trip_the_new_checks(db, seeded):
    # kind=cash with a collector who is a head admin, and a bookkeeping row, are both fine
    ledger.add_payment(db, admin=seeded["global_admin"], user_id=seeded["alice"].id, amount_cents=50)
    db.commit()
    assert check_ledger(db).ok


def test_negative_group_balance_is_a_note_not_a_failure(db, seeded, capsys):
    groups.record_remittance(db, head_admin=seeded["global_admin"], group_admin_id=seeded["ga2"].id,
                             amount_cents=900, idempotency_key="big")
    db.commit()
    report = check_ledger(db)
    assert report.ok and report.problems == []
    assert any("ga2" in n for n in report.notes) and any("chair" in n for n in report.notes)
    assert cli.main(["check-ledger"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("OK:") and "NOTE group admin ga2 has handed over 500 cents more" in out


def test_former_group_admin_holding_money_is_a_note(db, seeded):
    seeded["ga2"].active = False
    db.commit()
    report = check_ledger(db)
    assert report.ok
    assert any("former group admin ga2 still holds 400" in n for n in report.notes)
