"""ledger-audit: merges never touch ledger rows; totals follow the effective user everywhere."""

from __future__ import annotations

import hashlib
import sqlite3
import threading

import pytest

from app.db import write_session
from app.models import AdminUser, User
from app.services import ledger, users
from app.services.checker import check_ledger
from app.services.errors import Conflict, UserInactive
from app.web import deps
from tests import factories
from tests.user_support import events, post_scan


def table_digest(db_path, table):
    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(f"SELECT * FROM {table} ORDER BY id").fetchall()  # noqa: S608 - fixed table names
    finally:
        con.close()
    return hashlib.sha256(repr(rows).encode()).hexdigest(), len(rows)


def ledger_digest(db_path):
    return {t: table_digest(db_path, t) for t in ("consumption_events", "payment_events", "prices")}


def run_threads(fns):
    barrier = threading.Barrier(len(fns))
    results, errors = [], []

    def worker(fn):
        barrier.wait()
        try:
            results.append(fn())
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(fn,)) for fn in fns]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    return results, errors


@pytest.fixture
def trio(db, chair, other_chair, price, global_admin):
    a = factories.make_user(db, "A", chair=chair)
    b = factories.make_user(db, "B", chair=other_chair)
    c = factories.make_user(db, "C", chair=chair)
    factories.add_events(db, a, ["single", "double"])
    factories.add_events(db, b, ["double"])
    factories.add_events(db, c, ["single"])
    factories.make_payment(db, a, global_admin, 120)
    factories.make_payment(db, b, global_admin, -30)
    ledger.add_adjustment(db, admin=global_admin, user_id=c.id, quantity=-1, amount_cents=-50)
    db.commit()
    return a, b, c


def raw_totals(db_path, effective_id):
    """Totals computed in plain SQL over the effective_users view (independent of the service code)."""
    con = sqlite3.connect(db_path)
    try:
        eid = effective_id.hex
        q = ("SELECT COALESCE(SUM(quantity),0), COALESCE(SUM(amount_cents),0) FROM consumption_events "
             "WHERE user_id IN (SELECT id FROM effective_users WHERE effective_id = ?)")
        shots, consumed = con.execute(q, (eid,)).fetchone()
        paid = con.execute("SELECT COALESCE(SUM(amount_cents),0) FROM payment_events WHERE user_id IN "
                           "(SELECT id FROM effective_users WHERE effective_id = ?)", (eid,)).fetchone()[0]
    finally:
        con.close()
    return ledger.Totals(shots, consumed, paid, consumed - paid)


def test_merge_chain_moves_no_rows_and_keeps_grand_totals(db, db_path, trio, global_admin):
    a, b, c = trio
    before = ledger_digest(db_path)
    grand = [ledger.get_totals(db, u.id) for u in trio]
    users.merge_users(db, admin=global_admin, duplicate_id=a.id, target_id=b.id)
    db.commit()
    users.merge_users(db, admin=global_admin, duplicate_id=b.id, target_id=c.id)  # chain: A -> B -> C
    db.commit()
    assert ledger_digest(db_path) == before
    db.expire_all()
    assert db.get(User, a.id).merged_into_id == c.id  # re-pointed, no two-step chain
    expected = ledger.Totals(*(sum(getattr(t, f) for t in grand) for f in
                               ("consumed_shots", "consumed_amount_cents", "paid_amount_cents", "balance_cents")))
    for u in trio:
        assert ledger.get_totals(db, u.id) == expected
    assert raw_totals(db_path, c.id) == expected
    assert check_ledger(db).ok


def test_user_table_and_dashboard_agree_with_sql(db, db_path, trio, global_admin):
    from app.services import stats

    a, b, c = trio
    users.merge_users(db, admin=global_admin, duplicate_id=a.id, target_id=c.id)
    db.commit()
    rows = stats.list_users(db, global_admin, page_size=None).rows
    assert {r.id for r in rows} == {b.id, c.id}
    for r in rows:
        t = raw_totals(db_path, r.id)
        assert (r.shots, r.consumed_cents, r.paid_cents, r.balance_cents) == (
            t.consumed_shots, t.consumed_amount_cents, t.paid_amount_cents, t.balance_cents)
        assert ledger.get_totals(db, r.id) == t
    dash = stats.dashboard(db, global_admin)
    assert dash.totals.balance_cents == sum(r.balance_cents for r in rows)
    assert dash.totals.consumed_shots == sum(r.shots for r in rows)
    assert sum(ch.consumed_cents for ch in dash.per_chair) == dash.totals.consumed_amount_cents
    assert sum(ch.paid_cents for ch in dash.per_chair) == dash.totals.paid_amount_cents


def test_merge_into_merged_profile_or_back_into_duplicate_is_refused(db, trio, global_admin):
    a, b, c = trio
    users.merge_users(db, admin=global_admin, duplicate_id=a.id, target_id=b.id)
    with pytest.raises(Conflict):
        users.merge_users(db, admin=global_admin, duplicate_id=c.id, target_id=a.id)
    with pytest.raises(Conflict):
        users.merge_users(db, admin=global_admin, duplicate_id=a.id, target_id=c.id)
    with pytest.raises(Conflict):
        users.merge_users(db, admin=global_admin, duplicate_id=b.id, target_id=a.id)  # would create a cycle


def test_concurrent_opposite_merges_cannot_create_a_cycle(db, trio, global_admin):
    a, b, _ = trio

    def merge(dup, tgt):
        def go():
            with write_session() as w:
                users.merge_users(w, admin=w.get(AdminUser, global_admin.id), duplicate_id=dup, target_id=tgt)
                return dup
        return go

    results, errors = run_threads([merge(a.id, b.id), merge(b.id, a.id)])
    assert len(results) == 1 and len(errors) == 1 and isinstance(errors[0], Conflict)
    db.expire_all()
    assert check_ledger(db).ok
    assert ledger.get_totals(db, a.id) == ledger.get_totals(db, b.id)


def test_merge_into_inactive_target_keeps_totals_and_blocks_scanning(db, trio, global_admin):
    """Allowed by the implementation (PROMPT is silent); the money must still add up."""
    a, b, _ = trio
    sum_before = ledger.get_totals(db, a.id).balance_cents + ledger.get_totals(db, b.id).balance_cents
    users.set_user_status(db, admin=global_admin, user_id=b.id, active=False)
    users.merge_users(db, admin=global_admin, duplicate_id=a.id, target_id=b.id)
    db.commit()
    assert ledger.get_totals(db, b.id).balance_cents == sum_before
    for uid in (a.id, b.id):
        with pytest.raises(UserInactive):
            ledger.record_coffee(db, user_id=uid, kind="single", nonce=f"n-{uid}")


def test_merge_while_scan_request_is_in_flight_records_nothing(client, db, user, chair, price, login, global_admin,
                                                                 monkeypatch):
    login(user)
    target = factories.make_user(db, "Target", chair=chair)
    real = deps.current_user
    done = []

    def resolve_then_merge(request):
        ctx = real(request)  # session resolved as valid ...
        if request.method == "POST" and not done:  # ... then an admin merges the profile before the write transaction
            done.append(1)
            with write_session() as w:
                users.merge_users(w, admin=w.get(AdminUser, global_admin.id), duplicate_id=user.id,
                                  target_id=target.id)
        return ctx

    monkeypatch.setattr(deps, "current_user", resolve_then_merge)
    r = post_scan(client, "single")
    assert r.status_code == 403
    assert events(db) == []


def test_payment_correction_across_merge(db, trio, global_admin):
    a, b, _ = trio
    pay = factories.make_payment(db, a, global_admin, 500)
    users.merge_users(db, admin=global_admin, duplicate_id=a.id, target_id=b.id)
    db.commit()
    with pytest.raises(Conflict):  # the duplicate itself no longer takes entries
        ledger.add_payment(db, admin=global_admin, user_id=a.id, amount_cents=-500, correction_of_id=pay.id)
    before = ledger.get_totals(db, b.id).paid_amount_cents
    ledger.add_payment(db, admin=global_admin, user_id=b.id, amount_cents=-500, correction_of_id=pay.id)
    with pytest.raises(Conflict):
        ledger.add_payment(db, admin=global_admin, user_id=b.id, amount_cents=-500, correction_of_id=pay.id)
    assert ledger.get_totals(db, b.id).paid_amount_cents == before - 500
