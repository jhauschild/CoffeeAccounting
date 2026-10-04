"""check-ledger on clean and corrupted data, and the core CLI commands."""

import sqlite3
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from app import cli
from app.models import (AuditLog, PasswordResetToken, PendingAction, PendingRegistration, Price, RateLimitEvent,
                        UserSession)
from app.services import ledger, users
from app.services.checker import check_ledger
from app.timeutil import utcnow
from tests import factories


@pytest.fixture
def seeded(db, chair, other_chair, global_admin):
    now = utcnow()
    factories.set_price(db, 50, effective_from=now - timedelta(days=5))
    alice = factories.make_user(db, "Alice", chair=chair)
    bob = factories.make_user(db, "Bob", chair=other_chair)
    single, double = factories.add_events(db, alice, ["single", "double"], at=now - timedelta(days=4))
    factories.set_price(db, 70, effective_from=now - timedelta(days=3))
    factories.add_events(db, bob, ["double"], at=now - timedelta(days=2))
    rev = ledger.admin_reverse_event(db, admin=global_admin, event_id=double.id)
    ledger.add_adjustment(db, admin=global_admin, user_id=bob.id, quantity=1)
    pay = factories.make_payment(db, alice, global_admin, 1000)
    ledger.add_payment(db, admin=global_admin, user_id=alice.id, amount_cents=-1000, correction_of_id=pay.id)
    users.merge_users(db, admin=global_admin, duplicate_id=bob.id, target_id=alice.id)
    db.commit()
    return dict(alice=alice, bob=bob, single=single, double=double, rev=rev, now=now)


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


def test_clean_ledger_passes(db, seeded, capsys):
    report = check_ledger(db)
    assert report.ok, report.problems
    assert (report.consumption_events, report.payment_events, report.users) == (5, 2, 2)
    assert cli.main(["check-ledger"]) == 0
    assert capsys.readouterr().out.startswith("OK:")


def _event_insert(seed, **kw):
    row = dict(id=uuid.uuid4().hex, user_id=seed["alice"].id.hex, chair_id=seed["alice"].chair_id.hex, quantity=-2,
               type="reversal", unit_price_cents=50, amount_cents=-100, price_id=seed["double"].price_id.hex,
               idempotency_key=uuid.uuid4().hex, reversal_of_id=None, created_at="2026-01-01 00:00:00.000000")
    row.update(kw)
    cols = ", ".join(row)
    return (f"INSERT INTO consumption_events ({cols}) VALUES ({', '.join('?' * len(row))})", tuple(row.values()))


CORRUPTIONS = {
    "reversal_amount": lambda s: [
        "DROP TRIGGER consumption_events_no_update",
        ("UPDATE consumption_events SET amount_cents = -1 WHERE id = ?", (s["rev"].id.hex,)),
    ],
    "snapshot_mismatch": lambda s: [
        "DROP TRIGGER consumption_events_no_update",
        ("UPDATE consumption_events SET unit_price_cents = 70, amount_cents = 70 WHERE id = ?", (s["single"].id.hex,)),
    ],
    "amount_mismatch": lambda s: [
        "DROP TRIGGER consumption_events_no_update",
        "PRAGMA ignore_check_constraints = ON",
        ("UPDATE consumption_events SET amount_cents = 999 WHERE id = ?", (s["single"].id.hex,)),
    ],
    "quantity_type": lambda s: [
        "DROP TRIGGER consumption_events_no_update",
        "PRAGMA ignore_check_constraints = ON",
        ("UPDATE consumption_events SET quantity = 3, amount_cents = 150 WHERE id = ?", (s["single"].id.hex,)),
    ],
    "orphan_user": lambda s: ["PRAGMA foreign_keys = OFF", _event_insert(s, user_id=uuid.uuid4().hex, quantity=-1,
                                                                         amount_cents=-50,
                                                                         reversal_of_id=s["single"].id.hex)],
    "orphan_reversal": lambda s: ["PRAGMA foreign_keys = OFF", _event_insert(s, reversal_of_id=uuid.uuid4().hex)],
    "double_reversal": lambda s: ["DROP INDEX uq_consumption_events_reversal_of_id",
                                  _event_insert(s, reversal_of_id=s["double"].id.hex)],
    "reversal_of_reversal": lambda s: [_event_insert(s, quantity=2 * -1, reversal_of_id=s["rev"].id.hex)],
    "merge_cycle": lambda s: [("UPDATE users SET status = 'merged', merged_into_id = ? WHERE id = ?",
                               (s["bob"].id.hex, s["alice"].id.hex))],
    "price_row_mismatch": lambda s: [
        ("INSERT INTO prices (id, price_per_shot_cents, effective_from, created_at) VALUES (?, 50, ?, ?)",
         (uuid.uuid4().hex, (s["now"] - timedelta(days=4, minutes=1)).strftime("%Y-%m-%d %H:%M:%S.%f"),
          "2026-01-01 00:00:00.000000")),
    ],
}


@pytest.mark.parametrize("code", sorted(CORRUPTIONS))
def test_check_ledger_detects_seeded_corruption(db, db_path, seeded, code, capsys):
    raw(db_path, *CORRUPTIONS[code](seeded))
    assert code in codes(db)
    assert cli.main(["check-ledger"]) == 1
    out = capsys.readouterr()
    assert f"[{code}]" in out.out and "FAILED" in out.err


def test_cli_set_price(db, capsys):
    assert cli.main(["set-price", "--cents", "55", "--note", "beans"]) == 0
    assert "€0.55" in capsys.readouterr().out
    assert cli.main(["set-price", "--cents", "60", "--from", "2001-01-01T00:00"]) == 1  # backdated
    assert cli.main(["set-price", "--cents", "60", "--from", "tomorrow"]) == 2
    future = (utcnow() + timedelta(days=1)).isoformat()
    assert cli.main(["set-price", "--cents", "60", "--from", future]) == 0
    db.expire_all()
    assert sorted(db.scalars(select(Price.price_per_shot_cents))) == [55, 60]
    assert db.scalar(select(func.count()).where(AuditLog.action == "price.added", AuditLog.actor_type == "system")) == 2


def test_cli_purge_expired(db, user, capsys):
    now = utcnow()
    expired = factories.make_session(db, user, expires_in=timedelta(seconds=-1))
    live = factories.make_session(db, user)
    db.add_all([
        PendingAction(id="old", kind="single", nonce="n-old", expires_at=now - timedelta(minutes=1)),
        PendingAction(id="new", kind="double", nonce="n-new", expires_at=now + timedelta(hours=1)),
        RateLimitEvent(bucket="gate", key="ip", created_at=now - timedelta(days=2)),
        RateLimitEvent(bucket="gate", key="ip", created_at=now),
    ])
    db.commit()
    expired_id, live_id = expired.id, live.id
    assert cli.main(["purge-expired"]) == 0
    assert "user_sessions=1" in capsys.readouterr().out
    db.expire_all()
    assert db.get(UserSession, expired_id) is None and db.get(UserSession, live_id) is not None
    assert [p.id for p in db.scalars(select(PendingAction))] == ["new"]
    assert db.scalar(select(func.count()).select_from(RateLimitEvent)) == 1


def test_cli_purge_expired_removes_expired_and_used_registration_and_reset_links(db, chair, capsys):
    now = utcnow()
    member = factories.make_member(db, "Pat", chair)

    def registration(name, expires, consumed=None):
        return PendingRegistration(
            kind="member", username=name, username_normalized=name, display_name=name, chair_id=chair.id,
            email=f"{name}@tum.de", password_hash="!", token_hash=name.ljust(64, "0"), created_at=now,
            expires_at=expires, consumed_at=consumed)

    def reset(token_hash, expires, consumed=None):
        return PasswordResetToken(user_id=member.id, token_hash=token_hash.ljust(64, "0"), created_at=now,
                                  expires_at=expires, consumed_at=consumed)

    soon, past = now + timedelta(hours=1), now - timedelta(minutes=1)
    db.add_all([registration("open", soon), registration("expired", past), registration("used", soon, now),
                reset("open", soon), reset("expired", past), reset("used", soon, now)])
    db.commit()
    assert cli.main(["purge-expired"]) == 0
    out = capsys.readouterr().out
    assert "pending_registrations=2" in out and "reset_links=2" in out
    db.expire_all()
    assert [r.username for r in db.scalars(select(PendingRegistration))] == ["open"]
    assert [r.token_hash[:4] for r in db.scalars(select(PasswordResetToken))] == ["open"]
    assert db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == "maintenance.purge_expired")) == 1


def test_cli_registers_admin_commands(monkeypatch):
    import app.cli_admin

    def register(sub):
        p = sub.add_parser("hello")
        p.set_defaults(func=lambda args: 7)

    monkeypatch.setattr(app.cli_admin, "register", register)
    assert cli.main(["hello"]) == 7
