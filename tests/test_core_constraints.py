"""Database-level constraints and triggers, exercised with raw SQL (no service layer)."""

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError

from tests import factories

TS = "2026-01-01 10:00:00.000000"


def _event_row(user, price, **overrides):
    row = dict(
        id=uuid.uuid4().hex, user_id=user.id.hex, chair_id=user.chair_id.hex, quantity=1, type="single",
        unit_price_cents=50, amount_cents=50, price_id=price.id.hex, idempotency_key=uuid.uuid4().hex,
        reversal_of_id=None, session_id=None, admin_id=None, note=None, created_at=TS,
    )
    row.update(overrides)
    return row


def insert_event(engine, row):
    cols = ", ".join(row)
    params = ", ".join(f":{k}" for k in row)
    with engine.begin() as conn:
        conn.execute(text(f"INSERT INTO consumption_events ({cols}) VALUES ({params})"), row)
    return row


def insert_payment(engine, user, admin, **overrides):
    row = dict(id=uuid.uuid4().hex, user_id=user.id.hex, chair_id=user.chair_id.hex, amount_cents=500,
               admin_id=admin.id.hex, correction_of_id=None, note=None, created_at=TS)
    row.update(overrides)
    cols = ", ".join(row)
    with engine.begin() as conn:
        conn.execute(text(f"INSERT INTO payment_events ({cols}) VALUES ({', '.join(':' + k for k in row)})"), row)
    return row


@pytest.fixture
def base(engine, db, user, price, global_admin):
    return engine, user, price, global_admin


def test_valid_rows_are_accepted(base):
    engine, user, price, admin = base
    orig = insert_event(engine, _event_row(user, price))
    insert_event(engine, _event_row(user, price, type="double", quantity=2, amount_cents=100))
    insert_event(engine, _event_row(user, price, type="reversal", quantity=-1, amount_cents=-50,
                                    reversal_of_id=orig["id"]))
    insert_event(engine, _event_row(user, price, type="adjustment", quantity=3, amount_cents=0, price_id=None,
                                    admin_id=admin.id.hex))
    insert_payment(engine, user, admin)


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param(dict(quantity=0, amount_cents=0), id="zero-quantity"),
        pytest.param(dict(type="bogus"), id="unknown-type"),
        pytest.param(dict(type="single", quantity=2, amount_cents=100), id="single-with-2"),
        pytest.param(dict(type="double", quantity=1, amount_cents=50), id="double-with-1"),
        pytest.param(dict(amount_cents=49), id="amount-not-quantity-times-price"),
        pytest.param(dict(price_id=None), id="coffee-without-price"),
        pytest.param(dict(unit_price_cents=-50, amount_cents=-50), id="negative-unit-price"),
        pytest.param(dict(type="reversal", quantity=-1, amount_cents=-50), id="reversal-without-original"),
        pytest.param(dict(type="adjustment", quantity=1, amount_cents=50), id="adjustment-without-admin"),
        pytest.param(dict(type="adjustment", quantity=1, amount_cents=-50, admin_id="ADMIN"), id="opposite-signs"),
        pytest.param(dict(type="single", unit_price_cents=0, amount_cents=0, quantity=1), id="zero-price-ok"),
    ],
)
def test_consumption_check_constraints(base, overrides):
    engine, user, price, admin = base
    if overrides.get("admin_id") == "ADMIN":
        overrides["admin_id"] = admin.id.hex
    row = _event_row(user, price, **overrides)
    if row["unit_price_cents"] == 0 and row["amount_cents"] == 0 and row["type"] == "single":
        insert_event(engine, row)  # control: amount 0 is allowed when the price was 0
        return
    with pytest.raises(IntegrityError):
        insert_event(engine, row)


def test_zero_amount_only_for_zero_price_adjustment_or_reversal(base):
    engine, user, price, admin = base
    orig = insert_event(engine, _event_row(user, price))
    with pytest.raises(IntegrityError):  # a coffee with amount 0 at a non-zero price
        insert_event(engine, _event_row(user, price, amount_cents=0))
    # A reversal may carry amount 0 (it reverses a zero-amount adjustment); a row-level CHECK cannot
    # see the original, so `check-ledger` (zero_amount / reversal_amount) guards the bad pairing.
    insert_event(engine, _event_row(user, price, type="reversal", quantity=-1, amount_cents=0,
                                    reversal_of_id=orig["id"]))


def test_non_reversal_cannot_reference_an_event(base):
    engine, user, price, admin = base
    orig = insert_event(engine, _event_row(user, price))
    with pytest.raises(IntegrityError):
        insert_event(engine, _event_row(user, price, reversal_of_id=orig["id"]))


def test_reversal_needs_negative_quantity(base):
    engine, user, price, admin = base
    orig = insert_event(engine, _event_row(user, price))
    with pytest.raises(IntegrityError):
        insert_event(engine, _event_row(user, price, type="reversal", quantity=1, amount_cents=50,
                                        reversal_of_id=orig["id"]))


def test_duplicate_idempotency_key_rejected(base):
    engine, user, price, _ = base
    insert_event(engine, _event_row(user, price, idempotency_key="same"))
    with pytest.raises(IntegrityError):
        insert_event(engine, _event_row(user, price, idempotency_key="same"))


def test_second_reversal_of_one_event_rejected(base):
    engine, user, price, _ = base
    orig = insert_event(engine, _event_row(user, price))
    rev = dict(type="reversal", quantity=-1, amount_cents=-50, reversal_of_id=orig["id"])
    insert_event(engine, _event_row(user, price, **rev))
    with pytest.raises(IntegrityError):
        insert_event(engine, _event_row(user, price, **rev))


def test_foreign_keys_enforced(base):
    engine, user, price, _ = base
    with pytest.raises(IntegrityError):
        insert_event(engine, _event_row(user, price, user_id=uuid.uuid4().hex))
    with pytest.raises(IntegrityError):
        insert_event(engine, _event_row(user, price, type="reversal", quantity=-1, amount_cents=-50,
                                        reversal_of_id=uuid.uuid4().hex))


def test_payment_constraints(base):
    engine, user, _, admin = base
    with pytest.raises(IntegrityError):
        insert_payment(engine, user, admin, amount_cents=0)
    first = insert_payment(engine, user, admin)
    insert_payment(engine, user, admin, amount_cents=-500, correction_of_id=first["id"])
    with pytest.raises(IntegrityError):  # unique partial index on correction_of_id
        insert_payment(engine, user, admin, amount_cents=-500, correction_of_id=first["id"])
    with pytest.raises(IntegrityError):  # admin required
        insert_payment(engine, user, admin, admin_id=None)


def test_price_constraints(engine, db):
    factories.set_price(db, 10, effective_from=None)
    with engine.begin() as conn:
        eff = conn.execute(text("SELECT effective_from FROM prices")).scalar()
    with pytest.raises(IntegrityError):
        with engine.begin() as conn:
            conn.execute(text("INSERT INTO prices (id, price_per_shot_cents, effective_from, created_at) "
                              "VALUES (:i, 5, :e, :e)"), {"i": uuid.uuid4().hex, "e": eff})
    with pytest.raises(IntegrityError):
        with engine.begin() as conn:
            conn.execute(text("INSERT INTO prices (id, price_per_shot_cents, effective_from, created_at) "
                              "VALUES (:i, -1, :e, :e)"), {"i": uuid.uuid4().hex, "e": TS})


def test_user_and_session_and_admin_uniques(engine, db, user):
    factories.make_session(db, user, raw_token="tok")
    with pytest.raises(IntegrityError):
        factories.make_session(db, user, raw_token="tok")
    db.rollback()
    factories.make_admin(db, username="Boss")
    with pytest.raises(IntegrityError):
        factories.make_admin(db, username="boss")
    db.rollback()
    with pytest.raises(IntegrityError):  # merged requires merged_into_id
        with engine.begin() as conn:
            conn.execute(text("UPDATE users SET status='merged' WHERE id=:i"), {"i": user.id.hex})
    with pytest.raises(IntegrityError):  # cannot merge into itself
        with engine.begin() as conn:
            conn.execute(text("UPDATE users SET status='merged', merged_into_id=id WHERE id=:i"), {"i": user.id.hex})


@pytest.mark.parametrize("table", ["audit_log", "consumption_events", "payment_events", "prices"])
def test_append_only_triggers(base, db, table):
    engine, user, price, admin = base
    from app.services import audit

    audit.log(db, actor_type="system", action="test.entry")
    db.commit()
    insert_event(engine, _event_row(user, price))
    insert_payment(engine, user, admin)
    with pytest.raises((IntegrityError, OperationalError), match="append-only"):
        with engine.begin() as conn:
            conn.execute(text(f"UPDATE {table} SET created_at = :t"), {"t": TS})
    with pytest.raises((IntegrityError, OperationalError), match="append-only"):
        with engine.begin() as conn:
            conn.execute(text(f"DELETE FROM {table}"))
    with engine.begin() as conn:
        assert conn.execute(text(f"SELECT count(*) FROM {table}")).scalar() >= 1
