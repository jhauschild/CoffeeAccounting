"""The ledger: coffee events, undo, admin reversals/adjustments/payments, and totals.

All mutating functions run inside the caller's write transaction (`db.write_session()`)
and never commit. Users can only create single/double events and undo their own latest
in-window event; quantity, amount, price, user id and chair id are never taken from them.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import (
    COFFEE_KINDS,
    COFFEE_QUANTITY,
    PAYMENT_KINDS,
    AdminUser,
    ConsumptionEvent,
    PaymentEvent,
    User,
)
from app.services import audit
from app.services.authz import ensure_admin_can_access_user, require_global
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
from app.services.prices import clean_note, get_price_in_effect
from app.services.users import effective_user_id, member_ids_select
from app.timeutil import ensure_utc, local_month_bounds, utcnow

MAX_ADJUSTMENT_SHOTS = 1000
MAX_AMOUNT_CENTS = 1_000_000_00
MAX_NONCE_LENGTH = 80


@dataclass
class RecordResult:
    event: ConsumptionEvent
    created: bool


@dataclass
class Totals:
    consumed_shots: int
    consumed_amount_cents: int
    paid_amount_cents: int
    balance_cents: int  # positive: the user owes; negative: credit


def _now(now: datetime | None) -> datetime:
    return ensure_utc(now) if now is not None else utcnow()


def _event_by_key(db: Session, key: str) -> ConsumptionEvent | None:
    return db.scalars(select(ConsumptionEvent).where(ConsumptionEvent.idempotency_key == key)).first()


def _is_unique_violation(exc: IntegrityError) -> bool:
    """True only for unique-index/constraint conflicts (never CHECK, FK or NOT NULL failures)."""
    orig = getattr(exc, "orig", None)
    if getattr(orig, "sqlstate", None) == "23505" or getattr(orig, "pgcode", None) == "23505":
        return True
    # sqlite3: SQLITE_CONSTRAINT_UNIQUE = 2067, SQLITE_CONSTRAINT_PRIMARYKEY = 1555
    if getattr(orig, "sqlite_errorcode", None) in (2067, 1555):
        return True
    return "UNIQUE constraint failed" in str(orig)


def _insert_once(db: Session, obj, *, on_conflict):
    """Insert inside a SAVEPOINT; on a unique violation call `on_conflict()` instead.

    Under `write_session()` concurrent writers are already serialized, so this only
    matters for callers that use a deferred transaction.
    """
    try:
        with db.begin_nested():
            db.add(obj)
            db.flush()
    except IntegrityError as exc:
        if not _is_unique_violation(exc):
            raise
        return on_conflict()
    return obj


def _reversal_key(original_id: uuid.UUID) -> str:
    return f"reversal:{original_id}"


def is_reversed(db: Session, event_id: uuid.UUID) -> bool:
    return db.scalar(select(ConsumptionEvent.id).where(ConsumptionEvent.reversal_of_id == event_id)) is not None


def reversed_ids(db: Session, event_ids) -> set[uuid.UUID]:
    """Subset of `event_ids` that already have a reversal (for list views)."""
    ids = list(event_ids)
    if not ids:
        return set()
    return set(db.scalars(select(ConsumptionEvent.reversal_of_id).where(ConsumptionEvent.reversal_of_id.in_(ids))))


# ----- user actions -------------------------------------------------------------------------
def record_coffee(
    db: Session,
    *,
    user_id: uuid.UUID,
    kind: str,
    nonce: str,
    session_id: uuid.UUID | None = None,
    now: datetime | None = None,
) -> RecordResult:
    """Record a single/double for `user_id` at the price in effect now.

    Idempotent on `nonce`: if an event with this key exists it is returned with
    `created=False` (whoever owns it; the caller decides what to show). Raises
    `UserInactive`, `NoPriceConfigured`, `RateLimited` (per-session hourly cap) or
    `InvalidInput`.
    """
    if kind not in COFFEE_KINDS:
        raise InvalidInput("invalid coffee kind")
    if not nonce or len(nonce) > MAX_NONCE_LENGTH:
        raise InvalidInput("invalid nonce")
    existing = _event_by_key(db, nonce)
    if existing is not None:
        return RecordResult(existing, False)
    now = _now(now)
    user = db.get(User, user_id)
    if user is None:
        raise NotFound("user not found")
    if user.status != "active":
        raise UserInactive("profile is not active")
    price = get_price_in_effect(db, now)
    if price is None:
        raise NoPriceConfigured("no price configured")
    if session_id is not None:
        cap = get_settings().max_coffees_per_session_per_hour
        recent = db.scalar(
            select(func.count()).select_from(ConsumptionEvent).where(
                ConsumptionEvent.session_id == session_id,
                ConsumptionEvent.type.in_(COFFEE_KINDS),
                ConsumptionEvent.created_at > now - timedelta(hours=1),
            )
        )
        if recent >= cap:
            raise RateLimited("too many coffees from this browser in the last hour")
    quantity = COFFEE_QUANTITY[kind]
    event = ConsumptionEvent(
        user_id=user.id,
        chair_id=user.chair_id,
        quantity=quantity,
        type=kind,
        unit_price_cents=price.price_per_shot_cents,
        amount_cents=quantity * price.price_per_shot_cents,
        price_id=price.id,
        idempotency_key=nonce,
        session_id=session_id,
        created_at=now,
    )

    def _conflict():
        found = _event_by_key(db, nonce)
        if found is None:
            raise Conflict("could not record coffee")
        return found

    stored = _insert_once(db, event, on_conflict=_conflict)
    if stored is not event:
        return RecordResult(stored, False)
    user.last_activity_at = now
    db.flush()
    return RecordResult(event, True)


def _latest_session_coffee(db: Session, user_id: uuid.UUID, session_id: uuid.UUID) -> ConsumptionEvent | None:
    return db.scalars(
        select(ConsumptionEvent)
        .where(
            ConsumptionEvent.user_id == user_id,
            ConsumptionEvent.session_id == session_id,
            ConsumptionEvent.type.in_(COFFEE_KINDS),
        )
        .order_by(ConsumptionEvent.created_at.desc())
        .limit(1)
    ).first()


def _within_window(event: ConsumptionEvent, now: datetime) -> bool:
    return now - event.created_at <= timedelta(seconds=get_settings().undo_window_seconds)


def latest_undoable_event(
    db: Session, *, user_id: uuid.UUID, session_id: uuid.UUID | None, now: datetime | None = None
) -> ConsumptionEvent | None:
    """The user's most recent coffee from this session if still undoable, else None."""
    if session_id is None:
        return None
    event = _latest_session_coffee(db, user_id, session_id)
    if event is None or not _within_window(event, _now(now)) or is_reversed(db, event.id):
        return None
    return event


def _make_reversal(original: ConsumptionEvent, *, now: datetime, session_id=None, admin_id=None, note=None):
    # Same user and chair as the original so per-user and per-chair totals net out exactly.
    return ConsumptionEvent(
        user_id=original.user_id,
        chair_id=original.chair_id,
        quantity=-original.quantity,
        type="reversal",
        unit_price_cents=original.unit_price_cents,
        amount_cents=-original.amount_cents,
        price_id=original.price_id,
        idempotency_key=_reversal_key(original.id),
        reversal_of_id=original.id,
        session_id=session_id,
        admin_id=admin_id,
        note=note,
        created_at=now,
    )


def _insert_reversal(db: Session, reversal: ConsumptionEvent) -> ConsumptionEvent:
    def _conflict():
        raise AlreadyReversed("event has already been reversed")

    return _insert_once(db, reversal, on_conflict=_conflict)


def undo_coffee(
    db: Session, *, user_id: uuid.UUID, session_id: uuid.UUID | None, event_id: uuid.UUID, now: datetime | None = None
) -> ConsumptionEvent:
    """Reverse the user's own most recent coffee from this session within the undo window.

    Copies the original's quantity, unit price and amount (negated); ignores the current
    price. Raises `UndoNotAllowed` or `AlreadyReversed`.
    """
    now = _now(now)
    event = db.get(ConsumptionEvent, event_id)
    if event is None:
        raise NotFound("event not found")
    if event.user_id != user_id or session_id is None or event.session_id != session_id:
        raise UndoNotAllowed("not your event")
    if event.type not in COFFEE_KINDS:
        raise UndoNotAllowed("only coffees can be undone")
    user = db.get(User, user_id)
    if user is None or user.status != "active":
        raise UserInactive("profile is not active")
    if is_reversed(db, event.id):
        raise AlreadyReversed("event has already been reversed")
    if not _within_window(event, now):
        raise UndoNotAllowed("undo window has expired")
    latest = _latest_session_coffee(db, user_id, session_id)
    if latest is None or latest.id != event.id:
        raise UndoNotAllowed("only the most recent coffee can be undone")
    return _insert_reversal(db, _make_reversal(event, now=now, session_id=session_id))


# ----- admin actions ------------------------------------------------------------------------
def _access_effective(db: Session, admin: AdminUser, user_id: uuid.UUID) -> uuid.UUID:
    """Scope-check against the effective (post-merge) user; returns its id."""
    eff = effective_user_id(db, user_id) or user_id
    ensure_admin_can_access_user(db, admin, eff)
    return eff


def _ensure_not_own_account(db: Session, admin: AdminUser, user_id: uuid.UUID) -> None:
    """Own-balance rule: a group admin (role `chair`) may not post money or corrections to the
    account linked to themselves. Compared on effective (post-merge) ids. Head admins may."""
    if admin.role != "chair" or admin.user_id is None:
        return
    own = effective_user_id(db, admin.user_id) or admin.user_id
    target = effective_user_id(db, user_id) or user_id
    if own == target:
        raise Forbidden("a group admin cannot change their own account")


def admin_reverse_event(
    db: Session, *, admin: AdminUser, event_id: uuid.UUID, note: str | None = None, ip: str | None = None,
    now: datetime | None = None,
) -> ConsumptionEvent:
    """Reverse any coffee or adjustment (not a reversal) of an in-scope user, at most once."""
    now = _now(now)
    event = db.get(ConsumptionEvent, event_id)
    if event is None:
        raise NotFound("event not found")
    _access_effective(db, admin, event.user_id)
    _ensure_not_own_account(db, admin, event.user_id)
    if event.type == "reversal":
        raise Conflict("a reversal cannot be reversed")
    if is_reversed(db, event.id):
        raise AlreadyReversed("event has already been reversed")
    reversal = _insert_reversal(db, _make_reversal(event, now=now, admin_id=admin.id, note=clean_note(note)))
    audit.log(db, actor_type="admin", actor_id=admin.id, action="event.reversed", target_type="consumption_event",
              target_id=event.id,
              metadata={"reversal_id": str(reversal.id), "user_id": str(event.user_id),
                        "quantity": reversal.quantity, "amount_cents": reversal.amount_cents},
              ip=ip, now=now)
    return reversal


def _target_user_for_admin(db: Session, admin: AdminUser, user_id: uuid.UUID) -> User:
    ensure_admin_can_access_user(db, admin, user_id)
    user = db.get(User, user_id)
    if user.status == "merged":
        raise Conflict("profile has been merged; use the profile it was merged into")
    return user


def _check_int(value, what: str, limit: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidAmount(f"{what} must be an integer")
    if value == 0 or abs(value) > limit:
        raise InvalidAmount(f"{what} must be non-zero and at most {limit} in magnitude")
    return value


def adjustment_default_amount(db: Session, quantity: int, now: datetime | None = None) -> int | None:
    """Pre-fill value for the adjustment form: quantity × current price (None if no price)."""
    price = get_price_in_effect(db, _now(now))
    return None if price is None else quantity * price.price_per_shot_cents


def add_adjustment(
    db: Session,
    *,
    admin: AdminUser,
    user_id: uuid.UUID,
    quantity: int,
    amount_cents: int | None = None,
    note: str | None = None,
    ip: str | None = None,
    now: datetime | None = None,
) -> ConsumptionEvent:
    """Admin consumption adjustment. `amount_cents` defaults to quantity × current price;
    an override must not have the opposite sign of `quantity` (0 is allowed)."""
    now = _now(now)
    user = _target_user_for_admin(db, admin, user_id)
    _ensure_not_own_account(db, admin, user.id)
    quantity = _check_int(quantity, "quantity", MAX_ADJUSTMENT_SHOTS)
    price = get_price_in_effect(db, now)
    if amount_cents is None:
        if price is None:
            raise NoPriceConfigured("no price configured; enter the amount explicitly")
        amount_cents = quantity * price.price_per_shot_cents
    elif isinstance(amount_cents, bool) or not isinstance(amount_cents, int) or abs(amount_cents) > MAX_AMOUNT_CENTS:
        raise InvalidAmount("invalid amount")
    if (quantity > 0 and amount_cents < 0) or (quantity < 0 and amount_cents > 0):
        raise InvalidAmount("amount and quantity must not have opposite signs")
    event = ConsumptionEvent(
        user_id=user.id,
        chair_id=user.chair_id,
        quantity=quantity,
        type="adjustment",
        unit_price_cents=price.price_per_shot_cents if price else 0,
        amount_cents=amount_cents,
        price_id=price.id if price else None,
        idempotency_key=f"adjustment:{uuid.uuid4()}",
        admin_id=admin.id,
        note=clean_note(note),
        created_at=now,
    )
    db.add(event)
    db.flush()
    audit.log(db, actor_type="admin", actor_id=admin.id, action="event.adjustment", target_type="user",
              target_id=user.id,
              metadata={"event_id": str(event.id), "quantity": quantity, "amount_cents": amount_cents},
              ip=ip, now=now)
    return event


def _payment_by_key(db: Session, key: str) -> PaymentEvent | None:
    return db.scalars(select(PaymentEvent).where(PaymentEvent.idempotency_key == key)).first()


def _check_key(key: str | None) -> str | None:
    if key is None:
        return None
    if not isinstance(key, str) or not key or len(key) > MAX_NONCE_LENGTH:
        raise InvalidInput("invalid idempotency key")
    return key


def add_payment(
    db: Session,
    *,
    admin: AdminUser,
    user_id: uuid.UUID,
    amount_cents: int,
    kind: str = "cash",
    note: str | None = None,
    correction_of_id: uuid.UUID | None = None,
    idempotency_key: str | None = None,
    ip: str | None = None,
    now: datetime | None = None,
) -> PaymentEvent:
    """Record money received (positive) or paid back (negative) outside the app.

    `kind="cash"` (default): the recording admin is the collector (`collector_admin_id`).
    `kind="bookkeeping"` (head admin only, normally via `set_balance`): no collector, never
    counted as collected. With `correction_of_id` the new event corrects an earlier payment of
    the same (effective) user and COPIES kind and `collector_admin_id` from it, whoever records
    the correction; each payment can be corrected at most once.

    Idempotent on `idempotency_key`: if a payment with this key exists it is returned and
    nothing is inserted (a key reused for a different user or amount raises `Conflict`).
    A group admin cannot post to their own linked account (`Forbidden`).
    """
    now = _now(now)
    if kind not in PAYMENT_KINDS:
        raise InvalidInput("invalid payment kind")
    key = _check_key(idempotency_key)
    user = _target_user_for_admin(db, admin, user_id)
    _ensure_not_own_account(db, admin, user.id)
    amount_cents = _check_int(amount_cents, "amount", MAX_AMOUNT_CENTS)
    if kind == "bookkeeping":
        require_global(admin)
    if key is not None:
        existing = _payment_by_key(db, key)
        if existing is not None:
            return _same_payment_or_conflict(db, existing, user.id, amount_cents)
    collector_id: uuid.UUID | None = admin.id if kind == "cash" else None
    if correction_of_id is not None:
        original = db.get(PaymentEvent, correction_of_id)
        if original is None:
            raise NotFound("payment not found")
        if effective_user_id(db, original.user_id) != user.id:
            raise Conflict("payment belongs to another profile")
        if db.scalar(select(PaymentEvent.id).where(PaymentEvent.correction_of_id == original.id)) is not None:
            raise Conflict("payment has already been corrected")
        kind, collector_id = original.kind, original.collector_admin_id
        if kind == "bookkeeping":
            require_global(admin)
    payment = PaymentEvent(
        user_id=user.id,
        chair_id=user.chair_id,
        amount_cents=amount_cents,
        admin_id=admin.id,
        correction_of_id=correction_of_id,
        kind=kind,
        collector_admin_id=collector_id,
        idempotency_key=key,
        note=clean_note(note),
        created_at=now,
    )

    def _conflict():
        if key is not None:
            found = _payment_by_key(db, key)
            if found is not None:
                return _same_payment_or_conflict(db, found, user.id, amount_cents)
        raise Conflict("payment has already been corrected")

    stored = _insert_once(db, payment, on_conflict=_conflict)
    if stored is not payment:
        return stored
    audit.log(db, actor_type="admin", actor_id=admin.id,
              action="payment.corrected" if correction_of_id else "payment.recorded",
              target_type="user", target_id=user.id,
              metadata={"payment_id": str(payment.id), "amount_cents": amount_cents, "kind": kind,
                        "correction_of_id": str(correction_of_id) if correction_of_id else None},
              ip=ip, now=now)
    return payment


def _same_payment_or_conflict(db: Session, existing: PaymentEvent, user_id: uuid.UUID, amount_cents: int):
    if effective_user_id(db, existing.user_id) != user_id or existing.amount_cents != amount_cents:
        raise Conflict("idempotency key already used for a different payment")
    return existing


def set_balance(
    db: Session,
    *,
    admin: AdminUser,
    user_id: uuid.UUID,
    target_balance_cents: int,
    idempotency_key: str,
    note: str | None = None,
    ip: str | None = None,
    now: datetime | None = None,
) -> PaymentEvent:
    """Head admin only: make the user's balance (consumed - paid, positive = owes) equal
    `target_balance_cents` by booking one `bookkeeping` payment of (current - target).

    Append-only: nothing is edited. Idempotent on `idempotency_key` (a repeat returns the
    event booked the first time, even though the balance now already equals the target).
    If the balance already equals the target and the key is new, raises `InvalidAmount`
    (no zero-amount event is ever written). Non-head admins get `Forbidden`.
    """
    require_global(admin)
    key = _check_key(idempotency_key)
    if key is None:
        raise InvalidInput("idempotency key required")
    if isinstance(target_balance_cents, bool) or not isinstance(target_balance_cents, int) \
            or abs(target_balance_cents) > MAX_AMOUNT_CENTS:
        raise InvalidAmount("invalid target balance")
    user = _target_user_for_admin(db, admin, user_id)
    existing = _payment_by_key(db, key)
    if existing is not None:
        if existing.kind != "bookkeeping" or effective_user_id(db, existing.user_id) != user.id:
            raise Conflict("idempotency key already used for a different payment")
        return existing
    diff = get_totals(db, user.id).balance_cents - target_balance_cents
    if diff == 0:
        raise InvalidAmount("balance already equals the target")
    return add_payment(db, admin=admin, user_id=user.id, amount_cents=diff, kind="bookkeeping",
                       idempotency_key=key, note=note, ip=ip, now=now)


# ----- reads --------------------------------------------------------------------------------
def get_totals(db: Session, user_id: uuid.UUID) -> Totals:
    """Totals for the effective user of `user_id` (includes profiles merged into it)."""
    eff = effective_user_id(db, user_id) or user_id
    members = member_ids_select(eff)
    shots, consumed = db.execute(
        select(func.coalesce(func.sum(ConsumptionEvent.quantity), 0),
               func.coalesce(func.sum(ConsumptionEvent.amount_cents), 0))
        .where(ConsumptionEvent.user_id.in_(members))
    ).one()
    paid = db.scalar(
        select(func.coalesce(func.sum(PaymentEvent.amount_cents), 0)).where(PaymentEvent.user_id.in_(members))
    )
    return Totals(int(shots), int(consumed), int(paid), int(consumed) - int(paid))


def get_month_shots(db: Session, user_id: uuid.UUID, now: datetime | None = None) -> int:
    """Net shots (reversals netted out) of the effective user in the current LOCAL calendar
    month (LOCAL_TIMEZONE, DST-safe half-open bounds); includes merged profiles."""
    eff = effective_user_id(db, user_id) or user_id
    start, end = local_month_bounds(_now(now))
    total = db.scalar(
        select(func.coalesce(func.sum(ConsumptionEvent.quantity), 0)).where(
            ConsumptionEvent.user_id.in_(member_ids_select(eff)),
            ConsumptionEvent.created_at >= start,
            ConsumptionEvent.created_at < end,
        )
    )
    return int(total)


def recent_consumption(db: Session, user_id: uuid.UUID, limit: int | None = 20) -> list[ConsumptionEvent]:
    """Consumption events of the effective user, newest first (`limit=None`: all)."""
    eff = effective_user_id(db, user_id) or user_id
    q = (select(ConsumptionEvent).where(ConsumptionEvent.user_id.in_(member_ids_select(eff)))
         .order_by(ConsumptionEvent.created_at.desc()))
    if limit is not None:
        q = q.limit(limit)
    return list(db.scalars(q))


def recent_payments(db: Session, user_id: uuid.UUID, limit: int | None = 20) -> list[PaymentEvent]:
    """Payment events of the effective user, newest first (`limit=None`: all)."""
    eff = effective_user_id(db, user_id) or user_id
    q = (select(PaymentEvent).where(PaymentEvent.user_id.in_(member_ids_select(eff)))
         .order_by(PaymentEvent.created_at.desc()))
    if limit is not None:
        q = q.limit(limit)
    return list(db.scalars(q))
