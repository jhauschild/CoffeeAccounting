"""Price history (PROMPT §4 "prices"): immutable, append-only, never backdated."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import NOTE_MAX, AdminUser, Price
from app.services import audit
from app.services.authz import require_global
from app.services.errors import Conflict, InvalidAmount, InvalidInput, NotFound
from app.timeutil import ensure_utc, utcnow

MAX_PRICE_PER_SHOT_CENTS = 100_00


def get_price_in_effect(db: Session, at: datetime | None = None) -> Price | None:
    """The row with the greatest `effective_from <= at` (default: now), or None."""
    at = ensure_utc(at) if at is not None else utcnow()
    return db.scalars(
        select(Price).where(Price.effective_from <= at).order_by(Price.effective_from.desc()).limit(1)
    ).first()


def list_prices(db: Session) -> list[Price]:
    """All prices, newest `effective_from` first (including future-dated ones)."""
    return list(db.scalars(select(Price).order_by(Price.effective_from.desc())))


def clean_note(note: str | None) -> str | None:
    if note is None:
        return None
    note = " ".join(note.split())
    if len(note) > NOTE_MAX:
        raise InvalidInput(f"note longer than {NOTE_MAX} characters")
    return note or None


def add_price(
    db: Session,
    *,
    price_per_shot_cents: int,
    effective_from: datetime | None = None,
    admin_id: uuid.UUID | None,
    note: str | None = None,
    ip: str | None = None,
    now: datetime | None = None,
) -> Price:
    """Append a price row. Global admins only; `admin_id=None` means the CLI (system actor).

    `effective_from` defaults to now and must not lie in the past (no backdating).
    """
    now = ensure_utc(now) if now is not None else utcnow()
    if admin_id is not None:
        admin = db.get(AdminUser, admin_id)
        if admin is None:
            raise NotFound("admin not found")
        require_global(admin)
    if isinstance(price_per_shot_cents, bool) or not isinstance(price_per_shot_cents, int):
        raise InvalidAmount("price must be an integer number of cents")
    if not 0 <= price_per_shot_cents <= MAX_PRICE_PER_SHOT_CENTS:
        raise InvalidAmount("price out of range")
    if effective_from is None:
        effective_from = now
    elif effective_from.tzinfo is None:
        raise InvalidInput("effective_from must be timezone-aware")
    effective_from = ensure_utc(effective_from)
    if effective_from < now:
        raise InvalidInput("prices cannot be backdated")
    if db.scalar(select(Price.id).where(Price.effective_from == effective_from)) is not None:
        raise Conflict("a price with this effective time already exists")
    previous = get_price_in_effect(db, effective_from)
    price = Price(
        price_per_shot_cents=price_per_shot_cents,
        effective_from=effective_from,
        created_by_admin_id=admin_id,
        note=clean_note(note),
        created_at=now,
    )
    db.add(price)
    db.flush()
    audit.log(
        db,
        actor_type="admin" if admin_id else "system",
        actor_id=admin_id,
        action="price.added",
        target_type="price",
        target_id=price.id,
        metadata={
            "price_per_shot_cents": price_per_shot_cents,
            "effective_from": effective_from.isoformat(),
            "previous_price_per_shot_cents": previous.price_per_shot_cents if previous else None,
        },
        ip=ip,
        now=now,
    )
    return price
