"""View-model helpers for the user pages (no business rules; formatting and small lookups)."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request
from sqlalchemy.orm import Session

from app.models import COFFEE_KINDS, Chair, ConsumptionEvent
from app.services import chairs, ledger, pending
from app.services.ledger import Totals
from app.timeutil import format_local
from app.web import deps

NOTICES = {"saved": "user.account.notice_saved", "registered": "user.account.notice_registered",
           "expired": "user.account.notice_expired", "no_price": "user.account.notice_no_price"}


def notice_key(value: str | None) -> str | None:
    """Whitelisted notice shown on /account (the query value only selects a fixed string)."""
    return NOTICES.get(value or "")


def local_time(dt) -> str:
    return format_local(dt, "%Y-%m-%d %H:%M")


def pending_notice(request: Request, db: Session) -> str | None:
    """String key for the pending-coffee notice, or None if the browser has no pending cookie."""
    pid = deps.pending_id(request)
    if pid is None:
        return None
    action = pending.get_pending(db, pid)
    if action is None:
        return "user.pending.expired"
    return f"user.pending.{action.kind}"


def active_chairs(db: Session, include: Chair | None = None) -> list[Chair]:
    result = chairs.list_chairs(db, active_only=True)
    if include is not None and all(c.id != include.id for c in result):
        result.append(include)
    return result


@dataclass
class EventRow:
    id: str
    time: str
    type: str
    quantity: int
    amount_cents: int
    reversed: bool


def event_rows(db: Session, events: list[ConsumptionEvent]) -> list[EventRow]:
    reversed_set = ledger.reversed_ids(db, [e.id for e in events if e.type in COFFEE_KINDS])
    return [EventRow(str(e.id), local_time(e.created_at), e.type, e.quantity, e.amount_cents, e.id in reversed_set)
            for e in events]


@dataclass
class PaymentRow:
    time: str
    amount_cents: int


def payment_rows(payments) -> list[PaymentRow]:
    return [PaymentRow(local_time(p.created_at), p.amount_cents) for p in payments]


def totals(db: Session, user_id) -> Totals:
    return ledger.get_totals(db, user_id)
