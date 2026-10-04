"""View-model helpers for the user pages (no business rules; formatting and small lookups)."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import COFFEE_KINDS, AdminUser, Chair, ConsumptionEvent, PaymentEvent
from app.money import format_money
from app.services import chairs, ledger, overview, pending
from app.services.ledger import Totals
from app.strings import t
from app.timeutil import format_local
from app.web import deps

NOTICES = {"saved": "user.account.notice_saved", "registered": "user.account.notice_registered",
           "expired": "user.account.notice_expired", "no_price": "user.account.notice_no_price",
           "password": "user.account.notice_password"}


LOGIN_NOTICES = {"reset": "user.login.notice_reset"}


def login_notice_key(value: str | None) -> str | None:
    """Whitelisted notice shown on /login (the query value only selects a fixed string)."""
    return LOGIN_NOTICES.get(value or "")


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
    amount_cents: int  # always shown without a sign: the type says the direction
    type: str  # payment | paid_back | bookkeeping_in | bookkeeping_out
    correction: bool


def payment_type(p: PaymentEvent) -> str:
    credited = p.amount_cents >= 0  # a positive amount lowers what the person owes
    if p.kind == "bookkeeping":
        return "bookkeeping_in" if credited else "bookkeeping_out"
    return "payment" if credited else "paid_back"


def payment_rows(payments) -> list[PaymentRow]:
    return [PaymentRow(local_time(p.created_at), abs(p.amount_cents), payment_type(p),
                       p.correction_of_id is not None) for p in payments]


def totals(db: Session, user_id) -> Totals:
    return ledger.get_totals(db, user_id)


@dataclass(frozen=True)
class Headline:
    state: str  # owes | credit | even
    text: str


def headline(balance_cents: int) -> Headline:
    """The balance in words ("Outstanding: €1.50", "Credit: €2.00", "All settled"); never a minus sign."""
    state, amount = overview.balance_label(balance_cents)
    return Headline(state, t(f"user.headline.{state}", amount=format_money(amount)))


def month_shots(db: Session, user_id) -> int:
    """Net shots this local month for display. A reversal booked this month for a coffee of last month can make
    the net negative; a person is never shown "-1 shots", so the display floors at 0."""
    return max(0, ledger.get_month_shots(db, user_id))


def is_group_admin(db: Session, user_id) -> bool:
    """Linked to an ACTIVE group admin row: the chair is fixed (the scope derives from it)."""
    return db.scalar(select(AdminUser.id).where(AdminUser.user_id == user_id, AdminUser.role == "chair",
                                                AdminUser.active.is_(True))) is not None
