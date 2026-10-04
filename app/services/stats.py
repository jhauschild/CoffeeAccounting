"""Admin read models: dashboard, user table, user detail, audit view (PROMPT §6).

Everything is derived from the ledger (never stored) and restricted by
`authz.visible_chair_ids`: a chair administrator only sees events and profiles of users who are
*currently* in one of their chairs (resolved through the effective user, so a merged profile
counts for the profile it was merged into). Period bounds use the local calendar
(`timeutil.local_*_bounds`, weeks Monday-Sunday).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models import (
    AdminUser,
    AuditLog,
    Chair,
    ConsumptionEvent,
    PaymentEvent,
    Price,
    User,
    effective_users,
)
from app.services import authz, groups, ledger, mail_status, sessions
from app.services.ledger import Totals
from app.services.prices import get_price_in_effect, list_prices
from app.services.users import _escape_like, _fold, _fold_sql, effective_user_id, member_ids_select, normalize_name
from app.timeutil import ensure_utc, local_day_bounds, local_month_bounds, local_week_bounds, utcnow

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200
SORTS = ("balance", "name", "consumption", "activity")
DEFAULT_DIRECTION = {"balance": "desc", "name": "asc", "consumption": "desc", "activity": "desc"}
STATUS_FILTERS = ("active", "inactive")
RECENT_LIMIT = 20
USER_AUDIT_LIMIT = 200
AUDIT_PAGE_SIZE = 50


# ----- scope helpers --------------------------------------------------------------------------
def _scope_user_ids(visible: set[uuid.UUID] | None, user_id_col):
    """WHERE clause limiting an event's `user_id` to effective users in visible chairs (None: no limit)."""
    if visible is None:
        return None
    in_scope = (
        select(effective_users.c.id)
        .join(User, User.id == effective_users.c.effective_id)
        .where(User.chair_id.in_(visible))
    )
    return user_id_col.in_(in_scope)


def _where(*clauses):
    return [c for c in clauses if c is not None]


def check_chair_filter(db: Session, admin: AdminUser, chair_id: uuid.UUID | None) -> None:
    """A chair filter outside the admin's scope is refused (403) rather than silently ignored."""
    if chair_id is not None:
        authz.ensure_admin_can_access_chair(db, admin, chair_id)


def visible_chairs(db: Session, admin: AdminUser) -> list[Chair]:
    visible = authz.visible_chair_ids(db, admin)
    q = select(Chair).order_by(Chair.short_name)
    if visible is not None:
        q = q.where(Chair.id.in_(visible))
    return list(db.scalars(q))


# ----- dashboard ------------------------------------------------------------------------------
@dataclass(frozen=True)
class PeriodTotals:
    shots: int
    consumed_cents: int
    paid_cents: int


@dataclass(frozen=True)
class ChairTotals:
    chair_id: uuid.UUID
    short_name: str
    full_name: str
    active: bool
    shots: int
    consumed_cents: int
    paid_cents: int

    @property
    def balance_cents(self) -> int:
        return self.consumed_cents - self.paid_cents


@dataclass(frozen=True)
class EventRow:
    id: uuid.UUID
    created_at: datetime
    user_id: uuid.UUID
    user_name: str
    chair_short: str
    kind: str  # consumption type, or "payment" / "correction"
    quantity: int | None
    amount_cents: int
    note: str | None


@dataclass
class Dashboard:
    totals: Totals
    today: PeriodTotals
    week: PeriodTotals
    month: PeriodTotals
    per_chair: list[ChairTotals]
    current_price: Price | None
    prices: list[Price]
    recent_consumption: list[EventRow]
    recent_payments: list[EventRow]


def _consumption_sums(db: Session, visible, start=None, end=None) -> tuple[int, int]:
    ce = ConsumptionEvent
    q = select(func.coalesce(func.sum(ce.quantity), 0), func.coalesce(func.sum(ce.amount_cents), 0))
    clauses = _where(_scope_user_ids(visible, ce.user_id),
                     ce.created_at >= start if start is not None else None,
                     ce.created_at < end if end is not None else None)
    shots, amount = db.execute(q.where(*clauses)).one()
    return int(shots), int(amount)


def _payment_sum(db: Session, visible, start=None, end=None) -> int:
    pe = PaymentEvent
    clauses = _where(_scope_user_ids(visible, pe.user_id),
                     pe.created_at >= start if start is not None else None,
                     pe.created_at < end if end is not None else None)
    return int(db.scalar(select(func.coalesce(func.sum(pe.amount_cents), 0)).where(*clauses)))


def _period(db: Session, visible, bounds: tuple[datetime, datetime]) -> PeriodTotals:
    shots, amount = _consumption_sums(db, visible, *bounds)
    return PeriodTotals(shots, amount, _payment_sum(db, visible, *bounds))


def _per_chair(db: Session, visible) -> list[ChairTotals]:
    ce, pe = ConsumptionEvent, PaymentEvent
    cons = {
        row.chair_id: (int(row.shots), int(row.amount))
        for row in db.execute(
            select(ce.chair_id, func.sum(ce.quantity).label("shots"), func.sum(ce.amount_cents).label("amount"))
            .where(*_where(_scope_user_ids(visible, ce.user_id))).group_by(ce.chair_id))
    }
    paid = {
        row.chair_id: int(row.amount)
        for row in db.execute(
            select(pe.chair_id, func.sum(pe.amount_cents).label("amount"))
            .where(*_where(_scope_user_ids(visible, pe.user_id))).group_by(pe.chair_id))
    }
    out = []
    for chair in db.scalars(select(Chair).order_by(Chair.short_name)):
        if visible is not None and chair.id not in visible:
            continue  # a chair admin never sees groups of chairs outside their scope
        shots, amount = cons.get(chair.id, (0, 0))
        pay = paid.get(chair.id, 0)
        if chair.active or shots or amount or pay:
            out.append(ChairTotals(chair.id, chair.short_name, chair.full_name, chair.active, shots, amount, pay))
    return out


def _recent_consumption(db: Session, visible, limit: int) -> list[EventRow]:
    ce = ConsumptionEvent
    rows = db.execute(
        select(ce, User.display_name, Chair.short_name)
        .join(User, User.id == ce.user_id).join(Chair, Chair.id == ce.chair_id)
        .where(*_where(_scope_user_ids(visible, ce.user_id)))
        .order_by(ce.created_at.desc(), ce.id).limit(limit))
    return [EventRow(e.id, e.created_at, e.user_id, name, chair, e.type, e.quantity, e.amount_cents, e.note)
            for e, name, chair in rows]


def _recent_payments(db: Session, visible, limit: int) -> list[EventRow]:
    pe = PaymentEvent
    rows = db.execute(
        select(pe, User.display_name, Chair.short_name)
        .join(User, User.id == pe.user_id).join(Chair, Chair.id == pe.chair_id)
        .where(*_where(_scope_user_ids(visible, pe.user_id)))
        .order_by(pe.created_at.desc(), pe.id).limit(limit))
    return [EventRow(p.id, p.created_at, p.user_id, name, chair,
                     "correction" if p.correction_of_id else ("bookkeeping" if p.kind == "bookkeeping" else "payment"), None, p.amount_cents, p.note)
            for p, name, chair in rows]


def dashboard(db: Session, admin: AdminUser, now: datetime | None = None) -> Dashboard:
    now = ensure_utc(now) if now is not None else utcnow()
    visible = authz.visible_chair_ids(db, admin)
    shots, amount = _consumption_sums(db, visible)
    paid = _payment_sum(db, visible)
    return Dashboard(
        totals=Totals(shots, amount, paid, amount - paid),
        today=_period(db, visible, local_day_bounds(now)),
        week=_period(db, visible, local_week_bounds(now)),
        month=_period(db, visible, local_month_bounds(now)),
        per_chair=_per_chair(db, visible),
        current_price=get_price_in_effect(db, now),
        prices=list_prices(db)[:5],
        recent_consumption=_recent_consumption(db, visible, RECENT_LIMIT),
        recent_payments=_recent_payments(db, visible, RECENT_LIMIT),
    )


@dataclass(frozen=True)
class HeadTiles:
    """Dashboard additions only the head admin sees: money held by group admins and the mail status."""

    held_by_groups_cents: int
    mail: mail_status.MailCard


def head_tiles(db: Session, admin: AdminUser) -> HeadTiles:
    authz.require_global(admin)
    held = sum(row.held_cents for row in groups.list_group_balances(db))
    return HeadTiles(held_by_groups_cents=held, mail=mail_status.card(db))


# ----- user table -----------------------------------------------------------------------------
@dataclass(frozen=True)
class UserRow:
    id: uuid.UUID
    display_name: str
    chair_id: uuid.UUID
    chair_short: str
    shots: int
    consumed_cents: int
    paid_cents: int
    balance_cents: int
    last_activity_at: datetime | None
    status: str


@dataclass
class UserPage:
    rows: list[UserRow]
    total: int
    page: int
    pages: int
    page_size: int
    sort: str
    direction: str


def _user_filters(db: Session, admin: AdminUser, q: str | None, chair_id: uuid.UUID | None, status: str | None):
    visible = authz.visible_chair_ids(db, admin)
    check_chair_filter(db, admin, chair_id)
    clauses = [User.status != "merged"]
    if visible is not None:
        clauses.append(User.chair_id.in_(visible))
    if chair_id is not None:
        clauses.append(User.chair_id == chair_id)
    if status in STATUS_FILTERS:
        clauses.append(User.status == status)
    needle = _fold(normalize_name(q or ""))[:120]
    if needle:
        clauses.append(_fold_sql(User.normalized_name).like(f"%{_escape_like(needle)}%", escape="\\"))
    return clauses


def list_users(
    db: Session, admin: AdminUser, *, q: str | None = None, chair_id: uuid.UUID | None = None,
    status: str | None = None, sort: str = "balance", direction: str | None = None, page: int = 1,
    page_size: int | None = DEFAULT_PAGE_SIZE,
) -> UserPage:
    """One row per (non-merged) profile with totals that include profiles merged into it.

    `page_size=None` returns everything (used by the CSV export).
    """
    sort = sort if sort in SORTS else "balance"
    direction = direction if direction in ("asc", "desc") else DEFAULT_DIRECTION[sort]
    clauses = _user_filters(db, admin, q, chair_id, status)
    total = db.scalar(select(func.count()).select_from(User).where(*clauses))

    ce, pe, eu = ConsumptionEvent, PaymentEvent, effective_users
    cons = (select(eu.c.effective_id.label("uid"), func.sum(ce.quantity).label("shots"),
                   func.sum(ce.amount_cents).label("amount"))
            .join_from(ce, eu, eu.c.id == ce.user_id).group_by(eu.c.effective_id).subquery())
    paid = (select(eu.c.effective_id.label("uid"), func.sum(pe.amount_cents).label("amount"))
            .join_from(pe, eu, eu.c.id == pe.user_id).group_by(eu.c.effective_id).subquery())
    shots = func.coalesce(cons.c.shots, 0)
    consumed = func.coalesce(cons.c.amount, 0)
    paid_amount = func.coalesce(paid.c.amount, 0)
    balance = consumed - paid_amount

    stmt = (
        select(User.id, User.display_name, User.chair_id, Chair.short_name, shots, consumed, paid_amount, balance,
               User.last_activity_at, User.status)
        .join(Chair, Chair.id == User.chair_id)
        .outerjoin(cons, cons.c.uid == User.id).outerjoin(paid, paid.c.uid == User.id)
        .where(*clauses)
    )
    desc = direction == "desc"

    def _d(col):
        return col.desc() if desc else col.asc()

    if sort == "balance":
        keys = [_d(balance), User.normalized_name]
    elif sort == "name":
        keys = [_d(User.normalized_name), User.display_name]
    elif sort == "consumption":
        keys = [_d(consumed), _d(shots), User.normalized_name]
    else:  # activity: profiles without any activity always come last
        keys = [User.last_activity_at.is_(None), _d(User.last_activity_at), User.normalized_name]
    stmt = stmt.order_by(*keys, User.id)

    size = None if page_size is None else max(1, min(int(page_size), MAX_PAGE_SIZE))
    pages = 1 if size is None else max(1, -(-total // size))
    page = max(1, min(int(page or 1), pages))
    if size is not None:
        stmt = stmt.limit(size).offset((page - 1) * size)
    rows = [UserRow(*r) for r in db.execute(stmt)]
    return UserPage(rows, total, page, pages, size or total, sort, direction)


# ----- user detail ----------------------------------------------------------------------------
@dataclass(frozen=True)
class ConsumptionRow:
    event: ConsumptionEvent
    chair_short: str
    admin_name: str | None
    reversed: bool
    can_reverse: bool


@dataclass(frozen=True)
class PaymentRow:
    payment: PaymentEvent
    chair_short: str
    admin_name: str | None
    corrected: bool
    collector_name: str | None = None  # group admin / admin who collected the cash (admin-only view)


@dataclass(frozen=True)
class AuditRow:
    id: int
    created_at: datetime
    actor: str
    action: str
    target_type: str | None
    target_id: str | None
    details: str
    source_ip: str | None


@dataclass
class UserDetail:
    user: User
    totals: Totals
    consumption: list[ConsumptionRow]
    payments: list[PaymentRow]
    audit: list[AuditRow]
    active_sessions: int
    merged_profiles: list[User] = field(default_factory=list)
    current_price: Price | None = None


def _admin_names(db: Session, ids) -> dict[str, str]:
    ids = {uuid.UUID(str(i)) for i in ids if i}
    if not ids:
        return {}
    return {str(a.id): authz.admin_label(a) for a in db.scalars(select(AdminUser).where(AdminUser.id.in_(ids)))}


def _collector_names(db: Session, ids) -> dict[str, str]:
    """Collector shown to admins: the linked member's name for a group admin, else the admin username."""
    return _admin_names(db, ids)


def _details(meta: dict | None) -> str:
    if not meta:
        return ""
    return ", ".join(f"{k}={v}" for k, v in meta.items())


def audit_rows(db: Session, entries) -> list[AuditRow]:
    entries = list(entries)
    names = _admin_names(db, [e.actor_id for e in entries if e.actor_type == "admin"])
    out = []
    for e in entries:
        actor = names.get(e.actor_id, "admin") if e.actor_type == "admin" else e.actor_type
        out.append(AuditRow(e.id, e.created_at, actor, e.action, e.target_type, e.target_id, _details(e.meta),
                            e.source_ip))
    return out


def user_detail(db: Session, admin: AdminUser, user_id: uuid.UUID) -> UserDetail:
    """Complete history of a profile (and of profiles merged into it). Scope-checked."""
    authz.ensure_admin_can_access_user(db, admin, user_id)
    user = db.get(User, user_id)
    members = list(db.scalars(member_ids_select(user_id)))
    consumption = ledger.recent_consumption(db, user_id, limit=None)
    payments = ledger.recent_payments(db, user_id, limit=None)
    reversed_set = ledger.reversed_ids(db, [e.id for e in consumption])
    corrected = set(db.scalars(select(PaymentEvent.correction_of_id).where(
        PaymentEvent.correction_of_id.in_([p.id for p in payments])))) if payments else set()
    chairs = {c.id: c.short_name for c in db.scalars(select(Chair))}
    names = _admin_names(db, [e.admin_id for e in consumption] + [p.admin_id for p in payments])
    collectors = _collector_names(db, [p.collector_admin_id for p in payments])

    entries = db.scalars(
        select(AuditLog).where(or_(
            (AuditLog.target_type == "user") & AuditLog.target_id.in_([str(m) for m in members]),
            (AuditLog.target_type == "consumption_event") & AuditLog.target_id.in_([str(e.id) for e in consumption]),
        )).order_by(AuditLog.id.desc()).limit(USER_AUDIT_LIMIT))
    merged = list(db.scalars(select(User).where(User.id.in_(members), User.id != user_id).order_by(User.display_name)))
    return UserDetail(
        user=user,
        totals=ledger.get_totals(db, user_id),
        consumption=[ConsumptionRow(e, chairs.get(e.chair_id, "?"), names.get(str(e.admin_id)) if e.admin_id else None,
                                    e.id in reversed_set,
                                    e.type != "reversal" and e.quantity > 0 and e.id not in reversed_set)
                     for e in consumption],
        payments=[PaymentRow(p, chairs.get(p.chair_id, "?"), names.get(str(p.admin_id)), p.id in corrected,
                              collectors.get(str(p.collector_admin_id)) if p.collector_admin_id else None)
                  for p in payments],
        audit=audit_rows(db, entries),
        active_sessions=sessions.active_session_count(db, user_id),
        merged_profiles=merged,
        current_price=get_price_in_effect(db),
    )


def merge_candidates(db: Session, duplicate_id: uuid.UUID, q: str | None, limit: int = 30) -> list[User]:
    """Active/inactive, non-merged profiles other than `duplicate_id` matching `q` (global admins only)."""
    needle = _fold(normalize_name(q or ""))[:120]
    stmt = select(User).join(Chair, Chair.id == User.chair_id).where(User.status != "merged", User.id != duplicate_id)
    if needle:
        stmt = stmt.where(_fold_sql(User.normalized_name).like(f"%{_escape_like(needle)}%", escape="\\"))
    return list(db.scalars(stmt.order_by(User.normalized_name, Chair.short_name).limit(limit)))


def effective_target(db: Session, user_id: uuid.UUID) -> uuid.UUID:
    return effective_user_id(db, user_id) or user_id


# ----- audit view (global admins) -------------------------------------------------------------
@dataclass
class AuditPage:
    rows: list[AuditRow]
    total: int
    page: int
    pages: int


def audit_page(db: Session, admin: AdminUser, *, action: str | None = None, page: int = 1,
               page_size: int = AUDIT_PAGE_SIZE) -> AuditPage:
    authz.require_global(admin)
    clauses = []
    action = (action or "").strip()[:64]
    if action:
        clauses.append(AuditLog.action.like(f"{_escape_like(action)}%", escape="\\"))
    total = db.scalar(select(func.count()).select_from(AuditLog).where(*clauses))
    pages = max(1, -(-total // page_size))
    page = max(1, min(int(page or 1), pages))
    entries = db.scalars(select(AuditLog).where(*clauses).order_by(AuditLog.id.desc())
                         .limit(page_size).offset((page - 1) * page_size))
    return AuditPage(audit_rows(db, entries), total, page, pages)

