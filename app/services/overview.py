"""Read-only queries for the open website (`/overview*`, PLAN-v2 sections 0 A10/A11 and 3).

Everything here is derived from the ledger and returns frozen dataclasses that hold ONLY what
the open site may show: display names, chair names, shot counts, prices, amounts, dates and
balances. Nothing in this module selects an email, username, password hash, session, audit
entry, IP address, note, or the admin who recorded an entry (A10).

Rules:
- Totals follow the *effective* user (`effective_users` view): events of merged profiles count
  for the profile they were merged into, and merged profiles are never listed.
- Deactivated users are hidden unless their balance is non-zero; then they are listed with
  `inactive=True`.
- Month bounds come from `app.timeutil` (LOCAL_TIMEZONE calendar months, half-open).
- Sign convention (A11): internally `balance = consumed - paid`, positive means the person
  owes. Displayed wording never contains a minus sign: see `balance_label` / `balance_words`.
- Page-level functions run a small, fixed number of grouped statements (no per-user queries).

Services never commit; these functions only read.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import NamedTuple

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.orm import Session

from app.models import AdminUser, Chair, ConsumptionEvent, PaymentEvent, Price, User, effective_users
from app.money import format_money
from app.services import groups
from app.services.errors import NotFound
from app.services.prices import get_price_in_effect
from app.services.users import _escape_like, _fold, _fold_sql, normalize_name
from app.timeutil import ensure_utc, local_month_bounds, to_local, utcnow

PEOPLE_SORTS = ("name", "balance", "shots_month", "shots_total")
DEFAULT_PER_PAGE = 50
MAX_PER_PAGE = 200
TREND_MONTHS = 12
MAX_QUERY_LENGTH = 120

BALANCE_STATES = ("owes", "credit", "even")


# ----- balance wording (A11) ----------------------------------------------------------------
def balance_label(cents: int) -> tuple[str, int]:
    """`(state, amount_cents)` for an internal balance (positive = owes). The amount is never
    negative: state "owes" (amount > 0), "credit" (amount > 0) or "even" (amount 0)."""
    cents = int(cents)
    if cents > 0:
        return "owes", cents
    if cents < 0:
        return "credit", -cents
    return "even", 0


def balance_words(cents: int) -> str:
    """Neutral display wording for someone's balance: "Owes €3.50", "Credit €2.00", "Even".

    Never contains a minus sign. English fallback text: the route layer may format
    `balance_label` itself with `t()` keys instead.
    """
    state, amount = balance_label(cents)
    if state == "owes":
        return f"Owes {format_money(amount)}"
    if state == "credit":
        return f"Credit {format_money(amount)}"
    return "Even"


# ----- result types -------------------------------------------------------------------------
class MonthPoint(NamedTuple):
    label: str  # "YYYY-MM" (LOCAL_TIMEZONE calendar month)
    shots: int
    amount_cents: int


@dataclass(frozen=True)
class ChairSummary:
    chair_id: uuid.UUID
    name: str  # short name
    full_name: str
    members: int
    shots: int
    consumed_cents: int
    paid_cents: int
    owed_cents: int
    credit_cents: int


@dataclass(frozen=True)
class SiteTotals:
    total_shots: int
    consumed_cents: int
    paid_cents: int
    owed_total_cents: int
    credit_total_cents: int
    current_price_cents: int | None
    month_shots: int
    month_amount_cents: int
    trend: tuple[MonthPoint, ...]  # oldest first, the last entry is the current month
    chairs: tuple[ChairSummary, ...]


@dataclass(frozen=True)
class PersonRow:
    id: uuid.UUID
    display_name: str  # with a " (2)" style suffix when two visible accounts share the name
    chair_id: uuid.UUID
    chair_name: str  # short name
    shots_month: int
    shots_total: int
    balance_cents: int  # internal sign: positive = owes
    inactive: bool

    @property
    def balance_label(self) -> tuple[str, int]:
        return balance_label(self.balance_cents)

    @property
    def balance_words(self) -> str:
        return balance_words(self.balance_cents)


@dataclass(frozen=True)
class PeoplePage:
    rows: tuple[PersonRow, ...]
    total: int
    page: int
    pages: int
    per_page: int
    sort: str
    query: str
    chair_id: uuid.UUID | None


@dataclass(frozen=True)
class HistoryConsumption:
    date: datetime  # UTC
    shots: int  # negative for a reversal
    unit_price_cents: int
    amount_cents: int  # negative for a reversal
    is_reversal: bool
    is_reversed: bool  # an original entry that a later reversal cancelled


@dataclass(frozen=True)
class HistoryPayment:
    date: datetime  # UTC
    amount_cents: int  # negative: money paid back


@dataclass(frozen=True)
class PersonHistory:
    id: uuid.UUID
    display_name: str
    chair_id: uuid.UUID
    chair_name: str
    inactive: bool
    shots_month: int
    shots_total: int
    consumed_cents: int
    paid_cents: int
    balance_cents: int
    consumption: tuple[HistoryConsumption, ...]  # newest first
    payments: tuple[HistoryPayment, ...]  # newest first

    @property
    def balance_label(self) -> tuple[str, int]:
        return balance_label(self.balance_cents)

    @property
    def balance_words(self) -> str:
        return balance_words(self.balance_cents)


@dataclass(frozen=True)
class ChairOverview:
    chair_id: uuid.UUID
    name: str  # short name
    full_name: str
    members: int
    group_admins: tuple[str, ...]  # display names of current group admins
    owed_cents: int
    credit_cents: int
    collected_cents: int
    handed_over_cents: int
    held_cents: int


@dataclass(frozen=True)
class PricePoint:
    effective_from: datetime  # UTC
    price_per_shot_cents: int


# ----- shared building blocks ---------------------------------------------------------------
def _now(now: datetime | None) -> datetime:
    return ensure_utc(now) if now is not None else utcnow()


def _base(now: datetime):
    """One row per non-merged user with ledger totals of everything merged into it."""
    eu, ce, pe = effective_users, ConsumptionEvent, PaymentEvent
    start, end = local_month_bounds(now)
    in_month = case((and_(ce.created_at >= start, ce.created_at < end), ce.quantity), else_=0)
    cons = (
        select(eu.c.effective_id.label("uid"), func.sum(ce.quantity).label("shots"),
               func.sum(ce.amount_cents).label("amount"), func.sum(in_month).label("month_shots"))
        .join_from(ce, eu, eu.c.id == ce.user_id)
        .group_by(eu.c.effective_id)
        .subquery()
    )
    paid = (
        select(eu.c.effective_id.label("uid"), func.sum(pe.amount_cents).label("amount"))
        .join_from(pe, eu, eu.c.id == pe.user_id)
        .group_by(eu.c.effective_id)
        .subquery()
    )
    shots = func.coalesce(cons.c.shots, 0)
    consumed = func.coalesce(cons.c.amount, 0)
    paid_amount = func.coalesce(paid.c.amount, 0)
    return (
        select(
            User.id.label("id"), User.display_name.label("display_name"),
            User.normalized_name.label("normalized_name"), User.status.label("status"),
            User.created_at.label("created_at"), User.chair_id.label("chair_id"),
            Chair.short_name.label("chair_name"), Chair.full_name.label("chair_full_name"),
            shots.label("shots"), func.coalesce(cons.c.month_shots, 0).label("month_shots"),
            consumed.label("consumed"), paid_amount.label("paid"), (consumed - paid_amount).label("balance"),
        )
        .join(Chair, Chair.id == User.chair_id)
        .outerjoin(cons, cons.c.uid == User.id)
        .outerjoin(paid, paid.c.uid == User.id)
        .where(User.status != "merged")
        .subquery()
    )


def _is_visible(b):
    return or_(b.c.status == "active", b.c.balance != 0)


def _visible_ranked(base):
    """Visible accounts plus `rn`: 1-based rank among visible accounts sharing a normalized name."""
    rn = func.row_number().over(
        partition_by=base.c.normalized_name, order_by=(base.c.created_at, base.c.id)
    ).label("rn")
    return select(base, rn).where(_is_visible(base)).subquery()


def _name(display_name: str, rn: int) -> str:
    return display_name if rn <= 1 else f"{display_name} ({rn})"


def _person(r) -> PersonRow:
    return PersonRow(
        id=r.id, display_name=_name(r.display_name, r.rn), chair_id=r.chair_id, chair_name=r.chair_name,
        shots_month=int(r.month_shots), shots_total=int(r.shots), balance_cents=int(r.balance),
        inactive=r.status != "active",
    )


def _month_starts(now: datetime, months: int) -> list[tuple[datetime, datetime]]:
    """Bounds of the last `months` local calendar months, oldest first, ending with the current one."""
    start, end = local_month_bounds(now)
    out = [(start, end)]
    for _ in range(months - 1):
        start, end = local_month_bounds(start - timedelta(hours=1))  # last local hour of the previous month
        out.append((start, end))
    out.reverse()
    return out


# ----- site totals --------------------------------------------------------------------------
def _chair_summaries(db: Session, now: datetime) -> tuple[ChairSummary, ...]:
    b = _base(now)
    owed = func.coalesce(func.sum(case((b.c.balance > 0, b.c.balance), else_=0)), 0)
    credit = func.coalesce(func.sum(case((b.c.balance < 0, -b.c.balance), else_=0)), 0)
    chair_rows = db.execute(
        select(
            Chair.id, Chair.short_name, Chair.full_name, Chair.active,
            func.coalesce(func.sum(case((_is_visible(b), 1), else_=0)), 0),
            func.coalesce(func.sum(b.c.shots), 0), func.coalesce(func.sum(b.c.consumed), 0),
            func.coalesce(func.sum(b.c.paid), 0), owed, credit,
        )
        .select_from(Chair).outerjoin(b, b.c.chair_id == Chair.id)
        .group_by(Chair.id, Chair.short_name, Chair.full_name, Chair.active)
        .order_by(func.lower(Chair.short_name), Chair.id)
    ).all()
    return tuple(
        ChairSummary(cid, short, full, int(members), int(shots), int(consumed), int(paid), int(o), int(c))
        for cid, short, full, active, members, shots, consumed, paid, o, c in chair_rows
        if active or members or shots or consumed or paid
    )


def site_totals(db: Session, now: datetime | None = None) -> SiteTotals:
    now = _now(now)
    chairs = _chair_summaries(db, now)
    bounds = _month_starts(now, TREND_MONTHS)
    ce = ConsumptionEvent
    cols = []
    for start, end in bounds:
        in_month = and_(ce.created_at >= start, ce.created_at < end)
        cols.append(func.coalesce(func.sum(case((in_month, ce.quantity), else_=0)), 0))
        cols.append(func.coalesce(func.sum(case((in_month, ce.amount_cents), else_=0)), 0))
    values = db.execute(
        select(*cols).where(ce.created_at >= bounds[0][0], ce.created_at < bounds[-1][1])
    ).one()
    trend = tuple(
        MonthPoint(to_local(start).strftime("%Y-%m"), int(values[2 * i]), int(values[2 * i + 1]))
        for i, (start, _end) in enumerate(bounds)
    )

    price = get_price_in_effect(db, now)
    return SiteTotals(
        total_shots=sum(c.shots for c in chairs),
        consumed_cents=sum(c.consumed_cents for c in chairs),
        paid_cents=sum(c.paid_cents for c in chairs),
        owed_total_cents=sum(c.owed_cents for c in chairs),
        credit_total_cents=sum(c.credit_cents for c in chairs),
        current_price_cents=int(price.price_per_shot_cents) if price is not None else None,
        month_shots=trend[-1].shots,
        month_amount_cents=trend[-1].amount_cents,
        trend=trend,
        chairs=chairs,
    )


def chair_choices(db: Session, now: datetime | None = None) -> tuple[tuple[uuid.UUID, str], ...]:
    """`(chair_id, short name)` of every chair listed on the site (the chair filter's options), by name."""
    return tuple((c.chair_id, c.name) for c in _chair_summaries(db, _now(now)))


# ----- people -------------------------------------------------------------------------------
def people(
    db: Session, *, query: str | None = None, chair_id: uuid.UUID | None = None, sort: str = "name",
    page: int = 1, per_page: int = DEFAULT_PER_PAGE, now: datetime | None = None,
) -> PeoplePage:
    """Visible accounts, filtered by name search and chair, sorted and paginated.

    Search uses `users.normalize_name` folding ("muller" and "mueller" find "Müller"). The
    " (2)" suffix is decided among ALL visible accounts, so it does not change with filters
    or pages. Sorts: name (A-Z), balance (most owed first), shots_month and shots_total
    (highest first); ties fall back to the name.
    """
    now = _now(now)
    sort = sort if sort in PEOPLE_SORTS else "name"
    v = _visible_ranked(_base(now))
    clauses = []
    needle = _fold(normalize_name(query or ""))[:MAX_QUERY_LENGTH]
    if needle:
        clauses.append(_fold_sql(v.c.normalized_name).like(f"%{_escape_like(needle)}%", escape="\\"))
    if chair_id is not None:
        clauses.append(v.c.chair_id == chair_id)

    total = int(db.scalar(select(func.count()).select_from(v).where(*clauses)))
    size = max(1, min(int(per_page or DEFAULT_PER_PAGE), MAX_PER_PAGE))
    pages = max(1, -(-total // size))
    page = max(1, min(int(page or 1), pages))

    by_name = [v.c.normalized_name, v.c.created_at, v.c.id]
    keys = {
        "name": by_name,
        "balance": [v.c.balance.desc(), *by_name],
        "shots_month": [v.c.month_shots.desc(), *by_name],
        "shots_total": [v.c.shots.desc(), *by_name],
    }[sort]
    rows = db.execute(select(v).where(*clauses).order_by(*keys).limit(size).offset((page - 1) * size)).all()
    return PeoplePage(
        rows=tuple(_person(r) for r in rows), total=total, page=page, pages=pages, per_page=size, sort=sort,
        query=(query or "").strip()[:MAX_QUERY_LENGTH], chair_id=chair_id,
    )


# ----- one person ---------------------------------------------------------------------------
def person_history(db: Session, user_id: uuid.UUID, now: datetime | None = None) -> PersonHistory:
    """Complete consumption and payment history of one visible account. A merged profile id
    resolves to the profile it was merged into (check `.id`); raises `NotFound` for unknown or
    hidden (deactivated with zero balance) accounts."""
    eff = db.scalar(select(effective_users.c.effective_id).where(effective_users.c.id == user_id))
    if eff is None:
        raise NotFound("person not found")
    v = _visible_ranked(_base(_now(now)))
    r = db.execute(select(v).where(v.c.id == eff)).first()
    if r is None:
        raise NotFound("person not found")

    members = select(effective_users.c.id).where(effective_users.c.effective_id == eff)
    ce, pe = ConsumptionEvent, PaymentEvent
    # Only date, quantity, prices, amounts and the reversal link are selected; never notes or admins.
    cons_rows = db.execute(
        select(ce.id, ce.created_at, ce.quantity, ce.unit_price_cents, ce.amount_cents, ce.type, ce.reversal_of_id)
        .where(ce.user_id.in_(members)).order_by(ce.created_at.desc(), ce.id.desc())
    ).all()
    reversed_ids = {c.reversal_of_id for c in cons_rows if c.reversal_of_id is not None}
    consumption = tuple(
        HistoryConsumption(
            date=ensure_utc(c.created_at), shots=int(c.quantity), unit_price_cents=int(c.unit_price_cents),
            amount_cents=int(c.amount_cents), is_reversal=c.type == "reversal", is_reversed=c.id in reversed_ids,
        )
        for c in cons_rows
    )
    pay_rows = db.execute(
        select(pe.created_at, pe.amount_cents).where(pe.user_id.in_(members)).order_by(pe.created_at.desc(), pe.id.desc())
    ).all()
    payments = tuple(HistoryPayment(date=ensure_utc(p.created_at), amount_cents=int(p.amount_cents)) for p in pay_rows)
    return PersonHistory(
        id=r.id, display_name=_name(r.display_name, r.rn), chair_id=r.chair_id, chair_name=r.chair_name,
        inactive=r.status != "active", shots_month=int(r.month_shots), shots_total=int(r.shots),
        consumed_cents=int(r.consumed), paid_cents=int(r.paid), balance_cents=int(r.balance),
        consumption=consumption, payments=payments,
    )


def can_edit_balance(db: Session, viewer_user_id: uuid.UUID, person: PersonHistory) -> bool:
    """Whether the signed-in ACCOUNT `viewer_user_id` is linked to an active group admin (role chair) of the
    person's own chair, so the person page may offer the "Edit balance" link. Nobody gets the link on their
    own page (the ledger refuses own-account postings). Head admins have no user account and use /admin."""
    if viewer_user_id == person.id:
        return False
    row = db.execute(
        select(AdminUser.id, User.chair_id).join(User, User.id == AdminUser.user_id)
        .where(AdminUser.user_id == viewer_user_id, AdminUser.role == "chair", AdminUser.active.is_(True))
    ).first()
    return row is not None and row.chair_id == person.chair_id


# ----- chairs -------------------------------------------------------------------------------
def chairs_overview(db: Session, now: datetime | None = None) -> tuple[ChairOverview, ...]:
    """Per chair: members, current group admins, owed and credit totals and the group money
    (collected / handed over / still held, from `groups.chair_rollup`)."""
    summaries = {c.chair_id: c for c in _chair_summaries(db, _now(now))}
    rollup = {row.chair_id: row for row in groups.chair_rollup(db)}
    names: dict[uuid.UUID, list[str]] = {}
    for cid, display_name in db.execute(
        select(User.chair_id, User.display_name)
        .join(AdminUser, AdminUser.user_id == User.id)
        .where(AdminUser.role == "chair", AdminUser.active.is_(True))
    ):
        names.setdefault(cid, []).append(display_name)

    chair_meta = {cid: (short, full) for cid, short, full in db.execute(select(Chair.id, Chair.short_name, Chair.full_name))}
    out = []
    for cid in set(summaries) | set(rollup) | set(names):
        s, g = summaries.get(cid), rollup.get(cid)
        short, full = chair_meta[cid]
        out.append(ChairOverview(
            chair_id=cid, name=short, full_name=full, members=s.members if s else 0,
            group_admins=tuple(sorted(names.get(cid, []), key=lambda n: (normalize_name(n), n))),
            owed_cents=s.owed_cents if s else 0, credit_cents=s.credit_cents if s else 0,
            collected_cents=g.collected_cents if g else 0, handed_over_cents=g.remitted_cents if g else 0,
            held_cents=g.held_cents if g else 0,
        ))
    out.sort(key=lambda c: (c.name.casefold(), str(c.chair_id)))
    return tuple(out)


# ----- prices -------------------------------------------------------------------------------
def price_history(db: Session) -> tuple[PricePoint, ...]:
    """All prices, newest `effective_from` first (notes and recording admins are not selected)."""
    rows = db.execute(
        select(Price.effective_from, Price.price_per_shot_cents).order_by(Price.effective_from.desc())
    ).all()
    return tuple(PricePoint(ensure_utc(r.effective_from), int(r.price_per_shot_cents)) for r in rows)
