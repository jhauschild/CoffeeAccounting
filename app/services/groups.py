"""Group money: what each group admin collected, handed over and still holds.

Derived from the ledger, never stored (V2-CONTRACT "Derived values"):

- `collected(admin)` = SUM of cash payment amounts the admin collected (`kind = 'cash'`,
  `collector_admin_id = admin`). A negative cash payment (money paid back) reduces it;
  bookkeeping payments (set balance) never count.
- `held(admin)` = `collected(admin)` - SUM of the admin's remittances (signed).
- Chair roll-up: collected grouped by `payment_events.chair_id`, remittances by
  `group_remittances.chair_id` (the chair at event time), only for collectors with role
  `chair` (group admin). A demoted group admin keeps role `chair` and becomes inactive, so
  someone who has any collection or remittance event stays listed (`is_current=False`), even
  with nothing held, so old remittances can still be found and corrected.

Authoritative figure (decision L-3): `held(admin)` per group admin (collected minus remitted of
that admin) is THE number a head admin relies on. A remittance records `chair_id` = the chair of
the group admin's linked user at event time (a correction keeps the chair of its original). The
per-chair roll-up is therefore informational: if a group admin's profile is moved to another
chair and the role is later restored, new remittances carry the new chair while earlier
collections carry the old one, and the per-chair rows may show remitted cash against a chair
that did not collect it. `held` per admin and `check-ledger` stay correct regardless.

Paid-back flag (M-1): `over_credit_paybacks` lists negative cash payments (not corrections) that
exceeded the person's credit at the time they were booked. Group admins can no longer book
those (`ledger.add_payment`); a head admin may, and every such entry is flagged.

Services never commit; the caller owns the transaction.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import AdminUser, Chair, ConsumptionEvent, GroupRemittance, PaymentEvent, User
from app.services import audit
from app.services.authz import admin_label, require_global
from app.services.errors import Conflict, InvalidAmount, InvalidInput, NotFound
from app.services.prices import clean_note
from app.services.users import effective_user_id, member_ids_select
from app.timeutil import ensure_utc, utcnow

MAX_AMOUNT_CENTS = 1_000_000_00
MAX_KEY_LENGTH = 80


@dataclass(frozen=True)
class GroupBalanceRow:
    """One group admin (current or former) with money figures in cents."""

    admin_id: uuid.UUID
    username: str
    display_name: str | None  # linked member's display name
    chair_id: uuid.UUID | None  # chair of the linked member today
    chair_short_name: str | None
    collected_cents: int
    remitted_cents: int
    held_cents: int
    is_current: bool  # False: demoted (role chair, inactive): a former group admin with group money history
    negative: bool  # held < 0: more handed over than collected


@dataclass(frozen=True)
class ChairRollupRow:
    chair_id: uuid.UUID
    chair_short_name: str
    chair_full_name: str
    collected_cents: int
    remitted_cents: int
    held_cents: int
    negative: bool


@dataclass(frozen=True)
class OverCreditPayback:
    """A negative cash payment larger than the person's credit when it was booked."""

    payment_id: uuid.UUID
    user_id: uuid.UUID
    user_name: str  # display name of the person paid back (admin-only views)
    amount_cents: int  # magnitude paid back
    credit_cents: int  # credit just before it (never negative)
    collector_admin_id: uuid.UUID | None
    collector_name: str
    created_at: datetime


def over_credit_paybacks(db: Session) -> list[OverCreditPayback]:
    """Every negative cash payment (corrections excluded) that exceeded the effective user's credit at the
    time it was booked, oldest first. Credit then = payments booked before it (same or earlier time, the
    payment itself excluded) minus consumption up to that time, over the effective user's profiles as merged
    today. Both group admins (blocked by `ledger.add_payment` today, so only legacy or direct rows) and
    head admins (allowed) can appear."""
    pays = list(db.scalars(
        select(PaymentEvent).where(PaymentEvent.kind == "cash", PaymentEvent.amount_cents < 0,
                                   PaymentEvent.correction_of_id.is_(None))
        .order_by(PaymentEvent.created_at, PaymentEvent.id)))
    out = []
    for p in pays:
        members = member_ids_select(effective_user_id(db, p.user_id) or p.user_id)
        paid = db.scalar(select(func.coalesce(func.sum(PaymentEvent.amount_cents), 0)).where(
            PaymentEvent.user_id.in_(members), PaymentEvent.created_at <= p.created_at, PaymentEvent.id != p.id))
        consumed = db.scalar(select(func.coalesce(func.sum(ConsumptionEvent.amount_cents), 0)).where(
            ConsumptionEvent.user_id.in_(members), ConsumptionEvent.created_at <= p.created_at))
        credit = max(0, int(paid) - int(consumed))
        if -p.amount_cents > credit:
            collector = db.get(AdminUser, p.collector_admin_id) if p.collector_admin_id else None
            person = db.get(User, p.user_id)
            out.append(OverCreditPayback(p.id, p.user_id, person.display_name if person else "?",
                                         -p.amount_cents, credit, p.collector_admin_id,
                                         admin_label(collector) if collector is not None else "?", p.created_at))
    return out


def _cash_collected_query():
    return select(func.coalesce(func.sum(PaymentEvent.amount_cents), 0)).where(PaymentEvent.kind == "cash")


def collected(db: Session, admin_id: uuid.UUID) -> int:
    """Cash this admin collected, in cents (negative cash payments reduce it)."""
    return int(db.scalar(_cash_collected_query().where(PaymentEvent.collector_admin_id == admin_id)))


def remitted(db: Session, admin_id: uuid.UUID) -> int:
    """Signed sum of the remittances recorded for this group admin, in cents."""
    return int(db.scalar(
        select(func.coalesce(func.sum(GroupRemittance.amount_cents), 0))
        .where(GroupRemittance.group_admin_id == admin_id)
    ))


def held(db: Session, admin_id: uuid.UUID) -> int:
    """Money this admin still holds: collected minus remitted (may be negative)."""
    return collected(db, admin_id) - remitted(db, admin_id)


def chair_rollup(db: Session) -> list[ChairRollupRow]:
    """Per chair (at event time): collected and remitted by group admins; chairs without
    any group money are omitted. Sorted by short name."""
    coll = {cid: int(total) for total, cid in db.execute(
        _cash_collected_query().add_columns(PaymentEvent.chair_id)
        .join(AdminUser, AdminUser.id == PaymentEvent.collector_admin_id)
        .where(AdminUser.role == "chair")
        .group_by(PaymentEvent.chair_id)
    ).all()}
    rem = {cid: int(total) for cid, total in db.execute(
        select(GroupRemittance.chair_id, func.sum(GroupRemittance.amount_cents))
        .join(AdminUser, AdminUser.id == GroupRemittance.group_admin_id)
        .where(AdminUser.role == "chair")
        .group_by(GroupRemittance.chair_id)
    ).all()}
    chair_ids = set(coll) | set(rem)
    if not chair_ids:
        return []
    chairs = {c.id: c for c in db.scalars(select(Chair).where(Chair.id.in_(chair_ids)))}
    rows = []
    for cid in chair_ids:
        c, r = coll.get(cid, 0), rem.get(cid, 0)
        chair = chairs.get(cid)
        rows.append(ChairRollupRow(
            chair_id=cid,
            chair_short_name=chair.short_name if chair else "?",
            chair_full_name=chair.full_name if chair else "?",
            collected_cents=c, remitted_cents=r, held_cents=c - r, negative=c - r < 0,
        ))
    rows.sort(key=lambda row: (row.chair_short_name.casefold(), str(row.chair_id)))
    return rows


def list_group_balances(db: Session) -> list[GroupBalanceRow]:
    """All current group admins plus former ones (inactive, role chair) that have ANY collection or
    remittance event, even with held 0 (so old remittances stay correctable). Sorted by chair short
    name, then username."""
    coll = {aid: int(total) for aid, total in db.execute(
        select(PaymentEvent.collector_admin_id, func.sum(PaymentEvent.amount_cents))
        .where(PaymentEvent.kind == "cash", PaymentEvent.collector_admin_id.is_not(None))
        .group_by(PaymentEvent.collector_admin_id)
    ).all()}
    rem = {aid: int(total) for aid, total in db.execute(
        select(GroupRemittance.group_admin_id, func.sum(GroupRemittance.amount_cents))
        .group_by(GroupRemittance.group_admin_id)
    ).all()}
    has_events = set(coll) | set(rem)
    rows: list[GroupBalanceRow] = []
    for admin in db.scalars(select(AdminUser).where(AdminUser.role == "chair")):
        c, r = coll.get(admin.id, 0), rem.get(admin.id, 0)
        h = c - r
        if not admin.active and admin.id not in has_events:
            continue
        linked = admin.user
        chair = linked.chair if linked is not None else None
        rows.append(GroupBalanceRow(
            admin_id=admin.id,
            username=admin.username,
            display_name=linked.display_name if linked is not None else None,
            chair_id=linked.chair_id if linked is not None else None,
            chair_short_name=chair.short_name if chair is not None else None,
            collected_cents=c, remitted_cents=r, held_cents=h,
            is_current=bool(admin.active), negative=h < 0,
        ))
    rows.sort(key=lambda row: ((row.chair_short_name or "").casefold(), row.username.casefold()))
    return rows


def _by_key(db: Session, key: str) -> GroupRemittance | None:
    return db.scalars(select(GroupRemittance).where(GroupRemittance.idempotency_key == key)).first()


def _same_or_conflict(existing: GroupRemittance, group_admin_id, amount_cents, correction_of_id) -> GroupRemittance:
    if (existing.group_admin_id != group_admin_id or existing.amount_cents != amount_cents
            or existing.correction_of_id != correction_of_id):
        raise Conflict("idempotency key already used for a different remittance")
    return existing


def _is_unique_violation(exc: IntegrityError) -> bool:
    orig = getattr(exc, "orig", None)
    if getattr(orig, "sqlstate", None) == "23505" or getattr(orig, "pgcode", None) == "23505":
        return True
    return getattr(orig, "sqlite_errorcode", None) in (2067, 1555)


def record_remittance(
    db: Session,
    *,
    head_admin: AdminUser,
    group_admin_id: uuid.UUID,
    amount_cents: int,
    idempotency_key: str,
    correction_of_id: uuid.UUID | None = None,
    note: str | None = None,
    ip: str | None = None,
    now: datetime | None = None,
) -> GroupRemittance:
    """Record money a group admin handed to the head admin (signed, non-zero).

    Head (global) admin only (`Forbidden`). The target must be a role `chair` admin, current or
    former (`NotFound` if unknown, `InvalidInput` if another role). The remittance stores the
    chair of the group admin's linked user at event time; a correction instead keeps the chair
    of the entry it corrects so both net out in the same chair roll-up.

    Idempotent on `idempotency_key`: same key and same data returns the existing row; the same
    key with different group admin, amount or correction target raises `Conflict`. A correction
    must reference a remittance of the same group admin, an entry can be corrected at most once
    and a correction itself cannot be corrected (`Conflict`). Held may go negative; that is
    allowed and flagged by `list_group_balances`. Audited as `remittance.recorded` /
    `remittance.corrected`. Never commits.
    """
    require_global(head_admin)
    if not isinstance(idempotency_key, str) or not 1 <= len(idempotency_key) <= MAX_KEY_LENGTH:
        raise InvalidInput("invalid idempotency key")
    if isinstance(amount_cents, bool) or not isinstance(amount_cents, int):
        raise InvalidAmount("amount must be an integer")
    if amount_cents == 0 or abs(amount_cents) > MAX_AMOUNT_CENTS:
        raise InvalidAmount(f"amount must be non-zero and at most {MAX_AMOUNT_CENTS} in magnitude")
    target = db.get(AdminUser, group_admin_id)
    if target is None:
        raise NotFound("group admin not found")
    if target.role != "chair" or target.user is None:
        raise InvalidInput("target is not a group admin")
    note = clean_note(note)
    now = ensure_utc(now) if now is not None else utcnow()

    existing = _by_key(db, idempotency_key)
    if existing is not None:
        return _same_or_conflict(existing, target.id, amount_cents, correction_of_id)

    chair_id = target.user.chair_id
    if correction_of_id is not None:
        original = db.get(GroupRemittance, correction_of_id)
        if original is None:
            raise NotFound("remittance not found")
        if original.group_admin_id != target.id:
            raise Conflict("remittance belongs to another group admin")
        if original.correction_of_id is not None:
            raise Conflict("a correction cannot be corrected")
        if db.scalar(select(GroupRemittance.id).where(GroupRemittance.correction_of_id == original.id)) is not None:
            raise Conflict("remittance has already been corrected")
        chair_id = original.chair_id

    remittance = GroupRemittance(
        group_admin_id=target.id, chair_id=chair_id, amount_cents=amount_cents,
        recorded_by_admin_id=head_admin.id, correction_of_id=correction_of_id,
        idempotency_key=idempotency_key, note=note, created_at=now,
    )
    try:
        with db.begin_nested():
            db.add(remittance)
            db.flush()
    except IntegrityError as exc:
        if not _is_unique_violation(exc):
            raise
        found = _by_key(db, idempotency_key)
        if found is not None:
            return _same_or_conflict(found, target.id, amount_cents, correction_of_id)
        raise Conflict("remittance has already been corrected") from exc
    audit.log(
        db, actor_type="admin", actor_id=head_admin.id,
        action="remittance.corrected" if correction_of_id else "remittance.recorded",
        target_type="admin", target_id=target.id,
        metadata={"remittance_id": str(remittance.id), "amount_cents": amount_cents,
                  "chair_id": str(chair_id),
                  "correction_of_id": str(correction_of_id) if correction_of_id else None},
        ip=ip, now=now,
    )
    return remittance
