"""`check-ledger`: verify the ledger invariants (PROMPT §4) on existing data.

Works on plain rows (no reliance on DB constraints), so it also detects corruption that
bypassed them (e.g. rows edited with foreign keys or triggers disabled).
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    COFFEE_QUANTITY,
    EVENT_TYPES,
    PAYMENT_KINDS,
    USER_STATUSES,
    AdminUser,
    Chair,
    ConsumptionEvent,
    GroupRemittance,
    PaymentEvent,
    Price,
    User,
)
from app.services import groups


@dataclass(frozen=True)
class Problem:
    code: str
    message: str


@dataclass
class CheckReport:
    problems: list[Problem]
    consumption_events: int
    payment_events: int
    users: int
    prices: int
    remittances: int = 0
    notes: list[str] = field(default_factory=list)  # informational, never a failure

    @property
    def ok(self) -> bool:
        return not self.problems


def _zero_amount_ok(e, by_id) -> bool:
    """Amount 0 at a non-zero price is legitimate only for an adjustment or its exact reversal."""
    if e.type == "adjustment":
        return True
    if e.type == "reversal":
        orig = by_id.get(e.reversal_of_id)
        return orig is not None and orig.type == "adjustment" and orig.amount_cents == 0
    return False


def check_ledger(db: Session) -> CheckReport:
    problems: list[Problem] = []

    def bad(code: str, message: str) -> None:
        problems.append(Problem(code, message))

    chairs = set(db.scalars(select(Chair.id)))
    users = {u.id: u for u in db.scalars(select(User))}
    prices = sorted(db.scalars(select(Price)), key=lambda p: p.effective_from)
    price_by_id = {p.id: p for p in prices}
    price_times = [p.effective_from for p in prices]
    events = list(db.scalars(select(ConsumptionEvent)))
    by_id = {e.id: e for e in events}
    payments = list(db.scalars(select(PaymentEvent)))
    payment_ids = {p.id for p in payments}

    for p in prices:
        if p.price_per_shot_cents < 0:
            bad("price_negative", f"price {p.id} is negative")

    # users and merge chains
    for u in users.values():
        if u.chair_id not in chairs:
            bad("orphan_user_chair", f"user {u.id} references missing chair {u.chair_id}")
        if u.status not in USER_STATUSES:
            bad("user_status", f"user {u.id} has invalid status {u.status!r}")
        if (u.status == "merged") != (u.merged_into_id is not None):
            bad("merge_state", f"user {u.id} has status {u.status!r} but merged_into_id={u.merged_into_id}")
        if u.merged_into_id is not None and u.merged_into_id not in users:
            bad("merge_orphan", f"user {u.id} is merged into missing user {u.merged_into_id}")
    for u in users.values():
        seen = {u.id}
        cur = u
        while cur.merged_into_id is not None and cur.merged_into_id in users:
            if cur.merged_into_id in seen:
                bad("merge_cycle", f"merge chain starting at user {u.id} contains a cycle")
                break
            seen.add(cur.merged_into_id)
            cur = users[cur.merged_into_id]

    # consumption events
    reversals_of: dict = {}
    for e in events:
        ref = f"consumption event {e.id}"
        if e.user_id not in users:
            bad("orphan_user", f"{ref} references missing user {e.user_id}")
        if e.chair_id not in chairs:
            bad("orphan_chair", f"{ref} references missing chair {e.chair_id}")
        if e.type not in EVENT_TYPES:
            bad("event_type", f"{ref} has invalid type {e.type!r}")
            continue
        if e.quantity == 0:
            bad("zero_quantity", f"{ref} has quantity 0")
        if (e.quantity > 0 and e.amount_cents < 0) or (e.quantity < 0 and e.amount_cents > 0):
            bad("sign_mismatch", f"{ref} has quantity and amount with opposite signs")
        if e.amount_cents == 0 and e.unit_price_cents != 0 and not _zero_amount_ok(e, by_id):
            bad("zero_amount", f"{ref} has amount 0 at a non-zero price")
        if e.type == "adjustment" and e.admin_id is None:
            bad("adjustment_admin", f"{ref} is an adjustment without admin")
        if e.type != "reversal" and e.reversal_of_id is not None:
            bad("unexpected_reversal_ref", f"{ref} of type {e.type} references another event")
        if e.price_id is not None and e.price_id not in price_by_id:
            bad("orphan_price", f"{ref} references missing price {e.price_id}")

        if e.type in COFFEE_QUANTITY:
            if e.quantity != COFFEE_QUANTITY[e.type]:
                bad("quantity_type", f"{ref} is a {e.type} with quantity {e.quantity}")
            if e.amount_cents != e.quantity * e.unit_price_cents:
                bad("amount_mismatch", f"{ref} amount {e.amount_cents} != {e.quantity} x {e.unit_price_cents}")
            i = bisect.bisect_right(price_times, e.created_at)
            in_effect = prices[i - 1] if i else None
            if in_effect is None:
                bad("no_price_at_time", f"{ref} was recorded when no price was in effect")
            elif e.price_id != in_effect.id:
                bad("price_row_mismatch", f"{ref} references price {e.price_id}, but {in_effect.id} was in effect")
            if e.price_id in price_by_id and price_by_id[e.price_id].price_per_shot_cents != e.unit_price_cents:
                bad("snapshot_mismatch", f"{ref} unit price {e.unit_price_cents} differs from its price row")
        elif e.type == "reversal":
            if e.quantity >= 0:
                bad("reversal_quantity", f"{ref} is a reversal with non-negative quantity")
            if e.reversal_of_id is None:
                bad("reversal_without_original", f"{ref} is a reversal without original")
                continue
            reversals_of.setdefault(e.reversal_of_id, []).append(e)
            orig = by_id.get(e.reversal_of_id)
            if orig is None:
                bad("orphan_reversal", f"{ref} reverses missing event {e.reversal_of_id}")
                continue
            if orig.type == "reversal":
                bad("reversal_of_reversal", f"{ref} reverses another reversal {orig.id}")
            if e.quantity != -orig.quantity or e.amount_cents != -orig.amount_cents:
                bad("reversal_amount", f"{ref} does not exactly negate event {orig.id}")
            if e.unit_price_cents != orig.unit_price_cents:
                bad("reversal_unit_price", f"{ref} unit price differs from event {orig.id}")
            if e.user_id != orig.user_id:
                bad("reversal_user", f"{ref} belongs to a different user than event {orig.id}")
            if e.chair_id != orig.chair_id:
                bad("reversal_chair", f"{ref} belongs to a different chair than event {orig.id}")
    for orig_id, revs in reversals_of.items():
        if len(revs) > 1:
            bad("double_reversal", f"event {orig_id} is reversed {len(revs)} times")

    # payments
    corrections: dict = {}
    payment_by_id = {p.id: p for p in payments}

    def effective(uid):
        seen = set()
        while uid in users and users[uid].merged_into_id in users and uid not in seen:
            seen.add(uid)
            uid = users[uid].merged_into_id
        return uid

    for p in payments:
        ref = f"payment event {p.id}"
        if p.user_id not in users:
            bad("orphan_user", f"{ref} references missing user {p.user_id}")
        if p.chair_id not in chairs:
            bad("orphan_chair", f"{ref} references missing chair {p.chair_id}")
        if p.amount_cents == 0:
            bad("zero_payment", f"{ref} has amount 0")
        if p.correction_of_id is not None:
            corrections[p.correction_of_id] = corrections.get(p.correction_of_id, 0) + 1
            if p.correction_of_id not in payment_ids:
                bad("orphan_correction", f"{ref} corrects missing payment {p.correction_of_id}")
            else:
                target = payment_by_id[p.correction_of_id]
                if effective(p.user_id) != effective(target.user_id):
                    bad("correction_user", f"{ref} belongs to a different user than corrected payment {target.id}")
    for pid, n in corrections.items():
        if n > 1:
            bad("double_correction", f"payment {pid} is corrected {n} times")

    # collectors and kinds (v2)
    admins = {a.id: a for a in db.scalars(select(AdminUser))}
    for p in payments:
        ref = f"payment event {p.id}"
        if p.kind not in PAYMENT_KINDS:
            bad("payment_kind", f"{ref} has invalid kind {p.kind!r}")
        elif p.kind == "cash" and p.collector_admin_id is None:
            bad("cash_without_collector", f"{ref} is a cash payment without collector")
        elif p.kind == "bookkeeping" and p.collector_admin_id is not None:
            bad("bookkeeping_with_collector", f"{ref} is a bookkeeping payment with a collector")
        if p.collector_admin_id is not None and p.collector_admin_id not in admins:
            bad("orphan_collector", f"{ref} references missing collector {p.collector_admin_id}")
        if p.correction_of_id in payment_by_id:
            target = payment_by_id[p.correction_of_id]
            if p.collector_admin_id != target.collector_admin_id:
                bad("correction_collector", f"{ref} has a different collector than corrected payment {target.id}")
            if p.kind != target.kind:
                bad("correction_kind", f"{ref} has a different kind than corrected payment {target.id}")
            if p.chair_id != target.chair_id:
                bad("correction_chair", f"{ref} has a different chair than corrected payment {target.id}")
            if (p.amount_cents > 0) == (target.amount_cents > 0):
                bad("correction_sign", f"{ref} has the same sign as corrected payment {target.id}")
            if abs(p.amount_cents) > abs(target.amount_cents):
                bad("correction_amount", f"{ref} exceeds corrected payment {target.id}")
            recorder = admins.get(p.admin_id)
            if p.admin_id != target.collector_admin_id and (recorder is None or recorder.role != "global"):
                bad("correction_recorder",
                    f"{ref} was recorded by neither the collector nor a head admin of payment {target.id}")

    # group remittances (v2)
    remittances = list(db.scalars(select(GroupRemittance)))
    rem_by_id = {r.id: r for r in remittances}
    rem_corrections: dict = {}
    for r in remittances:
        ref = f"remittance {r.id}"
        target_admin = admins.get(r.group_admin_id)
        if target_admin is None:
            bad("remittance_admin", f"{ref} references missing group admin {r.group_admin_id}")
        elif target_admin.role != "chair":
            bad("remittance_admin_role", f"{ref} is for {target_admin.username}, who is not a group admin")
        recorder = admins.get(r.recorded_by_admin_id)
        if recorder is None or recorder.role != "global":
            bad("remittance_recorder", f"{ref} was not recorded by a head admin")
        if r.chair_id not in chairs:
            bad("orphan_chair", f"{ref} references missing chair {r.chair_id}")
        if r.amount_cents == 0:
            bad("zero_remittance", f"{ref} has amount 0")
        if r.correction_of_id is not None:
            rem_corrections[r.correction_of_id] = rem_corrections.get(r.correction_of_id, 0) + 1
            orig = rem_by_id.get(r.correction_of_id)
            if orig is None:
                bad("remittance_correction_orphan", f"{ref} corrects missing remittance {r.correction_of_id}")
            elif orig.id == r.id:
                bad("remittance_correction_self", f"{ref} corrects itself")
            else:
                if orig.group_admin_id != r.group_admin_id:
                    bad("remittance_correction_admin", f"{ref} corrects a remittance of another group admin")
                if orig.correction_of_id is not None:
                    bad("remittance_correction_of_correction", f"{ref} corrects another correction {orig.id}")
    for rid, n in rem_corrections.items():
        if n > 1:
            bad("double_remittance_correction", f"remittance {rid} is corrected {n} times")

    # group balance consistency: recompute from plain rows, compare with the service functions
    admin_collected: dict = {}
    chair_collected: dict = {}
    for p in payments:
        if p.kind == "cash" and p.collector_admin_id is not None:
            admin_collected[p.collector_admin_id] = admin_collected.get(p.collector_admin_id, 0) + p.amount_cents
            collector = admins.get(p.collector_admin_id)
            if collector is not None and collector.role == "chair":
                chair_collected[p.chair_id] = chair_collected.get(p.chair_id, 0) + p.amount_cents
    admin_remitted: dict = {}
    chair_remitted: dict = {}
    for r in remittances:
        admin_remitted[r.group_admin_id] = admin_remitted.get(r.group_admin_id, 0) + r.amount_cents
        holder = admins.get(r.group_admin_id)
        if holder is not None and holder.role == "chair":
            chair_remitted[r.chair_id] = chair_remitted.get(r.chair_id, 0) + r.amount_cents
    notes: list[str] = []
    for admin in admins.values():
        if admin.role != "chair":
            continue
        want_c, want_r = admin_collected.get(admin.id, 0), admin_remitted.get(admin.id, 0)
        got_c, got_h = groups.collected(db, admin.id), groups.held(db, admin.id)
        if got_c != want_c or got_h != want_c - want_r:
            bad("group_balance_mismatch",
                f"group admin {admin.username}: collected {got_c} / held {got_h}, rows say {want_c} / {want_c - want_r}")
        if want_c - want_r < 0:
            notes.append(f"group admin {admin.username} has handed over {-(want_c - want_r)} cents more than collected")
        elif not admin.active and want_c - want_r != 0:
            notes.append(f"former group admin {admin.username} still holds {want_c - want_r} cents")
    rollup = {row.chair_id: row for row in groups.chair_rollup(db)}
    for cid in set(chair_collected) | set(chair_remitted) | set(rollup):
        want_c, want_r = chair_collected.get(cid, 0), chair_remitted.get(cid, 0)
        row = rollup.get(cid)
        got_c = row.collected_cents if row else 0
        got_h = row.held_cents if row else 0
        if got_c != want_c or got_h != want_c - want_r:
            bad("group_balance_mismatch",
                f"chair {cid}: roll-up collected {got_c} / held {got_h}, rows say {want_c} / {want_c - want_r}")
        if want_c - want_r < 0:
            notes.append(f"chair {cid} has handed over {-(want_c - want_r)} cents more than collected")

    return CheckReport(problems, len(events), len(payments), len(users), len(prices), len(remittances), notes)
