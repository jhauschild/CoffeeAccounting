"""Final audit (task 7.2): property-style test of the ledger rules.

Hypothesis is not installed in the reference venv, so this uses seeded random sequences (reproducible: a failure
names the seed and the step). Each seed builds a small world (3 chairs, 2 head admins, several members, guests and
group admins) and applies random ledger operations through the services: scans, undo, admin reversals and
adjustments, cash payments and paid-back by group admins and head admins, corrections (full and partial),
set_balance, remittances and their corrections, merges, deactivation, promotion and demotion, chair changes of
non-admins and price changes. Operations that the rules refuse are simply refused (ServiceError).

After the steps the invariants are recomputed from the RAW tables with plain SQL, independently of the services:

* balance = consumed - paid for every effective user, `paid` counting both payment kinds;
* bookkeeping (set_balance) is never counted as collected: it has no collector and `groups.collected` equals the
  sum of cash payments of that collector;
* held = collected - remitted for every group admin and for every chair roll-up;
* a correction inherits collector, kind and chair from the payment it corrects;
* no ledger or audit row is ever deleted or updated: a snapshot of every row taken during the run is still present
  and unchanged at the end, and SQL UPDATE/DELETE statements are rejected by the append-only triggers;
* `check_ledger` stays clean.
"""

from __future__ import annotations

import random
import uuid
from collections import defaultdict
from datetime import timedelta

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DatabaseError

from app.models import (AdminUser, AuditLog, Chair, ConsumptionEvent, GroupRemittance, PaymentEvent, Price, User)
from app.services import groups, ledger, prices, registration, roles, users
from app.services.checker import check_ledger
from app.services.errors import ServiceError
from app.timeutil import utcnow
from tests import factories

SEEDS = list(range(1, 17))
STEPS = 70
APPEND_ONLY = (ConsumptionEvent, PaymentEvent, Price, GroupRemittance, AuditLog)


class World:
    def __init__(self, db, seed: int):
        self.db = db
        self.rng = random.Random(seed)
        self.seed = seed
        self.clock = utcnow() - timedelta(days=20)
        self.sessions: dict = {}
        self.last_scan: dict = {}
        self.step = 0
        self.executed = defaultdict(int)
        self.refused = defaultdict(int)
        self.snapshots: dict = {}
        factories.set_price(db, 50, effective_from=self.clock - timedelta(days=1))
        self.chairs = [factories.make_chair(db, short_name=f"C{i}", full_name=f"Chair {i}") for i in range(3)]
        self.head = factories.make_admin(db, role="global", username="headA")
        self.head2 = factories.make_admin(db, role="global", username="headB")
        self.members = [factories.make_member(db, f"Member {i}", self.chairs[i % 3], username=f"m{i}") for i in range(9)]
        self.guests = [factories.make_guest(db, self.members[i], f"Guest {i}", username=f"g{i}") for i in range(3)]
        # group admins: promote through the service so the real role flow is exercised
        for m in self.members[:4]:
            roles.promote_group_admin(db, head_admin=self.head, user_id=m.id, now=self.clock)
        db.commit()

    # ----- helpers ---------------------------------------------------------------------------
    def tick(self, lo=1, hi=300):
        self.clock += timedelta(minutes=self.rng.randint(lo, hi), seconds=self.rng.randint(0, 59))
        return self.clock

    def active_users(self):
        return list(self.db.scalars(select(User).where(User.status == "active")))

    def group_admins(self, active=True):
        q = select(AdminUser).where(AdminUser.role == "chair")
        if active is not None:
            q = q.where(AdminUser.active.is_(active))
        return list(self.db.scalars(q))

    def actor_for(self, user):
        pool = [self.head, self.head2]
        for ga in self.group_admins():
            if ga.user.chair_id == user.chair_id:
                pool += [ga, ga]
        return self.rng.choice(pool)

    def attempt(self, name, fn):
        try:
            out = fn()
            self.db.commit()
            self.executed[name] += 1
            return out
        except ServiceError:
            self.db.rollback()
            self.refused[name] += 1
            return None
        except IndexError:  # nothing to pick from right now
            self.db.rollback()
            return None

    # ----- the operations --------------------------------------------------------------------
    def op_scan(self):
        def run():
            user = self.rng.choice(self.active_users())
            sid = self.sessions.setdefault(user.id, uuid.uuid4())
            res = ledger.record_coffee(self.db, user_id=user.id, kind=self.rng.choice(["single", "double"]),
                                       nonce=uuid.uuid4().hex, session_id=sid, now=self.tick())
            self.last_scan[user.id] = (res.event.id, self.clock)
        self.attempt("scan", run)

    def op_undo(self):
        def run():
            uid = self.rng.choice(list(self.last_scan))
            eid, at = self.last_scan.pop(uid)
            ledger.undo_coffee(self.db, user_id=uid, session_id=self.sessions[uid], event_id=eid,
                               now=at + timedelta(seconds=30))
        self.attempt("undo", run)

    def op_reverse(self):
        def run():
            events = list(self.db.scalars(select(ConsumptionEvent).where(
                ConsumptionEvent.type != "reversal", ConsumptionEvent.quantity > 0).limit(200)))
            e = self.rng.choice(events)
            ledger.admin_reverse_event(self.db, admin=self.actor_for(self.db.get(User, e.user_id)), event_id=e.id,
                                       now=self.tick())
        self.attempt("reverse", run)

    def op_adjust(self):
        def run():
            u = self.rng.choice(self.active_users())
            q = self.rng.choice([-2, -1, 1, 2, 4])
            ledger.add_adjustment(self.db, admin=self.actor_for(u), user_id=u.id, quantity=q,
                                  amount_cents=None if self.rng.random() < 0.5 else q * self.rng.choice([0, 30, 70]),
                                  now=self.tick())
        self.attempt("adjust", run)

    def op_pay(self):
        def run():
            u = self.rng.choice(self.active_users())
            ledger.add_payment(self.db, admin=self.actor_for(u), user_id=u.id,
                               amount_cents=self.rng.choice([50, 100, 250, 600, 1500]),
                               idempotency_key=uuid.uuid4().hex, now=self.tick())
        self.attempt("pay", run)

    def op_payback(self):
        def run():
            u = self.rng.choice(self.active_users())
            actor = self.actor_for(u)
            amount = -self.rng.choice([50, 200, 700])
            if actor.role != "global":  # group admins: up to the credit only (otherwise PaybackExceedsCredit)
                credit = max(0, -ledger.get_totals(self.db, u.id).balance_cents)
                amount = -min(credit, -amount) or amount
            ledger.add_payment(self.db, admin=actor, user_id=u.id, amount_cents=amount,
                               idempotency_key=uuid.uuid4().hex, now=self.tick())
        self.attempt("payback", run)

    def op_correct(self):
        def run():
            done = set(self.db.scalars(select(PaymentEvent.correction_of_id).where(
                PaymentEvent.correction_of_id.is_not(None))))
            p = self.rng.choice([p for p in self.db.scalars(select(PaymentEvent).where(
                PaymentEvent.correction_of_id.is_(None))) if p.id not in done])
            collector = self.db.get(AdminUser, p.collector_admin_id) if p.collector_admin_id else None
            actor = collector if collector is not None and collector.active and self.rng.random() < 0.5 else self.head
            amount = -p.amount_cents if self.rng.random() < 0.6 else -(p.amount_cents // 2 or p.amount_cents)
            ledger.add_payment(self.db, admin=actor, user_id=p.user_id, amount_cents=amount, correction_of_id=p.id,
                               idempotency_key=uuid.uuid4().hex, now=self.tick())
        self.attempt("correct", run)

    def op_set_balance(self):
        def run():
            u = self.rng.choice(self.active_users())
            ledger.set_balance(self.db, admin=self.head, user_id=u.id,
                               target_balance_cents=self.rng.choice([-400, 0, 90, 500]),
                               idempotency_key=uuid.uuid4().hex, now=self.tick())
        self.attempt("set_balance", run)

    def op_remit(self):
        def run():
            ga = self.rng.choice(self.group_admins(active=None))
            held = groups.held(self.db, ga.id)
            amount = held if (held > 0 and self.rng.random() < 0.6) else self.rng.choice([-200, 100, 700])
            groups.record_remittance(self.db, head_admin=self.head, group_admin_id=ga.id, amount_cents=amount,
                                     idempotency_key=uuid.uuid4().hex, now=self.tick())
        self.attempt("remit", run)

    def op_correct_remit(self):
        def run():
            done = set(self.db.scalars(select(GroupRemittance.correction_of_id).where(
                GroupRemittance.correction_of_id.is_not(None))))
            r = self.rng.choice([r for r in self.db.scalars(select(GroupRemittance).where(
                GroupRemittance.correction_of_id.is_(None))) if r.id not in done])
            groups.record_remittance(self.db, head_admin=self.head, group_admin_id=r.group_admin_id,
                                     amount_cents=self.rng.choice([-r.amount_cents, 100, -100]),
                                     idempotency_key=uuid.uuid4().hex, correction_of_id=r.id, now=self.tick())
        self.attempt("correct_remit", run)

    def op_price(self):
        def run():
            now = self.tick()
            prices.add_price(self.db, price_per_shot_cents=self.rng.choice([35, 50, 60]), effective_from=now,
                             admin_id=self.head.id, now=now)
        self.attempt("price", run)

    def op_status(self):
        def run():
            u = self.rng.choice(self.active_users())
            users.set_user_status(self.db, admin=self.actor_for(u), user_id=u.id, active=False)
            users.set_user_status(self.db, admin=self.head, user_id=u.id, active=True)
        self.attempt("status", run)

    def op_promote_demote(self):
        def run():
            if self.rng.random() < 0.5:
                m = self.rng.choice([u for u in self.active_users() if u.account_kind == "member"])
                roles.promote_group_admin(self.db, head_admin=self.head, user_id=m.id, now=self.tick())
            else:
                ga = self.rng.choice(self.group_admins())
                roles.demote_group_admin(self.db, head_admin=self.head, user_id=ga.user_id, now=self.tick())
        self.attempt("promote_demote", run)

    def op_chair(self):
        def run():
            ga_users = {a.user_id for a in self.group_admins()}
            u = self.rng.choice([u for u in self.active_users() if u.id not in ga_users])
            c = self.rng.choice([c for c in self.chairs if c.id != u.chair_id])
            if self.rng.random() < 0.5:
                users.update_profile(self.db, user_id=u.id, chair_id=c.id, actor_type="admin", actor_id=self.head.id)
            else:
                users.update_profile(self.db, user_id=u.id, chair_id=c.id, actor_type="user")
        self.attempt("chair", run)

    def op_merge(self):
        def run():
            a, b = self.rng.sample(self.active_users(), 2)
            users.merge_users(self.db, admin=self.head, duplicate_id=a.id, target_id=b.id, now=self.tick())
        self.attempt("merge", run)

    # ----- snapshots and invariants ------------------------------------------------------------
    def snapshot(self):
        """Remember every ledger/audit row; `check_append_only` compares them at the end."""
        for model in APPEND_ONLY:
            for row in self.db.execute(select(model.__table__)).all():
                self.snapshots.setdefault((model.__tablename__, row[0]), tuple(row))
        self.db.rollback()

    def check_append_only(self):
        for model in APPEND_ONLY:
            now_rows = {(model.__tablename__, r[0]): tuple(r) for r in self.db.execute(
                select(model.__table__)).all()}
            for key, old in self.snapshots.items():
                if key[0] != model.__tablename__:
                    continue
                assert key in now_rows, f"seed {self.seed}: {key} was deleted"
                assert now_rows[key] == old, f"seed {self.seed}: {key} was modified"
        self.db.rollback()

    def invariants(self, where: str):
        db = self.db
        db.rollback()
        # raw tables, no service code
        u_rows = {r.id: r for r in db.execute(text("SELECT id, merged_into_id, chair_id FROM users")).all()}
        # SQLite returns the raw 32-hex uuid strings here; the ORM below returns uuid.UUID, so normalise to hex
        key = lambda v: None if v is None else (v.hex if isinstance(v, uuid.UUID) else str(v))  # noqa: E731
        parent = {key(i): key(r.merged_into_id) for i, r in u_rows.items()}

        def eff(uid):
            uid = key(uid)
            seen = set()
            while parent.get(uid) and uid not in seen:
                seen.add(uid)
                uid = parent[uid]
            return uid

        consumed, paid = defaultdict(int), defaultdict(int)
        for uid, amount in db.execute(text("SELECT user_id, amount_cents FROM consumption_events")).all():
            consumed[eff(uid)] += amount
        for uid, amount in db.execute(text("SELECT user_id, amount_cents FROM payment_events")).all():
            paid[eff(uid)] += amount
        for uid in list(parent):
            t = ledger.get_totals(db, uuid.UUID(uid))
            assert t.balance_cents == consumed[eff(uid)] - paid[eff(uid)], f"seed {self.seed} {where}: balance of {uid}"
            assert (t.consumed_amount_cents, t.paid_amount_cents) == (consumed[eff(uid)], paid[eff(uid)])

        pays = db.execute(text("SELECT id, kind, collector_admin_id, chair_id, amount_cents, correction_of_id "
                               "FROM payment_events")).all()
        by_id = {key(p.id): p for p in pays}
        roles_by_admin = {key(i): r for i, r in db.execute(text("SELECT id, role FROM admin_users")).all()}
        for p in pays:
            if p.kind == "bookkeeping":
                assert p.collector_admin_id is None, f"seed {self.seed}: bookkeeping with a collector"
            if p.correction_of_id is not None:
                o = by_id[key(p.correction_of_id)]
                assert (p.collector_admin_id, p.kind, p.chair_id) == (o.collector_admin_id, o.kind, o.chair_id), \
                    f"seed {self.seed} {where}: correction {p.id} does not inherit collector/kind/chair"
        rem = db.execute(text("SELECT group_admin_id, chair_id, amount_cents FROM group_remittances")).all()
        coll_admin, rem_admin = defaultdict(int), defaultdict(int)
        coll_chair, rem_chair = defaultdict(int), defaultdict(int)
        bookkeeping_total = sum(p.amount_cents for p in pays if p.kind == "bookkeeping")
        for p in pays:
            if p.kind == "cash" and p.collector_admin_id is not None:
                coll_admin[key(p.collector_admin_id)] += p.amount_cents
                if roles_by_admin[key(p.collector_admin_id)] == "chair":
                    coll_chair[key(p.chair_id)] += p.amount_cents
        for admin_id, chair_id, amount in rem:
            rem_admin[key(admin_id)] += amount
            if roles_by_admin[key(admin_id)] == "chair":
                rem_chair[key(chair_id)] += amount
        for aid, role in roles_by_admin.items():
            if role == "chair":
                assert groups.collected(db, uuid.UUID(aid)) == coll_admin[aid], f"seed {self.seed} {where}: collected"
                assert groups.held(db, uuid.UUID(aid)) == coll_admin[aid] - rem_admin[aid], f"seed {self.seed}: held"
        roll = {key(r.chair_id): (r.collected_cents, r.remitted_cents, r.held_cents) for r in groups.chair_rollup(db)}
        for cid in set(coll_chair) | set(rem_chair):
            assert roll.get(cid, (0, 0, 0)) == (coll_chair[cid], rem_chair[cid], coll_chair[cid] - rem_chair[cid]), \
                f"seed {self.seed} {where}: chair roll-up {cid}"
        # bookkeeping never leaks into any collected figure
        assert sum(coll_admin.values()) == sum(p.amount_cents for p in pays if p.kind == "cash" and p.collector_admin_id)
        _ = bookkeeping_total
        report = check_ledger(db)
        assert report.ok, f"seed {self.seed} {where}: check_ledger {[p.message for p in report.problems][:3]}"
        db.rollback()


OPS = ["op_scan"] * 6 + ["op_pay"] * 4 + ["op_payback", "op_undo", "op_reverse", "op_adjust", "op_correct",
                                          "op_correct", "op_set_balance", "op_remit", "op_remit", "op_correct_remit",
                                          "op_price", "op_status", "op_promote_demote", "op_chair", "op_merge"]


@pytest.mark.parametrize("seed", SEEDS)
def test_random_ledger_sequences_keep_every_invariant(db, seed):
    world = World(db, seed)
    world.snapshot()
    for i in range(STEPS):
        world.step = i
        getattr(world, world.rng.choice(OPS))()
        if i % 10 == 9:
            world.invariants(f"step {i}")
            world.snapshot()
    world.invariants("final")
    world.check_append_only()
    assert sum(world.executed.values()) >= STEPS // 3, f"seed {seed}: too few operations went through {dict(world.executed)}"
    assert len(world.executed) >= 7, f"seed {seed}: the mix was too narrow {dict(world.executed)}"
    print(f"seed {seed}: executed {dict(world.executed)} refused {dict(world.refused)}")


def test_append_only_triggers_reject_update_and_delete_on_every_protected_table(db):
    world = World(db, 99)
    for _ in range(25):
        getattr(world, world.rng.choice(["op_scan", "op_pay", "op_remit", "op_price"]))()
    db.rollback()
    for table in ("consumption_events", "payment_events", "prices", "group_remittances", "audit_log"):
        n = db.scalar(text(f"SELECT count(*) FROM {table}"))
        assert n > 0, f"no rows in {table} to try on"
        first_col = "note" if table in ("consumption_events", "payment_events", "group_remittances", "prices") else "action"
        for stmt in (f"UPDATE {table} SET {first_col} = 'x'", f"DELETE FROM {table}"):
            with pytest.raises(DatabaseError, match="append-only"):
                db.execute(text(stmt))
            db.rollback()
        assert db.scalar(text(f"SELECT count(*) FROM {table}")) == n
    # the service layer has no update/delete path either: no ORM-mapped delete helpers exist for these models
    from app.services import audit, groups as g, ledger as l, prices as p  # noqa: F401
    for module in (audit, g, l, p):
        public = [n for n in dir(module) if n.startswith(("delete", "remove", "update", "edit"))]
        assert not public, f"{module.__name__} exposes {public}"


def test_corrections_inherit_collector_and_chair_after_the_person_moves(db):
    """Targeted version of the property: the user changes chair between payment and correction."""
    c1, c2 = factories.make_chair(db, "P1"), factories.make_chair(db, "P2")
    head = factories.make_admin(db, role="global", username="hx")
    ga = factories.make_admin(db, role="chair", chairs=[c1], username="gx")
    person = factories.make_member(db, "Person", c1, username="px")
    factories.set_price(db, 50)
    pay = ledger.add_payment(db, admin=ga, user_id=person.id, amount_cents=900)
    db.commit()
    users.update_profile(db, user_id=person.id, chair_id=c2.id, actor_type="admin", actor_id=head.id)
    db.commit()
    corr = ledger.add_payment(db, admin=head, user_id=person.id, amount_cents=-900, correction_of_id=pay.id)
    db.commit()
    assert (corr.collector_admin_id, corr.chair_id, corr.kind) == (ga.id, c1.id, "cash")
    assert groups.held(db, ga.id) == 0
    assert [(r.chair_short_name, r.collected_cents, r.held_cents) for r in groups.chair_rollup(db)] == [("P1", 0, 0)]
    assert check_ledger(db).ok
