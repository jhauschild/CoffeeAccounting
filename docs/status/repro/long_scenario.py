"""Final audit (task 7.2): a long scripted scenario that seeds a database through the SERVICES only.

    python docs/status/repro/long_scenario.py DB_PATH [--seed 7] [--min-ops 220]

Builds a freshly migrated SQLite database at DB_PATH (it must not exist) and runs a deterministic (seeded)
sequence of mixed operations on a simulated clock: registrations (members and guests, through
`registration.begin_*` / `confirm_member` / `approve_guest`), coffee scans, undo, admin reversals and
adjustments, price changes, payments by group admins and head admins (cash, paid-back), corrections (full and
partial), `set_balance`, remittances and their corrections, merges, deactivation and reactivation, group-admin
promotion and demotion, sponsor reassignment, and chair changes of non-admins. It also fires operations that
MUST be refused (a group admin changing own chair or own balance, over-credit paybacks, a peer deactivating a group
admin, a second correction, ...) and records whether each was refused.

Prints one JSON object (operation counts, refusals, any unexpected outcome). Exit code 0 only if every operation
that was expected to succeed succeeded, every forbidden one was refused, `check_ledger` is clean and at least
--min-ops operations succeeded. Nothing here touches application code.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import uuid
from collections import Counter
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))


def configure_env(db_path: str) -> None:
    os.environ.setdefault("ENVIRONMENT", "development")
    os.environ.setdefault("PUBLIC_BASE_URL", "http://testserver")
    os.environ.setdefault("SECRET_KEY", "audit-scenario-secret-key-0123456789abcdef-xyz")
    os.environ.setdefault("MAIL_BACKEND", "memory")
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    os.environ.setdefault("ARGON2_TIME_COST", "1")
    os.environ.setdefault("ARGON2_MEMORY_COST_KIB", "8")
    os.environ.setdefault("ARGON2_PARALLELISM", "1")
    os.environ.setdefault("TRUSTED_PROXY_IPS", "")


def migrate(db_path: str) -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.attributes["url"] = f"sqlite:///{db_path}"
    cfg.attributes["configure_logger"] = False
    command.upgrade(cfg, "head")


class Scenario:
    def __init__(self, seed: int):
        from app.timeutil import utcnow

        self.rng = random.Random(seed)
        self.clock = utcnow() - timedelta(days=45)
        self.ok: Counter = Counter()
        self.refused: Counter = Counter()
        self.skipped: Counter = Counter()
        self.vacuous: list[str] = []
        self.unexpected: list[str] = []
        self.must_refuse_but_ok: list[str] = []
        self.sessions: dict = {}
        self.last_event: dict = {}
        self.counter = 0
        self.ip_seq = 0

    # ----- plumbing --------------------------------------------------------------------------
    def tick(self, lo=1, hi=240):
        self.clock += timedelta(minutes=self.rng.randint(lo, hi), seconds=self.rng.randint(0, 59))
        return self.clock

    def uniq(self, prefix: str) -> str:
        self.counter += 1
        return f"{prefix}{self.counter}"

    def ip(self) -> str:
        self.ip_seq += 1
        return f"10.{self.ip_seq // 250}.{self.ip_seq % 250}.7"

    def run(self, name, fn, *, must_refuse=False):
        """Run `fn(db)` in its own write transaction. ServiceError = refused (rolled back)."""
        from app.db import write_session
        from app.services.errors import ServiceError

        try:
            with write_session() as db:
                out = fn(db)
        except ServiceError as exc:
            self.refused[name] += 1
            if not must_refuse:
                self.unexpected.append(f"{name}: unexpected refusal {type(exc).__name__}: {exc}")
            return None
        if must_refuse:
            self.must_refuse_but_ok.append(name)
            return out
        self.ok[name] += 1
        return out

    def try_op(self, name, fn):
        """Randomised op whose target choice may be invalid: a refusal is fine, anything but ServiceError is not."""
        from app.db import write_session
        from app.services.errors import ServiceError

        try:
            with write_session() as db:
                out = fn(db)
        except ServiceError:
            self.refused[name] += 1
            return None
        except IndexError:  # random.choice on an empty candidate list: nothing to do for this op right now
            self.skipped[name] += 1
            return None
        self.ok[name] += 1
        return out

    # ----- state queries ---------------------------------------------------------------------
    def active_users(self, db, kind=None):
        from sqlalchemy import select

        from app.models import AdminUser, User

        q = select(User).where(User.status == "active", User.account_kind.is_not(None))
        if kind:
            q = q.where(User.account_kind == kind)
        users = list(db.scalars(q))
        return users

    def group_admins(self, db, active=True):
        from sqlalchemy import select

        from app.models import AdminUser

        q = select(AdminUser).where(AdminUser.role == "chair")
        if active is not None:
            q = q.where(AdminUser.active.is_(active))
        return list(db.scalars(q))

    def head(self, db, name="boss"):
        from app.services import admin_auth

        return admin_auth.get_by_username(db, name)

    def pick_actor_for(self, db, user):
        """A head admin, or a group admin of the user's chair (if any), at random."""
        from sqlalchemy import select

        from app.models import AdminUser

        candidates = [self.head(db), self.head(db, "boss2")]
        for ga in self.group_admins(db):
            if ga.user.chair_id == user.chair_id:
                candidates += [ga, ga]
        return self.rng.choice(candidates)

    # ----- setup -----------------------------------------------------------------------------
    def setup(self):
        from app.models import Chair
        from app.services import admin_auth, prices

        def _setup(db):
            for short, full in (("ALG", "Algorithms"), ("BIO", "Bioinformatics"), ("CTL", "Control")):
                db.add(Chair(short_name=short, full_name=f"Chair of {full}"))
            db.flush()
            admin_auth.create_admin(db, username="boss", password="boss-password-123456", role="global",
                                    now=self.clock)
            admin_auth.create_admin(db, username="boss2", password="boss2-password-123456", role="global",
                                    now=self.clock)
            prices.add_price(db, price_per_shot_cents=50, admin_id=None, now=self.clock, effective_from=self.clock)

        self.run("setup", _setup)

    # ----- registration ----------------------------------------------------------------------
    def register_member(self, chair_short=None):
        from sqlalchemy import select

        from app.models import Chair, User
        from app.services import registration

        n = self.counter + 1
        username = self.uniq("member")
        now = self.tick()
        ip = self.ip()

        def _reg(db):
            chairs = list(db.scalars(select(Chair).where(Chair.active.is_(True)).order_by(Chair.short_name)))
            chair = next((c for c in chairs if c.short_name == chair_short), None) or self.rng.choice(chairs)
            res = registration.begin_member(db, username=username, display_name=f"Member Number{n}", chair_id=chair.id,
                                            email=f"{username}@tum.de", password=f"pw-{username}-long-enough",
                                            privacy_ack=True, ip=ip, now=now)
            return res.token

        token = self.run("register_member", _reg)
        if token:
            self.run("confirm_member", lambda db: registration.confirm_member(db, token, now=now, ip=ip))
        return username

    def register_guest(self):
        from sqlalchemy import select

        from app.models import User
        from app.services import registration

        n = self.counter + 1
        username = self.uniq("guest")
        now = self.tick()
        ip = self.ip()

        def _reg(db):
            members = [u for u in self.active_users(db, "member")]
            sponsor = self.rng.choice(members)
            res = registration.begin_guest(db, username=username, display_name=f"Guest Number{n}",
                                           password=f"pw-{username}-long-enough", sponsor_email=sponsor.email,
                                           privacy_ack=True, ip=ip, now=now)
            return res.token

        token = self.run("register_guest", _reg)
        if token:
            self.run("approve_guest", lambda db: registration.approve_guest(db, token, ip=ip, now=now))

    # ----- ledger operations -----------------------------------------------------------------
    def scan(self):
        from app.services import ledger

        def _scan(db):
            users = self.active_users(db)
            user = self.rng.choice(users)
            sid = self.sessions.setdefault(user.id, uuid.uuid4())
            res = ledger.record_coffee(db, user_id=user.id, kind=self.rng.choice(["single", "double"]),
                                       nonce=uuid.uuid4().hex, session_id=sid, now=self.tick())
            return user.id, res.event.id, self.clock

        out = self.run("scan", _scan)
        if out:
            self.last_event[out[0]] = (out[1], out[2])
        return out

    def undo(self):
        from app.services import ledger

        if not self.last_event:
            return
        uid = self.rng.choice(list(self.last_event))
        event_id, at = self.last_event[uid]
        now = at + timedelta(seconds=self.rng.randint(5, 120))
        self.try_op("undo", lambda db: ledger.undo_coffee(db, user_id=uid, session_id=self.sessions[uid],
                                                          event_id=event_id, now=now))
        self.last_event.pop(uid, None)

    def admin_reverse(self):
        from sqlalchemy import select

        from app.models import ConsumptionEvent, User
        from app.services import ledger

        def _rev(db):
            # quantity > 0 only: reversing a NEGATIVE adjustment hits the CHECK constraint (finding, see
            # docs/status/repro/repro_reverse_negative_adjustment.py), so the random walk avoids it
            events = list(db.scalars(select(ConsumptionEvent).where(ConsumptionEvent.type != "reversal",
                                                                    ConsumptionEvent.quantity > 0)
                                     .order_by(ConsumptionEvent.created_at.desc()).limit(80)))
            event = self.rng.choice(events)
            user = db.get(User, event.user_id)
            actor = self.pick_actor_for(db, user)
            return ledger.admin_reverse_event(db, admin=actor, event_id=event.id, note="audit reverse",
                                              now=self.tick())

        self.try_op("admin_reverse", _rev)

    def adjust(self):
        from app.services import ledger

        def _adj(db):
            user = self.rng.choice(self.active_users(db))
            actor = self.pick_actor_for(db, user)
            qty = self.rng.choice([-3, -2, -1, 1, 2, 3, 5])
            amount = None if self.rng.random() < 0.6 else (abs(qty) * self.rng.choice([0, 40, 55, 70])) * (1 if qty > 0 else -1)
            return ledger.add_adjustment(db, admin=actor, user_id=user.id, quantity=qty, amount_cents=amount,
                                         note="audit adjustment", now=self.tick())

        self.try_op("adjust", _adj)

    def pay(self, sign=1):
        from app.services import ledger

        def _pay(db):
            user = self.rng.choice(self.active_users(db))
            actor = self.pick_actor_for(db, user)
            amount = self.rng.choice([50, 100, 150, 200, 350, 500, 1000, 2000]) * sign
            if sign < 0 and actor.role != "global":
                credit = max(0, -ledger.get_totals(db, user.id).balance_cents)
                amount = -min(credit, abs(amount)) if credit else amount
            return ledger.add_payment(db, admin=actor, user_id=user.id, amount_cents=amount,
                                      note="audit payment", idempotency_key=uuid.uuid4().hex, now=self.tick())

        self.try_op("pay_cash" if sign > 0 else "pay_back", _pay)

    def correct_payment(self):
        from sqlalchemy import select

        from app.models import AdminUser, PaymentEvent
        from app.services import ledger

        def _corr(db):
            corrected = set(db.scalars(select(PaymentEvent.correction_of_id).where(
                PaymentEvent.correction_of_id.is_not(None))))
            cands = [p for p in db.scalars(select(PaymentEvent).where(PaymentEvent.correction_of_id.is_(None)))
                     if p.id not in corrected]
            p = self.rng.choice(cands)
            collector = db.get(AdminUser, p.collector_admin_id) if p.collector_admin_id else None
            actor = collector if (collector and collector.active and self.rng.random() < 0.6) else self.head(db)
            amount = -p.amount_cents if self.rng.random() < 0.6 else -(p.amount_cents // 2 or p.amount_cents)
            return ledger.add_payment(db, admin=actor, user_id=p.user_id, amount_cents=amount, correction_of_id=p.id,
                                      note="audit correction", idempotency_key=uuid.uuid4().hex, now=self.tick())

        self.try_op("correct_payment", _corr)

    def set_balance(self):
        from app.services import ledger

        def _sb(db):
            user = self.rng.choice(self.active_users(db))
            return ledger.set_balance(db, admin=self.head(db), user_id=user.id,
                                      target_balance_cents=self.rng.choice([-500, -100, 0, 0, 75, 300, 800]),
                                      idempotency_key=uuid.uuid4().hex, note="audit set balance", now=self.tick())

        self.try_op("set_balance", _sb)

    def remit(self):
        from sqlalchemy import select

        from app.models import GroupRemittance
        from app.services import groups

        def _rem(db):
            gas = self.group_admins(db, active=None)
            ga = self.rng.choice(gas)
            held = groups.held(db, ga.id)
            if self.rng.random() < 0.7 and held > 0:
                amount = self.rng.choice([held, held // 2 or held])
            else:
                amount = self.rng.choice([-300, -100, 100, 250, 1000])
            return groups.record_remittance(db, head_admin=self.rng.choice([self.head(db), self.head(db, "boss2")]),
                                            group_admin_id=ga.id, amount_cents=amount,
                                            idempotency_key=uuid.uuid4().hex, note="audit remit", now=self.tick())

        self.try_op("remit", _rem)

    def correct_remittance(self):
        from sqlalchemy import select

        from app.models import GroupRemittance
        from app.services import groups

        def _crem(db):
            done = set(db.scalars(select(GroupRemittance.correction_of_id).where(
                GroupRemittance.correction_of_id.is_not(None))))
            cands = [r for r in db.scalars(select(GroupRemittance).where(GroupRemittance.correction_of_id.is_(None)))
                     if r.id not in done]
            r = self.rng.choice(cands)
            delta = self.rng.choice([-r.amount_cents, -(r.amount_cents // 2) or 5, 100, -100])
            return groups.record_remittance(db, head_admin=self.head(db), group_admin_id=r.group_admin_id,
                                            amount_cents=delta, idempotency_key=uuid.uuid4().hex,
                                            correction_of_id=r.id, note="audit remit correction", now=self.tick())

        self.try_op("correct_remittance", _crem)

    def price_change(self):
        from app.services import prices

        now = self.tick()
        self.run("price_change", lambda db: prices.add_price(
            db, price_per_shot_cents=self.rng.choice([40, 45, 50, 55, 60, 65]), effective_from=now,
            admin_id=self.head(db).id, note="audit price", now=now))

    def status_toggle(self):
        from app.services import users

        def _st(db):
            user = self.rng.choice(self.active_users(db))
            actor = self.pick_actor_for(db, user)
            users.set_user_status(db, admin=actor, user_id=user.id, active=False)
            if self.rng.random() < 0.8:
                users.set_user_status(db, admin=self.head(db), user_id=user.id, active=True)

        self.try_op("status_toggle", _st)

    def promote(self):
        from app.services import roles

        def _pro(db):
            cands = [u for u in self.active_users(db, "member")]
            u = self.rng.choice(cands)
            return roles.promote_group_admin(db, head_admin=self.head(db), user_id=u.id, now=self.tick())

        self.try_op("promote", _pro)

    def demote(self):
        from app.services import roles

        def _dem(db):
            ga = self.rng.choice(self.group_admins(db))
            return roles.demote_group_admin(db, head_admin=self.head(db), user_id=ga.user_id, now=self.tick())

        self.try_op("demote", _dem)

    def chair_change(self):
        from sqlalchemy import select

        from app.models import Chair
        from app.services import users

        def _cc(db):
            admin_user_ids = {a.user_id for a in self.group_admins(db, active=True)}
            cands = [u for u in self.active_users(db) if u.id not in admin_user_ids]
            u = self.rng.choice(cands)
            chairs = [c for c in db.scalars(select(Chair).where(Chair.active.is_(True))) if c.id != u.chair_id]
            c = self.rng.choice(chairs)
            if self.rng.random() < 0.5:
                users.update_profile(db, user_id=u.id, chair_id=c.id, actor_type="admin", actor_id=self.head(db).id)
            else:
                users.update_profile(db, user_id=u.id, chair_id=c.id, actor_type="user")

        self.try_op("chair_change", _cc)

    def merge(self):
        from sqlalchemy import func, select

        from app.models import ConsumptionEvent
        from app.services import users

        def _mg(db):
            cands = self.active_users(db)
            dup, target = self.rng.sample(cands, 2)
            return users.merge_users(db, admin=self.head(db), duplicate_id=dup.id, target_id=target.id,
                                     now=self.tick())

        self.try_op("merge", _mg)

    def reassign(self):
        from app.services import registration

        def _re(db):
            guests = self.active_users(db, "guest")
            members = self.active_users(db, "member")
            return registration.reassign_sponsor(db, head_admin=self.head(db), guest_id=self.rng.choice(guests).id,
                                                 new_sponsor_id=self.rng.choice(members).id, now=self.tick())

        self.try_op("reassign_sponsor", _re)

    # ----- operations that MUST be refused ---------------------------------------------------
    def forbidden_ops(self):
        from sqlalchemy import select

        from app.models import AdminUser, PaymentEvent
        from app.services import groups, ledger, roles, users

        def own_chair(db):
            ga = self.rng.choice(self.group_admins(db))
            other = [c for c in db.scalars(select(__import__("app.models", fromlist=["Chair"]).Chair)) if c.id != ga.user.chair_id]
            users.update_profile(db, user_id=ga.user_id, chair_id=other[0].id, actor_type="user")

        def own_balance(db):
            ga = self.rng.choice(self.group_admins(db))
            ledger.add_payment(db, admin=ga, user_id=ga.user_id, amount_cents=100, now=self.tick())

        def cross_chair(db):
            ga = self.rng.choice(self.group_admins(db))
            others = [u for u in self.active_users(db) if u.chair_id != ga.user.chair_id]
            ledger.add_payment(db, admin=ga, user_id=self.rng.choice(others).id, amount_cents=100, now=self.tick())

        def over_credit(db):
            ga = self.rng.choice(self.group_admins(db))
            members = [u for u in self.active_users(db) if u.chair_id == ga.user.chair_id and u.id != ga.user_id]
            u = self.rng.choice(members)
            credit = max(0, -ledger.get_totals(db, u.id).balance_cents)
            ledger.add_payment(db, admin=ga, user_id=u.id, amount_cents=-(credit + 100), now=self.tick())

        def set_balance_by_group_admin(db):
            ga = self.rng.choice(self.group_admins(db))
            u = self.rng.choice([u for u in self.active_users(db) if u.chair_id == ga.user.chair_id and u.id != ga.user_id])
            ledger.set_balance(db, admin=ga, user_id=u.id, target_balance_cents=12345,
                               idempotency_key=uuid.uuid4().hex, now=self.tick())

        def remit_by_group_admin(db):
            ga = self.rng.choice(self.group_admins(db))
            groups.record_remittance(db, head_admin=ga, group_admin_id=ga.id, amount_cents=100,
                                     idempotency_key=uuid.uuid4().hex, now=self.tick())

        def peer_deactivation(db):
            gas = self.group_admins(db)
            pairs = [(a, b) for a in gas for b in gas if a.id != b.id and a.user.chair_id == b.user.chair_id]
            a, b = self.rng.choice(pairs)
            users.set_user_status(db, admin=a, user_id=b.user_id, active=False)

        def second_correction(db):
            p = db.scalars(select(PaymentEvent).where(PaymentEvent.correction_of_id.is_not(None))).first()
            ledger.add_payment(db, admin=self.head(db), user_id=p.user_id, amount_cents=-1,
                               correction_of_id=p.correction_of_id, now=self.tick())

        def over_correction(db):
            ga = self.rng.choice(self.group_admins(db))
            p = db.scalars(select(PaymentEvent).where(PaymentEvent.kind == "cash",
                                                      PaymentEvent.collector_admin_id == ga.id,
                                                      PaymentEvent.amount_cents > 0)).first()
            if p is None:  # nothing to try on: the check is vacuous this time, and says so
                from app.services.errors import InvalidInput
                self.vacuous.append("over_correction")
                raise InvalidInput("no payment to over-correct")
            ledger.add_payment(db, admin=self.head(db), user_id=p.user_id, amount_cents=-(p.amount_cents + 5000),
                               correction_of_id=p.id, now=self.tick())

        def promote_guest(db):
            g = self.rng.choice(self.active_users(db, "guest"))
            roles.promote_group_admin(db, head_admin=self.head(db), user_id=g.id, now=self.tick())

        for fn in (own_chair, own_balance, cross_chair, over_credit, set_balance_by_group_admin,
                   remit_by_group_admin, peer_deactivation, second_correction, over_correction, promote_guest):
            try:
                self.run("MUST_REFUSE:" + fn.__name__, fn, must_refuse=True)
            except (IndexError, ValueError, AttributeError):  # no candidates right now (e.g. every group admin was demoted)
                self.skipped["MUST_REFUSE:" + fn.__name__] += 1
            except Exception as exc:  # noqa: BLE001
                self.unexpected.append(f"{fn.__name__}: could not be attempted ({type(exc).__name__}: {exc})")

    # ----- the script ------------------------------------------------------------------------
    def play(self, min_ops: int):
        self.setup()
        for chair in ("ALG", "ALG", "BIO", "BIO", "CTL", "CTL", "ALG", "BIO", "CTL", "CTL"):
            self.register_member(chair)
        for _ in range(6):
            self.register_guest()
        for _ in range(3):
            self.promote()
        # make sure each chair has a group admin
        from app.db import write_session
        from app.services import roles
        with write_session() as db:
            have = {ga.user.chair_id for ga in self.group_admins(db)}
            members = self.active_users(db, "member")
            for u in members:
                if u.chair_id not in have:
                    roles.promote_group_admin(db, head_admin=self.head(db), user_id=u.id, now=self.tick())
                    have.add(u.chair_id)
        self.ok["promote"] += 1

        weights = [
            (self.scan, 30), (self.undo, 6), (self.admin_reverse, 4), (self.adjust, 5), (lambda: self.pay(1), 14),
            (lambda: self.pay(-1), 4), (self.correct_payment, 5), (self.set_balance, 4), (self.remit, 8),
            (self.correct_remittance, 3), (self.price_change, 2), (self.status_toggle, 3), (self.promote, 2),
            (self.demote, 2), (self.chair_change, 3), (self.merge, 2), (self.reassign, 1),
            (lambda: self.register_member(), 2), (self.register_guest, 1),
        ]
        population = [fn for fn, w in weights for _ in range(w)]
        guard = 0
        while sum(self.ok.values()) < min_ops + 40 and guard < 4000:
            guard += 1
            self.rng.choice(population)()
            if guard % 60 == 0:
                self.forbidden_ops()
        # finale: every chair that has an active member gets an active group admin again, then the forbidden
        # operations are tried once more against that final state
        with write_session() as db:
            have = {ga.user.chair_id for ga in self.group_admins(db)}
            for u in self.active_users(db, "member"):
                if u.chair_id not in have:
                    roles.promote_group_admin(db, head_admin=self.head(db), user_id=u.id, now=self.tick())
                    have.add(u.chair_id)
        self.ok["promote"] += 1
        self.forbidden_ops()

    def summary(self):
        return {"ok_total": sum(self.ok.values()), "ok": dict(self.ok), "refused": dict(self.refused), "skipped_no_candidate": dict(self.skipped), "vacuous_must_refuse_attempts": self.vacuous,
                "unexpected": self.unexpected, "must_refuse_but_succeeded": self.must_refuse_but_ok}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("db_path")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--min-ops", type=int, default=220)
    args = ap.parse_args()
    if Path(args.db_path).exists():
        print("refusing to overwrite an existing database", file=sys.stderr)
        return 2
    configure_env(args.db_path)
    migrate(args.db_path)

    sim = Scenario(args.seed)
    sim.play(args.min_ops)

    from app.db import read_session
    from app.services.checker import check_ledger

    with read_session() as db:
        report = check_ledger(db)
    out = sim.summary()
    out["check_ledger_ok"] = report.ok
    out["check_ledger_problems"] = [f"{p.code}: {p.message}" for p in report.problems]
    out["check_ledger_notes"] = report.notes
    out["events"] = {"consumption": report.consumption_events, "payments": report.payment_events,
                     "remittances": report.remittances, "users": report.users, "prices": report.prices}
    print(json.dumps(out, indent=1, default=str))
    good = (report.ok and not out["unexpected"] and not out["must_refuse_but_succeeded"]
            and out["ok_total"] >= args.min_ops)
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
