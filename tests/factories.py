"""Test data factories (core-a). Names and signatures are stable; other agents rely on them.

All factories take the ORM session first and commit by default (`commit=False` to only flush).

make_chair(db, short_name=None, full_name=None, active=True)            -> Chair
make_user(db, display_name="Test User", chair=None, status="active")     -> User   (creates a chair if None)
make_member(db, display_name, chair=None, username=None, email=None)       -> User   (v2 member)
make_guest(db, sponsor, display_name, username=None)                      -> User   (v2 guest)
make_admin(db, role="global", chairs=(), username=None, active=True,
           password_hash="!")                                            -> AdminUser
           (role "chair" = group admin: creates a linked member in chairs[0] or a new chair)
           (password_hash "!" matches no password; admin-auth tests set a real hash)
set_price(db, cents=50, effective_from=None, admin=None)                 -> Price
           (direct insert, may be backdated; default effective_from = now - 1 day)
add_events(db, user, kinds, at=None, session_id=None)                    -> list[ConsumptionEvent]
           (records "single"/"double" via ledger.record_coffee at time `at`; needs a price)
make_payment(db, user, admin, cents, at=None, note=None)                 -> PaymentEvent
make_session(db, user, raw_token=None, expires_in=timedelta(days=180))   -> UserSession
           (stores sha256(raw_token); for core tests only — core-b's sessions.py is canonical)
"""

from __future__ import annotations

import hashlib
import itertools
import secrets
import uuid
from datetime import datetime, timedelta

from app.models import AdminUser, Chair, ConsumptionEvent, PaymentEvent, Price, User, UserSession
from app.services import ledger
from app.services.users import normalize_name
from app.timeutil import utcnow

_seq = itertools.count(1)


def _done(db, obj, commit: bool):
    if commit:
        db.commit()
    else:
        db.flush()
    return obj


def make_chair(db, short_name: str | None = None, full_name: str | None = None, active: bool = True,
               commit: bool = True) -> Chair:
    n = next(_seq)
    chair = Chair(short_name=short_name or f"C{n}", full_name=full_name or f"Chair {n}", active=active)
    db.add(chair)
    return _done(db, chair, commit)


def make_user(db, display_name: str = "Test User", chair: Chair | None = None, status: str = "active",
              commit: bool = True) -> User:
    if chair is None:
        chair = make_chair(db, commit=False)
    user = User(display_name=display_name, normalized_name=normalize_name(display_name), chair_id=chair.id,
                status=status, last_activity_at=utcnow())
    db.add(user)
    return _done(db, user, commit)


def make_member(db, display_name: str = "Test Member", chair: Chair | None = None, username: str | None = None,
                email: str | None = None, password_hash: str = "!", commit: bool = True) -> User:
    """A v2 member account (username, TUM-style email, verified)."""
    n = next(_seq)
    username = username or f"member{n}"
    user = make_user(db, display_name, chair, commit=False)
    user.username, user.username_normalized = username, username.casefold()
    user.account_kind, user.email = "member", email or f"{username}@tum.de"
    user.password_hash, user.verified_at = password_hash, utcnow()
    return _done(db, user, commit)


def make_guest(db, sponsor: User, display_name: str = "Test Guest", username: str | None = None,
               password_hash: str = "!", commit: bool = True) -> User:
    """A v2 guest account vouched for by `sponsor` (chair inherited from the sponsor)."""
    username = username or f"guest{next(_seq)}"
    user = make_user(db, display_name, sponsor.chair, commit=False)
    user.username, user.username_normalized = username, username.casefold()
    user.account_kind, user.sponsor_id = "guest", sponsor.id
    user.password_hash, user.verified_at = password_hash, utcnow()
    return _done(db, user, commit)


def make_admin(db, role: str = "global", chairs=(), username: str | None = None, active: bool = True,
               password_hash: str = "!", commit: bool = True) -> AdminUser:
    username = username or f"admin{next(_seq)}"
    linked = None
    if role == "chair":
        # v2: a group admin is linked to a member account; its chair is the user's chair.
        linked = make_member(db, chair=chairs[0] if chairs else None, username=f"member-{username}", commit=False)
    admin = AdminUser(username=username, username_normalized=username.casefold(), password_hash=password_hash,
                      role=role, active=active, recovery_codes=[], user_id=linked.id if linked else None)
    db.add(admin)
    db.flush()
    db.refresh(admin)
    return _done(db, admin, commit)


def set_price(db, cents: int = 50, effective_from: datetime | None = None, admin: AdminUser | None = None,
              commit: bool = True) -> Price:
    price = Price(price_per_shot_cents=cents, effective_from=effective_from or utcnow() - timedelta(days=1),
                  created_by_admin_id=admin.id if admin else None)
    db.add(price)
    return _done(db, price, commit)


def add_events(db, user: User, kinds, at: datetime | None = None, session_id: uuid.UUID | None = None,
               commit: bool = True) -> list[ConsumptionEvent]:
    if isinstance(kinds, str):
        kinds = [kinds]
    events = []
    for i, kind in enumerate(kinds):
        when = (at or utcnow()) + timedelta(microseconds=i)
        result = ledger.record_coffee(db, user_id=user.id, kind=kind, nonce=secrets.token_urlsafe(16),
                                      session_id=session_id, now=when)
        events.append(result.event)
    return _done(db, events, commit)


def make_payment(db, user: User, admin: AdminUser, cents: int, at: datetime | None = None, note: str | None = None,
                 commit: bool = True) -> PaymentEvent:
    payment = ledger.add_payment(db, admin=admin, user_id=user.id, amount_cents=cents, note=note, now=at)
    return _done(db, payment, commit)


def make_session(db, user: User, raw_token: str | None = None, expires_in: timedelta = timedelta(days=180),
                 commit: bool = True) -> UserSession:
    raw_token = raw_token or secrets.token_urlsafe(32)
    now = utcnow()
    session = UserSession(user_id=user.id, token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
                          created_at=now, last_seen_at=now, expires_at=now + expires_in)
    db.add(session)
    return _done(db, session, commit)
