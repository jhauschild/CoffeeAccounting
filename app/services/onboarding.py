"""Registration and profile selection, each in the caller's ONE write transaction
(PROMPT §3 step 4, §5).

Order: (create user) → issue a NEW session (revoking the browser's previous one) →
atomically consume the pending action → `record_coffee` with the stored nonce and the new
session id (price looked up now). The caller wraps the call in `write_session()`.

Registration double-submit protection
-------------------------------------
The registration form carries a signed one-time registration token (see
`app.web.tokens.make_registration_token`) whose random nonce determines the new user's id:
``user_id = HMAC(SECRET_KEY, "register:" + nonce)`` truncated to a UUID. The primary key
therefore makes the token single-use at the database level: a second submit with the same
token finds the already-created profile and returns it (with the coffee recorded by the
first submit) instead of creating a second profile or coffee. Nothing extra is stored.

A pending coffee that cannot be recorded (no price configured) does not abort the
registration: the savepoint is rolled back, the pending action stays unconsumed, and
`coffee_status` tells the route what to show.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Chair, ConsumptionEvent, PendingAction, User, UserSession
from app.services import sessions, signing
from app.services.errors import InvalidInput, NoPriceConfigured, NotFound, UserInactive
from app.services.ledger import record_coffee
from app.services.pending import consume_pending
from app.services.users import clean_display_name, normalize_name
from app.timeutil import ensure_utc, utcnow

# coffee_status values
COFFEE_NONE = "none"          # no pending action given
COFFEE_RECORDED = "recorded"  # event holds the coffee (new, or recorded by an earlier submit)
COFFEE_EXPIRED = "expired"    # pending action expired / already consumed / not found
COFFEE_NO_PRICE = "no_price"  # no price configured; nothing recorded, pending kept


@dataclass
class OnboardResult:
    user: User
    raw_token: str
    session: UserSession
    event: ConsumptionEvent | None
    coffee_status: str = COFFEE_NONE
    created: bool = True  # False when a duplicate registration submit returned the existing profile


def _now(now: datetime | None) -> datetime:
    return ensure_utc(now) if now is not None else utcnow()


def registration_user_id(registration_nonce: str) -> uuid.UUID:
    digest = bytes.fromhex(signing.mac("register-user", registration_nonce))
    return uuid.UUID(bytes=digest[:16], version=4)


def _start_session(db: Session, user: User, old_session_id: uuid.UUID | None, now: datetime):
    if old_session_id is not None:
        sessions.revoke_session(db, old_session_id, now)
    return sessions.create_session(db, user.id, now)


def _event_for_pending(db: Session, pending_id: str | None, user_id: uuid.UUID) -> ConsumptionEvent | None:
    if not pending_id:
        return None
    nonce = db.scalar(select(PendingAction.nonce).where(PendingAction.id == pending_id))
    if nonce is None:
        return None
    return db.scalars(select(ConsumptionEvent).where(ConsumptionEvent.idempotency_key == nonce,
                                                     ConsumptionEvent.user_id == user_id)).first()


def _consume_and_record(db: Session, user: User, session: UserSession, pending_id: str | None,
                        now: datetime) -> tuple[ConsumptionEvent | None, str]:
    if not pending_id:
        return None, COFFEE_NONE
    try:
        with db.begin_nested():
            action = consume_pending(db, pending_id, now)
            if action is None:
                return None, COFFEE_EXPIRED
            result = record_coffee(db, user_id=user.id, kind=action.kind, nonce=action.nonce,
                                   session_id=session.id, now=now)
    except NoPriceConfigured:
        return None, COFFEE_NO_PRICE
    if result.event.user_id != user.id:
        # The scan token was already used by another browser/profile; never show their event.
        return None, COFFEE_EXPIRED
    return result.event, COFFEE_RECORDED


def _new_user(db: Session, *, user_id: uuid.UUID | None, display_name: str, chair_id: uuid.UUID,
              now: datetime) -> User:
    # Mirrors users.create_user, but with a caller-chosen id (see module docstring).
    name = clean_display_name(display_name)
    chair = db.get(Chair, chair_id) if chair_id is not None else None
    if chair is None or not chair.active:
        raise InvalidInput("unknown or inactive chair")
    user = User(display_name=name, normalized_name=normalize_name(name), chair_id=chair.id, status="active",
                created_at=now, last_activity_at=now)
    if user_id is not None:
        user.id = user_id
    db.add(user)
    db.flush()
    return user


def register_and_start_session(
    db: Session,
    *,
    display_name: str,
    chair_id: uuid.UUID,
    pending_id: str | None = None,
    registration_nonce: str | None = None,
    old_session_id: uuid.UUID | None = None,
    now: datetime | None = None,
) -> OnboardResult:
    """Create a profile, start a new session and record the pending coffee (if any).

    Raises `InvalidInput` (bad name / chair) or `UserInactive` (a duplicate submit whose
    profile has meanwhile been deactivated or merged).
    """
    now = _now(now)
    user_id = registration_user_id(registration_nonce) if registration_nonce else None
    if user_id is not None:
        existing = db.get(User, user_id)
        if existing is not None:
            if existing.status != "active":
                raise UserInactive("profile is not active")
            session, raw = _start_session(db, existing, old_session_id, now)
            event = _event_for_pending(db, pending_id, existing.id)
            status = COFFEE_RECORDED if event is not None else (COFFEE_EXPIRED if pending_id else COFFEE_NONE)
            return OnboardResult(existing, raw, session, event, status, created=False)
    user = _new_user(db, user_id=user_id, display_name=display_name, chair_id=chair_id, now=now)
    session, raw = _start_session(db, user, old_session_id, now)
    event, status = _consume_and_record(db, user, session, pending_id, now)
    return OnboardResult(user, raw, session, event, status, created=True)


def select_profile_and_start_session(
    db: Session,
    *,
    user_id: uuid.UUID,
    pending_id: str | None = None,
    old_session_id: uuid.UUID | None = None,
    now: datetime | None = None,
) -> OnboardResult:
    """Switch this browser to an existing active profile (rotating the session) and record
    the pending coffee (if any). Raises `NotFound` or `UserInactive` (inactive/merged)."""
    now = _now(now)
    user = db.get(User, user_id) if isinstance(user_id, uuid.UUID) else None
    if user is None:
        raise NotFound("profile not found")
    if user.status != "active":
        raise UserInactive("profile is not active")
    session, raw = _start_session(db, user, old_session_id, now)
    event, status = _consume_and_record(db, user, session, pending_id, now)
    return OnboardResult(user, raw, session, event, status, created=False)
