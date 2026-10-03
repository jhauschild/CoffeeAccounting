"""Normal-user browser sessions (PROMPT §5).

The cookie carries a random 256-bit opaque token; only its SHA-256 hash is stored (a fast
hash is correct for a high-entropy random token). A session is valid while it is not
revoked, not expired, and its user is `active` (deactivated or merged users are rejected
immediately). `last_seen_at` is written at most once per hour.

The session layer is independent of the ledger: ledger rows only reference `user_id`
(and optionally the session id that created them).
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import User, UserSession
from app.timeutil import ensure_utc, utcnow

SESSION_COOKIE = "coffee_session"
TOKEN_BYTES = 32  # 256 bit
TOUCH_INTERVAL = timedelta(hours=1)
MAX_RAW_TOKEN_LENGTH = 100


def _now(now: datetime | None) -> datetime:
    return ensure_utc(now) if now is not None else utcnow()


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def create_session(db: Session, user_id: uuid.UUID, now: datetime | None = None) -> tuple[UserSession, str]:
    """Insert a new session row; return it together with the raw token (shown once)."""
    now = _now(now)
    raw = secrets.token_urlsafe(TOKEN_BYTES)
    lifetime = timedelta(days=get_settings().session_lifetime_days)
    session = UserSession(user_id=user_id, token_hash=hash_token(raw), created_at=now, last_seen_at=now,
                          expires_at=now + lifetime)
    db.add(session)
    db.flush()
    return session, raw


def issue_session(db: Session, user_id: uuid.UUID, now: datetime | None = None) -> str:
    """Create a session for `user_id` and return the raw token for the cookie."""
    return create_session(db, user_id, now)[1]


def needs_touch(session: UserSession, now: datetime | None = None) -> bool:
    return ensure_utc(session.last_seen_at) <= _now(now) - TOUCH_INTERVAL


def touch_session(db: Session, session_id: uuid.UUID, now: datetime | None = None) -> bool:
    """Set `last_seen_at = now` unless it was updated within the last hour. Returns True if written."""
    now = _now(now)
    result = db.execute(
        update(UserSession)
        .where(UserSession.id == session_id, UserSession.last_seen_at <= now - TOUCH_INTERVAL)
        .values(last_seen_at=now)
        .execution_options(synchronize_session=False)
    )
    return result.rowcount == 1


def resolve_session(db: Session, raw_token: str | None, now: datetime | None = None, *,
                    touch: bool = True) -> tuple[UserSession, User] | None:
    """Return (session, user) for a valid token, else None.

    With `touch=True` (the default) `last_seen_at` is updated at most once per hour; this
    only persists if `db` is a write transaction. Callers on a read session pass
    `touch=False` and use `needs_touch()` + `touch_session()` in a write session.
    """
    if not raw_token or len(raw_token) > MAX_RAW_TOKEN_LENGTH:
        return None
    now = _now(now)
    row = db.execute(
        select(UserSession, User)
        .join(User, User.id == UserSession.user_id)
        .where(UserSession.token_hash == hash_token(raw_token))
    ).first()
    if row is None:
        return None
    session, user = row
    if session.revoked_at is not None or ensure_utc(session.expires_at) <= now or user.status != "active":
        return None
    if touch and needs_touch(session, now):
        touch_session(db, session.id, now)
        session.last_seen_at = now
    return session, user


def revoke_session(db: Session, session_id: uuid.UUID, now: datetime | None = None) -> bool:
    """Revoke one session (idempotent). Returns True if it was active before."""
    result = db.execute(
        update(UserSession)
        .where(UserSession.id == session_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=_now(now))
        .execution_options(synchronize_session=False)
    )
    return result.rowcount == 1


def revoke_user_sessions(db: Session, user_id: uuid.UUID, now: datetime | None = None) -> int:
    """Revoke all of a user's active sessions; returns how many were revoked."""
    result = db.execute(
        update(UserSession)
        .where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=_now(now))
        .execution_options(synchronize_session=False)
    )
    return result.rowcount


def active_session_count(db: Session, user_id: uuid.UUID, now: datetime | None = None) -> int:
    """Number of unrevoked, unexpired sessions (for admin user detail pages)."""
    now = _now(now)
    return len(db.scalars(
        select(UserSession.id).where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None),
                                     UserSession.expires_at > now)
    ).all())
