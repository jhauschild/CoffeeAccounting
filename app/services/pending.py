"""Pending scan actions (PROMPT §3 step 3–5).

A scan without a valid session stores the action server-side (`pending_actions`) and the
browser only gets an HttpOnly cookie holding the random opaque id. After login or e-mail
verification the action is consumed atomically (see `consume_pending`).

Kinds: `single`, `double` (a coffee, recorded after sign-in) and `view_site` (the browser asked for
`/overview` without a session; after sign-in it is sent there). A pending action carries no redirect
parameter: the target of each kind is fixed in the route code.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models import PENDING_ACTION_KINDS, PendingAction
from app.services.errors import InvalidInput
from app.timeutil import ensure_utc, utcnow

PENDING_COOKIE = "coffee_pending"
PENDING_TTL = timedelta(hours=1)
MAX_PENDING_ID_LENGTH = 64
MAX_NONCE_LENGTH = 80
VIEW_SITE_KIND = "view_site"


def _now(now: datetime | None) -> datetime:
    return ensure_utc(now) if now is not None else utcnow()


def create_pending(db: Session, kind: str, nonce: str, now: datetime | None = None) -> str:
    """Store a pending action (`single`, `double` or `view_site`) for a nonce and return its opaque id.

    Idempotent on `nonce`: a replayed scan token returns the existing row's id (whether or
    not it was consumed; consuming it again is impossible).
    """
    if kind not in PENDING_ACTION_KINDS:
        raise InvalidInput("invalid pending action kind")
    if not nonce or len(nonce) > MAX_NONCE_LENGTH:
        raise InvalidInput("invalid nonce")
    existing = db.scalars(select(PendingAction.id).where(PendingAction.nonce == nonce)).first()
    if existing is not None:
        return existing
    now = _now(now)
    pending_id = secrets.token_urlsafe(32)
    db.add(PendingAction(id=pending_id, kind=kind, nonce=nonce, created_at=now, expires_at=now + PENDING_TTL))
    db.flush()
    return pending_id


def create_view_site_pending(db: Session, now: datetime | None = None) -> str:
    """Pending "view the website" action for an anonymous visit of `/overview`; returns its opaque id.
    Every call stores a new row (there is no scan token to replay), expiring like any pending action."""
    return create_pending(db, VIEW_SITE_KIND, secrets.token_urlsafe(24), now)


def _valid_id(pending_id: str | None) -> bool:
    return bool(pending_id) and isinstance(pending_id, str) and len(pending_id) <= MAX_PENDING_ID_LENGTH


def get_pending(db: Session, pending_id: str | None, now: datetime | None = None) -> PendingAction | None:
    """The pending action if it exists, is unconsumed and unexpired (for display only)."""
    if not _valid_id(pending_id):
        return None
    action = db.get(PendingAction, pending_id)
    if action is None or action.consumed_at is not None or ensure_utc(action.expires_at) <= _now(now):
        return None
    return action


def consume_pending(db: Session, pending_id: str | None, now: datetime | None = None) -> PendingAction | None:
    """Atomically mark the action consumed. Returns it only if *this* call consumed it.

    `UPDATE … WHERE consumed_at IS NULL AND expires_at > now`; proceeds only if exactly
    one row changed, so two concurrent consumers can never both succeed.
    """
    if not _valid_id(pending_id):
        return None
    now = _now(now)
    result = db.execute(
        update(PendingAction)
        .where(PendingAction.id == pending_id, PendingAction.consumed_at.is_(None), PendingAction.expires_at > now)
        .values(consumed_at=now)
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        return None
    action = db.get(PendingAction, pending_id)
    db.refresh(action)
    return action
