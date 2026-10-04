"""Sign-in helpers shared by login and e-mail verification (PLAN-v2 section 1), in the caller's ONE write
transaction.

Order: issue a NEW session (revoking the browser's previous one) -> atomically consume the pending action ->
`record_coffee` with the stored nonce and the new session id (price looked up now). A pending `view_site`
action is consumed too and only reported (`coffee_status == COFFEE_VIEW_SITE`); the route then redirects to
`/overview` (a fixed path, nothing travels in the URL). A pending coffee that cannot be recorded (no price
configured) never aborts the caller: the savepoint is rolled back, the pending action stays unconsumed, and
`coffee_status` tells the route what to show.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from app.models import ConsumptionEvent, User, UserSession
from app.services import sessions
from app.services.errors import NoPriceConfigured
from app.services.ledger import record_coffee
from app.services.pending import VIEW_SITE_KIND, consume_pending
from app.timeutil import ensure_utc, utcnow

# coffee_status values
COFFEE_NONE = "none"          # no pending action given
COFFEE_RECORDED = "recorded"  # event holds the coffee (new, or recorded by an earlier submit)
COFFEE_EXPIRED = "expired"    # pending action expired / already consumed / not found
COFFEE_NO_PRICE = "no_price"  # no price configured; nothing recorded, pending kept
COFFEE_VIEW_SITE = "view_site"  # a pending "view the website" action was consumed; no coffee involved


@dataclass
class OnboardResult:
    user: User
    raw_token: str
    session: UserSession
    event: ConsumptionEvent | None
    coffee_status: str = COFFEE_NONE
    created: bool = True  # always True: kept for the registration tests, which still read it


def _now(now: datetime | None) -> datetime:
    return ensure_utc(now) if now is not None else utcnow()


def _start_session(db: Session, user: User, old_session_id: uuid.UUID | None, now: datetime):
    if old_session_id is not None:
        sessions.revoke_session(db, old_session_id, now)
    return sessions.create_session(db, user.id, now)


def _consume_and_record(db: Session, user: User, session: UserSession, pending_id: str | None,
                        now: datetime) -> tuple[ConsumptionEvent | None, str]:
    if not pending_id:
        return None, COFFEE_NONE
    try:
        with db.begin_nested():
            action = consume_pending(db, pending_id, now)
            if action is None:
                return None, COFFEE_EXPIRED
            if action.kind == VIEW_SITE_KIND:
                return None, COFFEE_VIEW_SITE
            result = record_coffee(db, user_id=user.id, kind=action.kind, nonce=action.nonce,
                                   session_id=session.id, now=now)
    except NoPriceConfigured:
        return None, COFFEE_NO_PRICE
    if result.event.user_id != user.id:
        # The scan token was already used by another browser/profile; never show their event.
        return None, COFFEE_EXPIRED
    return result.event, COFFEE_RECORDED


def start_session_and_record(db: Session, user: User, *, pending_id: str | None = None,
                             old_session_id: uuid.UUID | None = None,
                             now: datetime | None = None) -> OnboardResult:
    """Issue a NEW session for `user` (revoking `old_session_id`) and consume the browser's pending action, if
    any: a coffee is recorded (exactly once, even for concurrent callers), a `view_site` action is reported."""
    now = _now(now)
    session, raw = _start_session(db, user, old_session_id, now)
    event, status = _consume_and_record(db, user, session, pending_id, now)
    return OnboardResult(user, raw, session, event, status)
