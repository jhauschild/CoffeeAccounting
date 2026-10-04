"""Mail status that survives across processes (the server and the CLI are different processes).

`mail.get_status()` is per process and lost on restart, so the server also leaves minimal, PII-free traces in
the audit log and `mail-status` / the head admin dashboard read the latest ones from there:

* `mail.send_failed`  metadata `{"category": "<safe category>"}` only (never an address, host, text or login);
* `mail.send_ok`      no metadata.

Both are written by `mail.send_in_background` (and therefore by `test-mail`) AFTER the send, in a short write
session of their own, and are coalesced: a row is skipped when the most recent mail row is the same kind (same
category for a failure) and younger than `COALESCE_SECONDS` (10 minutes). A flip (failure after success, success
after failure, another category) is always written, so the "latest of each kind" shown is at most 10 minutes
stale in time but never wrong in state. Persisting is best effort: it never raises into a mail send.

Read side: `read_status(db)` returns a `mail.MailStatus` (so `.cap_reached` works unchanged) and `card(db)` the
complete head-admin view: stored login (`mail_credentials.status()`: configured, masked user, unreadable) plus
the last send state and one `banner` (`not_configured` | `cap_reached` | `failing` | None).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import AuditLog
from app.services import audit, mail, mail_credentials
from app.timeutil import ensure_utc, utcnow

log = logging.getLogger("app.mail")

ACTION_OK = "mail.send_ok"
ACTION_FAILED = "mail.send_failed"
COALESCE_SECONDS = 600
_ACTIONS = (ACTION_OK, ACTION_FAILED)

BANNER_NOT_CONFIGURED = "not_configured"
BANNER_CAP_REACHED = "cap_reached"
BANNER_FAILING = "failing"


def _latest_mail_row(db: Session) -> AuditLog | None:
    return db.scalars(select(AuditLog).where(AuditLog.action.in_(_ACTIONS)).order_by(AuditLog.id.desc())).first()


def _coalesced(last: AuditLog | None, action: str, category: str | None, now: datetime) -> bool:
    if last is None or last.action != action:
        return False
    if action == ACTION_FAILED and (last.meta or {}).get("category") != category:
        return False
    return ensure_utc(now) - ensure_utc(last.created_at) < timedelta(seconds=COALESCE_SECONDS)


def persist(db: Session, category: str | None, now: datetime | None = None) -> bool:
    """Add the audit row for one send result (`None` = success) unless coalesced. Does not commit.
    Returns True when a row was added."""
    now = now or utcnow()
    if category is None:
        action, meta = ACTION_OK, None
    else:
        category = category if category in mail.CATEGORIES else "other"
        action, meta = ACTION_FAILED, {"category": category}
    if _coalesced(_latest_mail_row(db), action, category, now):
        return False
    audit.log(db, actor_type="system", action=action, target_type="mail", metadata=meta, now=now)
    return True


def record(category: str | None) -> None:
    """Persist one send result in its own write session. Never raises (status is best effort)."""
    from app.db import write_session

    try:
        with write_session() as db:
            persist(db, category)
    except Exception:  # busy or unmigrated database: the in-process status still works
        log.warning("mail status not persisted")


def read_status(db: Session) -> mail.MailStatus:
    """Latest send OK and latest failure from the audit log."""
    def latest(action: str) -> AuditLog | None:
        return db.scalars(select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.id.desc())).first()

    ok, failed = latest(ACTION_OK), latest(ACTION_FAILED)
    return mail.MailStatus(
        last_ok_at=ensure_utc(ok.created_at) if ok else None,
        last_failure_category=(failed.meta or {}).get("category", "other") if failed else None,
        last_failure_at=ensure_utc(failed.created_at) if failed else None,
    )


@dataclass(frozen=True)
class MailCard:
    backend: str  # smtp | console | memory | file
    configured: bool  # a readable login is stored
    masked_username: str | None
    unreadable: bool
    needs_login: bool  # the backend is smtp: a login is required to send anything
    last_ok_at: datetime | None
    last_failure_category: str | None
    last_failure_at: datetime | None
    cap_reached: bool
    max_per_hour: int  # MAIL_MAX_PER_HOUR
    banner: str | None  # BANNER_*

    @property
    def failing(self) -> bool:
        """The most recent send failed (for a reason other than the cap) and nothing succeeded since."""
        if self.last_failure_category is None or self.last_failure_category == "cap_exceeded":
            return False
        return self.last_ok_at is None or self.last_failure_at > self.last_ok_at


def card(db: Session) -> MailCard:
    """Everything the page and `mail-status` show. Never contains the password."""
    settings = get_settings()
    backend = settings.mail_backend or ("smtp" if settings.is_production else "console")
    login = mail_credentials.status()
    status = read_status(db)
    needs_login = backend == "smtp"
    view = MailCard(
        backend=backend, configured=login.configured, masked_username=login.masked_username,
        unreadable=login.unreadable, needs_login=needs_login, last_ok_at=status.last_ok_at,
        last_failure_category=status.last_failure_category, last_failure_at=status.last_failure_at,
        cap_reached=status.cap_reached, max_per_hour=settings.mail_max_per_hour, banner=None)
    banner = None
    if needs_login and not login.configured:
        banner = BANNER_NOT_CONFIGURED
    elif view.cap_reached:
        banner = BANNER_CAP_REACHED
    elif view.failing:
        banner = BANNER_FAILING
    return MailCard(**{**view.__dict__, "banner": banner})
