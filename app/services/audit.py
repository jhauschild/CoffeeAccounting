"""Append-only audit log (PROMPT §7). There is deliberately no update/delete path."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from app.models import ACTOR_TYPES, AuditLog
from app.timeutil import utcnow

# Metadata keys that suggest a secret is being logged. Logging them is a programming error.
_FORBIDDEN_KEY_PARTS = ("password", "secret", "token", "cookie", "totp_code", "otp_code")


def _check_metadata(metadata: dict) -> None:
    for key, value in metadata.items():
        k = str(key).lower()
        if any(part in k for part in _FORBIDDEN_KEY_PARTS):
            raise ValueError(f"audit metadata key {key!r} looks like a secret; never log secrets")
        if isinstance(value, dict):
            _check_metadata(value)


def log(
    db: Session,
    *,
    actor_type: str,
    actor_id=None,
    action: str,
    target_type: str | None = None,
    target_id=None,
    metadata: dict | None = None,
    ip: str | None = None,
    now: datetime | None = None,
) -> AuditLog:
    """Add an audit entry to the caller's transaction (never commits).

    `actor_id`/`target_id` may be UUIDs or strings. `metadata` must be JSON-serialisable
    and must not contain secrets (passwords, TOTP secrets/codes, tokens, the access code,
    cookies); keys that look like secrets raise `ValueError`.
    """
    if actor_type not in ACTOR_TYPES:
        raise ValueError(f"invalid actor_type {actor_type!r}")
    if metadata:
        _check_metadata(metadata)
    entry = AuditLog(
        actor_type=actor_type,
        actor_id=str(actor_id) if actor_id is not None else None,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        meta=metadata or None,
        source_ip=ip[:64] if ip else None,
        created_at=now or utcnow(),
    )
    db.add(entry)
    db.flush()
    return entry


def admin_actor(admin) -> tuple[str, str | None]:
    """(actor_type, actor_id) for an admin object, or the system actor when `admin` is None (CLI)."""
    if admin is None:
        return "system", None
    return "admin", str(admin.id)
