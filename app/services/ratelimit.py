"""Database-backed sliding-window rate limiter (survives restarts).

Rows live in `rate_limit_events` (bucket, key, created_at) and are purged by
`python -m app.cli purge-expired`. Run these inside `write_session()` so the count and the
insert are atomic (`BEGIN IMMEDIATE` serializes writers).

* `check_rate(db, bucket, key, limit, window_seconds)` — count this attempt; raise
  `RateLimited` if `limit` attempts already happened in the window (the rejected attempt
  is not recorded). Use for "N requests per window" (registration, profile search).
* `is_limited(...)` + `record_hit(...)` — for "N *failures* per window" (access code,
  admin login): check before verifying, record only failures.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import RateLimitEvent
from app.services.errors import RateLimited
from app.timeutil import ensure_utc, utcnow

MAX_BUCKET_LENGTH = 32
MAX_KEY_LENGTH = 200

# Limits used by the web layer (PROMPT §5, §6).
ACCESS_CODE_FAILURES = ("access_code", 10, 15 * 60)   # per IP
REGISTRATION = ("register", 10, 60 * 60)               # per IP
PROFILE_SEARCH = ("profile_search", 60, 5 * 60)        # per IP
ADMIN_LOGIN_FAILURES = ("admin_login", 5, 15 * 60)     # per username+IP
ADMIN_LOGIN_FAILURES_IP = ("admin_login_ip", 15, 15 * 60)  # per IP, across usernames


def _now(now: datetime | None) -> datetime:
    return ensure_utc(now) if now is not None else utcnow()


def _key(key: str) -> str:
    key = key or "-"
    if len(key) > MAX_KEY_LENGTH:
        return "sha256:" + hashlib.sha256(key.encode("utf-8")).hexdigest()
    return key


def _bucket(bucket: str) -> str:
    if not bucket or len(bucket) > MAX_BUCKET_LENGTH:
        raise ValueError("invalid rate-limit bucket")
    return bucket


def count_hits(db: Session, bucket: str, key: str, window_seconds: int, now: datetime | None = None) -> int:
    since = _now(now) - timedelta(seconds=window_seconds)
    return db.scalar(
        select(func.count()).select_from(RateLimitEvent).where(
            RateLimitEvent.bucket == _bucket(bucket), RateLimitEvent.key == _key(key),
            RateLimitEvent.created_at > since,
        )
    )


def is_limited(db: Session, bucket: str, key: str, limit: int, window_seconds: int,
               now: datetime | None = None) -> bool:
    return count_hits(db, bucket, key, window_seconds, now) >= limit


def record_hit(db: Session, bucket: str, key: str, now: datetime | None = None) -> int:
    """Record one event; returns its id (so a caller can release it again)."""
    event = RateLimitEvent(bucket=_bucket(bucket), key=_key(key), created_at=_now(now))
    db.add(event)
    db.flush()
    return event.id


def check_rate(db: Session, bucket: str, key: str, limit: int, window_seconds: int,
               now: datetime | None = None) -> None:
    if is_limited(db, bucket, key, limit, window_seconds, now):
        raise RateLimited("too many requests", bucket=bucket)
    record_hit(db, bucket, key, now)
