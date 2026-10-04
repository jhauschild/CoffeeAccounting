"""Database-backed sliding-window rate limiter (survives restarts).

Rows live in `rate_limit_events` (bucket, key, created_at) and are purged by
`python -m app.cli purge-expired`. Run these inside `write_session()` so the count and the
insert are atomic (`BEGIN IMMEDIATE` serializes writers).

* `check_rate(db, bucket, key, limit, window_seconds)` — count this attempt; raise
  `RateLimited` if `limit` attempts already happened in the window (the rejected attempt
  is not recorded). Use for "N requests per window" (registration, password reset requests).
* `is_limited(...)` + `record_hit(...)` — for "N *failures* per window" (admin
  login): check before verifying, record only failures.
"""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.models import RateLimitEvent
from app.services.errors import RateLimited
from app.timeutil import ensure_utc, utcnow

MAX_BUCKET_LENGTH = 32
MAX_KEY_LENGTH = 200

# Limits used by the web layer (PROMPT §5, §6).
REGISTRATION = ("register", 10, 60 * 60)               # per IP
LOGIN_FAILURES = ("login", 5, 15 * 60)                 # per username+IP
LOGIN_FAILURES_IP = ("login_ip", 20, 15 * 60)          # per IP, across usernames
USERNAME_PROBE = ("username_probe", 10, 15 * 60)       # "username taken" answers per IP (registration forms)
RESET_USER = ("reset_user", 3, 60 * 60)                # reset requests per username
RESET_IP = ("reset_ip", 10, 60 * 60)                   # reset requests per IP
RESET_RECIPIENT = ("reset_rcpt", 6, 60 * 60)           # reset mails per recipient address (hashed)
OVERVIEW_ANON = ("overview_anon", 30, 10 * 60)         # pending rows created by cookie-less /overview* visits, per IP
ADMIN_LOGIN_FAILURES = ("admin_login", 5, 15 * 60)     # per username+IP
ADMIN_LOGIN_FAILURES_IP = ("admin_login_ip", 15, 15 * 60)  # per IP, across usernames


def _now(now: datetime | None) -> datetime:
    return ensure_utc(now) if now is not None else utcnow()


def _key(key: str) -> str:
    key = key or "-"
    if len(key) > MAX_KEY_LENGTH:
        return "sha256:" + hashlib.sha256(key.encode("utf-8")).hexdigest()
    return key


def ip_key(ip: str) -> str:
    """Rate-limit key for a client address: an IPv6 client is keyed by its /64 (one subscriber
    typically holds a whole /64, so per-address keys would make every limit trivially bypassable);
    IPv4 and anything unparsable are returned unchanged."""
    try:
        addr = ipaddress.ip_address((ip or "").split("%", 1)[0])
    except ValueError:
        return ip
    if addr.version == 6:
        if addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
        return str(ipaddress.ip_network((addr, 64), strict=False))
    return ip


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


def release_hits(db: Session, ids: list[int]) -> None:
    """Remove hits recorded earlier (an attempt that counted up front turned out to be a success)."""
    if ids:
        db.execute(delete(RateLimitEvent).where(RateLimitEvent.id.in_(ids)))


def check_rate(db: Session, bucket: str, key: str, limit: int, window_seconds: int,
               now: datetime | None = None) -> None:
    if is_limited(db, bucket, key, limit, window_seconds, now):
        raise RateLimited("too many requests", bucket=bucket)
    record_hit(db, bucket, key, now)
