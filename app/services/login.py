"""Username and password sign-in (PLAN-v2 section 1, "Sign-in and recovery"; task 2.5).

    # POST /login  (write_session; catch InvalidCredentials INSIDE the block so the failure is committed)
    with write_session() as db:
        try:
            result = login.sign_in(db, username=..., password=..., ip=ip, pending_id=..., old_session_id=...)
        except InvalidCredentials:
            ...   # one generic page

Rules
-----
* One generic failure, `InvalidCredentials`, for an unknown username, a wrong password and an account that
  cannot sign in (inactive, merged, unverified, no password hash, a legacy v1 profile). No state difference is
  visible to the caller. Unknown and unusable accounts burn a dummy Argon2 check, so the timing does not tell.
* Limits (database-backed, `ratelimit`): 5 FAILURES per 15 minutes per username+IP and 20 per IP across
  usernames (IPv6 by /64). A limited attempt raises `RateLimited` before any password check, whether or not the
  password would have been right, and records nothing. A success records nothing.
  Failures are recorded in the caller's transaction: a raised error rolls it back, so the route catches
  `InvalidCredentials` inside its `write_session()` block and commits the recorded failure (see the sketch above).
* Success: `sign_in` issues a fresh session (the browser's old session is revoked), consumes the browser's pending
  action once (`onboarding.start_session_and_record`: a coffee is recorded exactly once, `view_site` is reported)
  and audits `user.login` (no password, no token). An outdated Argon2 hash is upgraded on success.
* Argon2 runs inside the caller's write transaction (tens of milliseconds in production), like registration.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import User
from app.services import audit, passwords, ratelimit, registration
from app.services.errors import InvalidCredentials, RateLimited
from app.services.onboarding import OnboardResult, start_session_and_record
from app.timeutil import ensure_utc, utcnow

MAX_USERNAME_LENGTH = 64  # longer input cannot be a username; it is cut before it becomes a rate-limit key


def normalize_username(username: str) -> str:
    return registration.normalize_username(username)[:MAX_USERNAME_LENGTH]


def _limit_checks(normalized: str, ip: str) -> tuple[tuple[str, str, int, int], ...]:
    """(bucket, key, limit, window seconds) for every cap a sign-in failure counts against."""
    ip_key = ratelimit.ip_key(ip)
    user_bucket, user_limit, window = ratelimit.LOGIN_FAILURES
    ip_bucket, ip_limit, ip_window = ratelimit.LOGIN_FAILURES_IP
    return ((user_bucket, f"{normalized}|{ip_key}", user_limit, window), (ip_bucket, ip_key, ip_limit, ip_window))


def can_sign_in(user: User | None) -> bool:
    """A verified, active account with a password (member or guest). Merged and inactive profiles, unverified
    accounts and legacy v1 profiles (no `account_kind`, no password) cannot."""
    return (user is not None and user.status == "active" and user.account_kind in ("member", "guest")
            and user.verified_at is not None and bool(user.password_hash))


def authenticate(db: Session, username: str, password: str, ip: str, *, now: datetime | None = None) -> User:
    """Check the credentials and return the user, or raise `InvalidCredentials` (failure recorded) or
    `RateLimited` (nothing recorded). Does not start a session."""
    now = ensure_utc(now) if now is not None else utcnow()
    normalized = normalize_username(username)
    checks = _limit_checks(normalized, ip)
    for bucket, key, limit, window in checks:
        if ratelimit.is_limited(db, bucket, key, limit, window, now):
            raise RateLimited("too many sign-in attempts", bucket=bucket)
    user = db.scalar(select(User).where(User.username_normalized == normalized)) if normalized else None
    ok = False
    if can_sign_in(user):
        ok, new_hash = passwords.verify_and_rehash(user.password_hash, password)
        if ok and new_hash is not None:
            user.password_hash = new_hash
    else:
        passwords.verify_dummy(password)
    if not ok:
        for bucket, key, _limit, _window in checks:
            ratelimit.record_hit(db, bucket, key, now)
        raise InvalidCredentials("invalid username or password")
    return user


def sign_in(db: Session, *, username: str, password: str, ip: str, pending_id: str | None = None,
            old_session_id: uuid.UUID | None = None, now: datetime | None = None) -> OnboardResult:
    """`authenticate`, then a fresh session and the browser's pending action (see the module docstring)."""
    now = ensure_utc(now) if now is not None else utcnow()
    user = authenticate(db, username, password, ip, now=now)
    result = start_session_and_record(db, user, pending_id=pending_id, old_session_id=old_session_id, now=now)
    audit.log(db, actor_type="user", actor_id=user.id, action="user.login", target_type="user", target_id=user.id,
              metadata={"coffee_status": result.coffee_status}, ip=ip, now=now)
    return result
