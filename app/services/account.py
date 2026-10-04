"""Self-service account changes of a signed-in user (task 3.2): change password.

    # POST /account/password (write_session; catch InvalidCredentials INSIDE the block so the recorded failure commits)
    with write_session() as db:
        try:
            account.change_password(db, user_id=..., session_id=..., current_password=..., new_password=..., ip=ip)
        except InvalidCredentials:
            ...

Rules
-----
* The current password is required. A wrong one raises `InvalidCredentials` and records a hit; after
  `PASSWORD_FAILURES` hits in the window every attempt raises `RateLimited` before any password check (a stolen
  session cannot be used to guess the password).
* The new password follows `passwords.validate_policy` (`InvalidPassword`; nothing is recorded or changed).
* Success revokes every OTHER session of the user and ALL sessions of an admin account linked to the user
  (`admin_users.user_id`), because both authenticate with this password. The session that made the change stays.
* Audited as `password.changed` (counts only, never a password or token).
* The web route calls `start_change_password`, which keeps Argon2 OUT of the SQLite write lock (final audit M1):
  a short write transaction (checks, up-front count of the attempt as a wrong guess, read the stored hash),
  the verify of the current password and the hash of the new one with no lock held, a short write transaction
  that re-checks the account and that its hash is unchanged and then records the result (fails safely like a
  wrong current password otherwise). `change_password` is the single-transaction form for tests and scripts.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.db import write_session
from app.models import AdminUser, User, UserSession
from app.services import admin_auth, audit, passwords, ratelimit
from app.services.errors import InvalidCredentials, InvalidPassword, RateLimited, UserInactive
from app.services.users import get_user
from app.timeutil import ensure_utc, utcnow

PASSWORD_FAILURES = ("pw_change", 5, 15 * 60)  # wrong "current password" answers per user


def change_password(db: Session, *, user_id: uuid.UUID, session_id: uuid.UUID, current_password: str,
                    new_password: str, ip: str | None = None, now: datetime | None = None) -> User:
    now = ensure_utc(now) if now is not None else utcnow()
    user = get_user(db, user_id)
    if user.status != "active":
        raise UserInactive("profile is not active")
    bucket, limit, window = PASSWORD_FAILURES
    if ratelimit.is_limited(db, bucket, str(user.id), limit, window, now):
        raise RateLimited("too many password attempts", bucket=bucket)
    if not user.password_hash or not passwords.verify_password(user.password_hash, current_password):
        ratelimit.record_hit(db, bucket, str(user.id), now)
        raise InvalidCredentials("current password is not correct")
    passwords.validate_policy(new_password, user.username or "", user.email)
    return _apply_new_password(db, user, passwords.hash_password(new_password), session_id=session_id, ip=ip, now=now)


def _apply_new_password(db: Session, user: User, new_hash: str, *, session_id: uuid.UUID, ip: str | None,
                        now: datetime) -> User:
    """Store the new hash, revoke every other session (and all sessions of a linked admin row), audit."""
    user.password_hash = new_hash
    revoked = db.execute(
        update(UserSession)
        .where(UserSession.user_id == user.id, UserSession.id != session_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=now).execution_options(synchronize_session=False)).rowcount
    admin_revoked = 0
    for admin_id in db.scalars(select(AdminUser.id).where(AdminUser.user_id == user.id)).all():
        admin_revoked += admin_auth.revoke_admin_sessions(db, admin_id, now=now)
    db.flush()
    audit.log(db, actor_type="user", actor_id=user.id, action="password.changed", target_type="user",
              target_id=user.id, metadata={"sessions_revoked": revoked, "admin_sessions_revoked": admin_revoked},
              ip=ip, now=now)
    return user


def start_change_password(*, user_id: uuid.UUID, session_id: uuid.UUID, current_password: str, new_password: str,
                          ip: str | None = None, now: datetime | None = None) -> User:
    """Same outcome as `change_password`, but Argon2 never runs while the SQLite write lock is held. Opens and
    commits its own short transactions (callers do not wrap it). Raises `UserInactive`, `RateLimited`,
    `InvalidCredentials` (wrong current password, or the account's password changed while we were hashing: the
    counted wrong guess stays) or `InvalidPassword` (policy; a correct current password is not a wrong guess)."""
    now = ensure_utc(now) if now is not None else utcnow()
    bucket, limit, window = PASSWORD_FAILURES
    with write_session() as db:
        user = get_user(db, user_id)
        if user.status != "active":
            raise UserInactive("profile is not active")
        if ratelimit.is_limited(db, bucket, str(user.id), limit, window, now):
            raise RateLimited("too many password attempts", bucket=bucket)
        current_hash, username, email = user.password_hash, user.username or "", user.email
        hit_id = ratelimit.record_hit(db, bucket, str(user.id), now)  # up front: strict budget for parallel guesses
    ok = bool(current_hash) and passwords.verify_password(current_hash, current_password)  # no lock held
    policy_error: InvalidPassword | None = None
    new_hash = None
    if ok:
        try:
            passwords.validate_policy(new_password, username, email)
            new_hash = passwords.hash_password(new_password)
        except InvalidPassword as exc:
            policy_error = exc
    if not ok:  # the wrong guess is already counted; nothing more to write
        raise InvalidCredentials("current password is not correct")
    with write_session() as db:
        user = get_user(db, user_id)
        if user.status != "active":
            raise UserInactive("profile is not active")
        if user.password_hash != current_hash:  # changed while we were hashing: fail safe, keep the counted hit
            raise InvalidCredentials("current password is not correct")
        ratelimit.release_hits(db, [hit_id])
        if policy_error is None:
            _apply_new_password(db, user, new_hash, session_id=session_id, ip=ip, now=now)
    if policy_error is not None:
        raise policy_error
    return user
