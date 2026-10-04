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
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models import AdminUser, User, UserSession
from app.services import admin_auth, audit, passwords, ratelimit
from app.services.errors import InvalidCredentials, RateLimited, UserInactive
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
    user.password_hash = passwords.hash_password(new_password)
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
