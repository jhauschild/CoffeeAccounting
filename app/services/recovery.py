"""Password recovery by mail (PLAN-v2 section 1, "Sign-in and recovery"; task 2.5).

    # POST /forgot  (write_session)
    outcome = recovery.request_reset(db, username, ip)
    # ... commit, then (message is None when there is nothing to send):
    if outcome.message is not None:
        background_tasks.add_task(send_in_background, outcome.message, outcome.recipient)
    # -> render the SAME neutral page whatever happened.

    # GET /reset/{token}   (read_session):  recovery.peek_reset(db, token) -> ResetView | None
    # POST /reset/{token}  (write_session): recovery.reset_password(db, token, new_password, ip=ip)

Rules
-----
* `request_reset` gives the same caller-visible outcome for an existing and an unknown account, and for every
  limit that applies to existing accounts only (the per-recipient cap): no error, no token, no mail. Only the
  username and IP caps raise `RateLimited`, and both are counted for unknown usernames too, so they say
  nothing about the account.
* The mail goes to the recovery address: a member's own e-mail, a guest's SPONSOR's e-mail. The mail names the
  account (`mail_templates.password_reset`, `for_guest` for the sponsor). Only a SHA-256 of the 256-bit random
  token is stored; the raw token is in the returned message only.
* Limits (per hour): 3 requests per username, 10 per IP (IPv6 by /64), 6 mails per recipient address
  (HMAC of the address, never stored). They are counted in the caller's transaction, so a request refused by
  an exception does not consume the others.
* A token is valid for `RESET_TTL_MINUTES` (1 hour), single use. Unknown, expired, used and "account can no
  longer sign in" are one error, `InvalidToken`.
* `reset_password` validates the password policy BEFORE it consumes the token (a weak password never burns the
  link), consumes it with one atomic `UPDATE ... WHERE consumed_at IS NULL AND expires_at > now`, sets the
  hash, consumes the account's other outstanding tokens, revokes ALL sessions of the account (and of the admin
  row linked to it) and audits. It does not sign anybody in.
* Services never commit and never send mail.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import AdminUser, PasswordResetToken, User
from app.services import admin_auth, audit, login, passwords, ratelimit, sessions
from app.services.errors import InvalidToken
from app.services.mail import MailMessage, build_message, recipient_bucket_key
from app.services.mail_templates import password_reset
from app.timeutil import ensure_utc, utcnow

TOKEN_BYTES = 32  # 256 bit
MAX_RAW_TOKEN_LENGTH = 100


@dataclass(frozen=True)
class ResetOutcome:
    """What `request_reset` hands to the route. `message` and `recipient` are None when nothing is to be sent
    (unknown or unusable account, no recovery address, recipient cap). The route must not let the page differ."""

    message: MailMessage | None = field(default=None, repr=False)
    recipient: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class ResetView:
    """What the reset page may show for a valid token: the account it is for."""

    username: str
    display_name: str
    for_guest: bool
    expires_at: datetime


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _recovery_address(db: Session, user: User) -> str | None:
    """Where a reset mail for `user` goes: a member's own address, a guest's sponsor's address (the sponsor must
    be an active member). TODO: swap for `registration.recovery_address` once the guest task provides it."""
    if user.account_kind == "member":
        return user.email
    if user.account_kind == "guest" and user.sponsor_id is not None:
        sponsor = db.get(User, user.sponsor_id)
        if sponsor is not None and sponsor.status == "active" and sponsor.account_kind == "member":
            return sponsor.email
    return None


# ----- request ---------------------------------------------------------------------------------
def request_reset(db: Session, username: str, ip: str, *, now: datetime | None = None) -> ResetOutcome:
    """Count the request, and, for an account that can sign in and has a recovery address, store a reset token and
    return the mail to send after the commit. Raises `RateLimited` only for the username and IP caps."""
    now = ensure_utc(now) if now is not None else utcnow()
    normalized = login.normalize_username(username)
    user_bucket, user_limit, user_window = ratelimit.RESET_USER
    ip_bucket, ip_limit, ip_window = ratelimit.RESET_IP
    ratelimit.check_rate(db, user_bucket, normalized or "-", user_limit, user_window, now=now)
    ratelimit.check_rate(db, ip_bucket, ratelimit.ip_key(ip), ip_limit, ip_window, now=now)

    user = db.scalar(select(User).where(User.username_normalized == normalized)) if normalized else None
    if not login.can_sign_in(user):
        return ResetOutcome()
    address = _recovery_address(db, user)
    if not address:
        return ResetOutcome()
    rcpt_bucket, rcpt_limit, rcpt_window = ratelimit.RESET_RECIPIENT
    rcpt_key = recipient_bucket_key(address)
    if ratelimit.is_limited(db, rcpt_bucket, rcpt_key, rcpt_limit, rcpt_window, now):
        return ResetOutcome()
    ratelimit.record_hit(db, rcpt_bucket, rcpt_key, now)

    raw_token = secrets.token_urlsafe(TOKEN_BYTES)
    row = PasswordResetToken(user_id=user.id, token_hash=hash_token(raw_token), created_at=now,
                             expires_at=now + timedelta(minutes=get_settings().reset_ttl_minutes))
    db.add(row)
    db.flush()
    audit.log(db, actor_type="system", action="password.reset_requested", target_type="user", target_id=user.id,
              metadata={"for_guest": user.account_kind == "guest"}, ip=ip, now=now)
    subject, body = password_reset(username=user.username, token=raw_token, for_guest=user.account_kind == "guest")
    return ResetOutcome(build_message(to=address, subject=subject, body=body), address)


# ----- peek and reset --------------------------------------------------------------------------
def _find(db: Session, raw_token: str | None, now: datetime) -> tuple[PasswordResetToken, User] | None:
    """The usable (unconsumed, unexpired) token and the account it is for, if that account can still sign in."""
    if not isinstance(raw_token, str) or not raw_token or len(raw_token) > MAX_RAW_TOKEN_LENGTH:
        return None
    row = db.scalar(select(PasswordResetToken).where(PasswordResetToken.token_hash == hash_token(raw_token)))
    if row is None or row.consumed_at is not None or ensure_utc(row.expires_at) <= now:
        return None
    user = db.get(User, row.user_id)
    if not login.can_sign_in(user):
        return None
    return row, user


def peek_reset(db: Session, raw_token: str | None, now: datetime | None = None) -> ResetView | None:
    """Read-only (GET /reset): the account a valid token is for, else None. Unknown, expired and used tokens are
    indistinguishable. Writes nothing."""
    now = ensure_utc(now) if now is not None else utcnow()
    found = _find(db, raw_token, now)
    if found is None:
        return None
    row, user = found
    return ResetView(user.username or "", user.display_name, user.account_kind == "guest", ensure_utc(row.expires_at))


def reset_password(db: Session, raw_token: str | None, new_password: str, *, ip: str | None = None,
                   now: datetime | None = None) -> User:
    """Set the new password, consume the token and revoke every session of the account, in ONE transaction.

    Raises `InvalidToken` (unknown, expired, used, or the account can no longer sign in) or `InvalidPassword`
    (policy; the token is then NOT consumed because the caller's transaction is rolled back).
    """
    now = ensure_utc(now) if now is not None else utcnow()
    found = _find(db, raw_token, now)
    if found is None:
        raise InvalidToken("reset link is invalid or expired")
    row, user = found
    passwords.validate_policy(new_password, user.username or "", user.email)
    new_hash = passwords.hash_password(new_password)
    consumed = db.execute(
        update(PasswordResetToken)
        .where(PasswordResetToken.id == row.id, PasswordResetToken.consumed_at.is_(None),
               PasswordResetToken.expires_at > now)
        .values(consumed_at=now).execution_options(synchronize_session=False))
    if consumed.rowcount != 1:
        raise InvalidToken("reset link is invalid or expired")
    db.execute(update(PasswordResetToken)
               .where(PasswordResetToken.user_id == user.id, PasswordResetToken.consumed_at.is_(None))
               .values(consumed_at=now).execution_options(synchronize_session=False))
    user.password_hash = new_hash
    revoked = sessions.revoke_user_sessions(db, user.id, now)
    admin_revoked = 0
    for admin_id in db.scalars(select(AdminUser.id).where(AdminUser.user_id == user.id)):
        admin_revoked += admin_auth.revoke_admin_sessions(db, admin_id, now=now)
    db.flush()
    audit.log(db, actor_type="user", actor_id=user.id, action="password.reset", target_type="user",
              target_id=user.id, metadata={"sessions_revoked": revoked, "admin_sessions_revoked": admin_revoked},
              ip=ip, now=now)
    return user
