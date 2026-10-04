"""Member registration and e-mail verification (PLAN-v2 section 1, A1/A2/A12; task 2.3).

Flow (routes are task 3.1; this module is the service layer they call)::

    # POST /register  (write_session)
    result = registration.begin_member(db, username=..., display_name=..., chair_id=..., email=...,
                                       password=..., privacy_ack=..., ip=ip)
    message = registration.mail_for_registration(result)     # build before the commit, send after
    # ... commit, then:
    background_tasks.add_task(send_in_background, message, result.email)
    # -> render the SAME page whatever `result.already_registered` says.

    # GET /verify/{token}   (read_session): registration.peek_pending(db, token) -> PendingView | None
    # POST /verify/{token}  (write_session): registration.confirm_member(db, token, pending_id=..., ...)

Rules
-----
* Services never commit and never send mail. A raised error rolls the caller's transaction back, including
  the rate-limit hits recorded in it; so only attempts that got through validation count towards the limits.
* Nothing but a SHA-256 of the token and an Argon2id hash of the password is stored; the raw token is
  returned once (to be mailed) and never logged or audited.
* Usernames: stored lower-case (strip + casefold), 3 to 32 characters of ``a-z 0-9 . _ -``. Display names carry
  capitalisation and spelling. A username is refused when a user holds it or a CLI admin (an admin row that is
  not linked to a user) does. Pending rows never reserve a name: whoever CONFIRMS first gets it.
* Rate limits (per hour): 10 registrations per client address (`ratelimit.REGISTRATION`, IPv6 by /64) and
  5 per e-mail address (HMAC of the lower-cased address, so no address is stored in `rate_limit_events`).
  Mails are additionally bounded by the mail caps (`mail.reserve_send`), which also cover the
  already-registered notices.
* Known and unknown e-mail addresses give the same caller-visible outcome (same result shape, same errors);
  only the internal ``already_registered`` flag and ``token`` differ. The password is hashed in both cases to
  keep the timing close.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import unicodedata
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import EMAIL_MAX, USERNAME_MAX, AdminUser, Chair, PendingRegistration, User
from app.services import audit, passwords, ratelimit, signing, users
from app.services.errors import Conflict, InvalidInput, InvalidToken
from app.services.mail import MailMessage, build_message, normalize_address
from app.services.mail_templates import already_registered, member_verification
from app.services.onboarding import OnboardResult, start_session_and_record
from app.timeutil import ensure_utc, utcnow

USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 32
assert USERNAME_MAX_LENGTH <= USERNAME_MAX
_USERNAME_RE = re.compile(r"^[a-z0-9._-]+$")

# Per e-mail address: 5 registration requests per hour (bucket, limit, window seconds).
REGISTRATION_EMAIL = ("register_email", 5, 60 * 60)
MAX_RAW_TOKEN_LENGTH = 100
TOKEN_BYTES = 32  # 256 bit

# `InvalidInput.context["field"]` / `Conflict.context["reason"]` values the routes map to strings.
REASON_USERNAME_TAKEN = "username_taken"
REASON_EMAIL_TAKEN = "email_taken"


@dataclass(frozen=True)
class RegistrationResult:
    """Outcome of `begin_member`. `token` (the raw verification token, only ever mailed) is None exactly when
    `already_registered` is True. `repr` hides the token."""

    email: str
    already_registered: bool
    token: str | None = field(default=None, repr=False)
    pending_id: uuid.UUID | None = None


@dataclass(frozen=True)
class PendingView:
    """What the confirm page may show for a valid, unconsumed token (no e-mail, no hashes)."""

    kind: str
    username: str
    display_name: str
    chair_id: uuid.UUID
    chair_short_name: str
    chair_full_name: str
    expires_at: datetime


# ----- validation -----------------------------------------------------------------------------
def normalize_username(raw: str) -> str:
    return (raw or "").strip().casefold() if isinstance(raw, str) else ""


def username_taken(db: Session, normalized: str) -> bool:
    """True when a user, or a CLI admin (admin row without a user link), holds the normalised username."""
    if db.scalar(select(User.id).where(User.username_normalized == normalized)) is not None:
        return True
    return db.scalar(select(AdminUser.id).where(AdminUser.username_normalized == normalized,
                                                AdminUser.user_id.is_(None))) is not None


def validate_username(raw: str, db: Session | None = None) -> str:
    """Return the normalised username (strip + casefold). Raises `InvalidInput` (``field="username"``,
    reason ``length`` or ``chars``) for a bad format and, when `db` is given, `Conflict`
    (reason ``username_taken``) if a user or a CLI admin holds it."""
    normalized = normalize_username(raw)
    if not USERNAME_MIN_LENGTH <= len(normalized) <= USERNAME_MAX_LENGTH:
        raise InvalidInput("username must have 3 to 32 characters", field="username", reason="length")
    if not _USERNAME_RE.match(normalized):
        raise InvalidInput("username may only contain a-z, 0-9, dot, underscore and hyphen", field="username",
                           reason="chars")
    if db is not None and username_taken(db, normalized):
        raise Conflict("username is taken", field="username", reason=REASON_USERNAME_TAKEN)
    return normalized


def clean_display_name(raw: str) -> str:
    """Strip control, format, private-use and surrogate characters (whitespace controls become spaces),
    collapse whitespace, then apply the profile rules (non-empty, at most 60 characters)."""
    text = unicodedata.normalize("NFC", raw if isinstance(raw, str) else "")
    text = "".join(" " if c in "\t\n\r\x0b\x0c\x85  " else c for c in text)
    text = "".join(c for c in text if unicodedata.category(c) not in ("Cc", "Cf", "Co", "Cs"))
    try:
        return users.clean_display_name(text)
    except InvalidInput as exc:
        raise InvalidInput(str(exc), field="display_name") from exc


def domain_allowed(domain: str, patterns: list[str] | None = None) -> bool:
    """`tum.de` matches exactly; `*.tum.de` matches subdomains only (at least one extra label). Case-insensitive.
    Lookalikes such as `tum.de.evil.com` or `evil-tum.de` never match."""
    domain = (domain or "").strip().lower()
    for pattern in (patterns if patterns is not None else get_settings().allowed_email_domain_list):
        if pattern.startswith("*."):
            suffix = pattern[1:]  # ".tum.de"
            if domain.endswith(suffix) and len(domain) > len(suffix) and not domain.startswith("."):
                return True
        elif domain == pattern:
            return True
    return False


def validate_email(raw: str) -> str:
    """Lower-cased plain address from an allowed domain, or `InvalidInput` (``field="email"``, reason
    ``format`` or ``domain``)."""
    text = (raw or "").strip() if isinstance(raw, str) else ""
    if len(text) > EMAIL_MAX:
        raise InvalidInput("invalid e-mail address", field="email", reason="format")
    try:
        address = normalize_address(text)
    except InvalidInput as exc:
        raise InvalidInput("invalid e-mail address", field="email", reason="format") from exc
    if not domain_allowed(address.rsplit("@", 1)[1]):
        raise InvalidInput("e-mail domain is not allowed", field="email", reason="domain")
    return address


def _active_chair(db: Session, chair_id) -> Chair:
    chair = db.get(Chair, chair_id) if isinstance(chair_id, uuid.UUID) else None
    if chair is None or not chair.active:
        raise InvalidInput("unknown or inactive chair", field="chair")
    return chair


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _email_key(email: str) -> str:
    return signing.mac("register-email", email)


# ----- begin ----------------------------------------------------------------------------------
def begin_member(db: Session, *, username: str, display_name: str, chair_id: uuid.UUID, email: str, password: str,
                 privacy_ack: bool, ip: str, now: datetime | None = None) -> RegistrationResult:
    """Validate a member registration and store a `pending_registrations` row (kind member).

    Raises `RateLimited`, `InvalidInput` (``context["field"]``: username, display_name, chair, email, password,
    privacy), `InvalidPassword` or `Conflict` (username taken). If the e-mail already belongs to a member
    nothing is stored and the result has ``already_registered=True`` (and no token); otherwise the result
    carries the raw token once. The caller mails `mail_for_registration(result)` after its commit.
    """
    now = ensure_utc(now) if now is not None else utcnow()
    ip_bucket, ip_limit, ip_window = ratelimit.REGISTRATION
    ratelimit.check_rate(db, ip_bucket, ratelimit.ip_key(ip), ip_limit, ip_window, now=now)
    normalized = validate_username(username, db)
    name = clean_display_name(display_name)
    _active_chair(db, chair_id)
    address = validate_email(email)
    passwords.validate_policy(password, normalized, address)
    if privacy_ack is not True:
        raise InvalidInput("the privacy notice must be acknowledged", field="privacy")
    bucket, limit, window = REGISTRATION_EMAIL
    ratelimit.check_rate(db, bucket, _email_key(address), limit, window, now=now)

    password_hash = passwords.hash_password(password)  # also on the known-email path (timing)
    holder = db.scalar(select(User.id).where(User.email == address))
    if holder is not None:
        audit.log(db, actor_type="system", action="registration.duplicate_email", target_type="user",
                  metadata={"kind": "member", "username": normalized}, ip=ip, now=now)
        return RegistrationResult(email=address, already_registered=True)

    raw_token = secrets.token_urlsafe(TOKEN_BYTES)
    pending = PendingRegistration(
        kind="member", username=normalized, username_normalized=normalized, display_name=name, chair_id=chair_id,
        email=address, password_hash=password_hash, token_hash=hash_token(raw_token), created_at=now,
        expires_at=now + timedelta(hours=get_settings().verification_ttl_hours))
    db.add(pending)
    db.flush()
    audit.log(db, actor_type="system", action="registration.requested", target_type="pending_registration",
              target_id=pending.id,
              metadata={"kind": "member", "username": normalized, "chair_id": str(chair_id),
                        "email_domain": address.rsplit("@", 1)[1]}, ip=ip, now=now)
    return RegistrationResult(email=address, already_registered=False, token=raw_token, pending_id=pending.id)


def mail_for_registration(result: RegistrationResult) -> MailMessage:
    """The mail to send after the commit: the verification link, or (known address) the notice without a link.

        message = mail_for_registration(result)
        background_tasks.add_task(send_in_background, message, result.email)
    """
    if result.already_registered or result.token is None:
        subject, body = already_registered()
    else:
        subject, body = member_verification(result.token)
    return build_message(to=result.email, subject=subject, body=body)


# ----- peek and confirm -----------------------------------------------------------------------
def _find_pending(db: Session, raw_token: str | None, kind: str = "member") -> PendingRegistration | None:
    if not isinstance(raw_token, str) or not raw_token or len(raw_token) > MAX_RAW_TOKEN_LENGTH:
        return None
    return db.scalar(select(PendingRegistration).where(PendingRegistration.token_hash == hash_token(raw_token),
                                                       PendingRegistration.kind == kind))


def _usable(row: PendingRegistration | None, now: datetime) -> bool:
    return row is not None and row.consumed_at is None and ensure_utc(row.expires_at) > now


def peek_pending(db: Session, raw_token: str | None, now: datetime | None = None) -> PendingView | None:
    """Read-only (GET /verify): display data for a valid member token, else None. Writes nothing, not even
    for expired or consumed tokens; the three failures are indistinguishable."""
    now = ensure_utc(now) if now is not None else utcnow()
    row = _find_pending(db, raw_token)
    if not _usable(row, now):
        return None
    chair = db.get(Chair, row.chair_id)
    return PendingView(row.kind, row.username, row.display_name, row.chair_id,
                       chair.short_name if chair else "", chair.full_name if chair else "", ensure_utc(row.expires_at))


def confirm_member(db: Session, raw_token: str | None, *, pending_id: str | None = None,
                   old_session_id: uuid.UUID | None = None, ip: str | None = None,
                   now: datetime | None = None) -> OnboardResult:
    """POST /verify: create the verified member, sign the browser in and record a pending coffee. ONE transaction.

    Raises `InvalidToken` (unknown, expired or already used: one error), `Conflict` (the username was taken
    meanwhile, reason ``username_taken``, or the address got an account meanwhile, reason ``email_taken``) or
    `InvalidInput` (the chair has been deactivated). The pending row is consumed with
    ``UPDATE ... WHERE consumed_at IS NULL`` and the flow continues only if exactly one row changed, so two
    concurrent confirmations create exactly one user. A pending coffee that cannot be recorded does not abort
    the registration (see `OnboardResult.coffee_status`).
    """
    now = ensure_utc(now) if now is not None else utcnow()
    row = _find_pending(db, raw_token)
    if not _usable(row, now):
        raise InvalidToken("verification link is invalid or expired")
    if username_taken(db, row.username_normalized):
        raise Conflict("username is taken", field="username", reason=REASON_USERNAME_TAKEN)
    if db.scalar(select(User.id).where(User.email == row.email)) is not None:
        raise Conflict("e-mail address is already registered", field="email", reason=REASON_EMAIL_TAKEN)
    consumed = db.execute(
        update(PendingRegistration)
        .where(PendingRegistration.id == row.id, PendingRegistration.consumed_at.is_(None),
               PendingRegistration.expires_at > now)
        .values(consumed_at=now).execution_options(synchronize_session=False))
    if consumed.rowcount != 1:
        raise InvalidToken("verification link is invalid or expired")
    try:
        with db.begin_nested():
            user = users.create_account(
                db, kind="member", username=row.username, username_normalized=row.username_normalized,
                display_name=row.display_name, chair_id=row.chair_id, password_hash=row.password_hash,
                email=row.email, verified_at=now, now=now)
    except IntegrityError as exc:  # lost a race on the unique username/e-mail index
        raise Conflict("username or e-mail address is already registered", reason=REASON_USERNAME_TAKEN) from exc
    audit.log(db, actor_type="user", actor_id=user.id, action="user.registered", target_type="user",
              target_id=user.id, metadata={"kind": "member", "username": user.username,
                                           "chair_id": str(user.chair_id), "pending_registration_id": str(row.id)},
              ip=ip, now=now)
    result = start_session_and_record(db, user, pending_id=pending_id, old_session_id=old_session_id, now=now)
    audit.log(db, actor_type="user", actor_id=user.id, action="user.verified", target_type="user",
              target_id=user.id, metadata={"coffee_status": result.coffee_status}, ip=ip, now=now)
    return result
