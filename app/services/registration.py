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
  One exception: a "username taken" answer (`Conflict`, reason `username_taken`) records a hit in the
  `username_probe` bucket (10 per 15 minutes per client address) that the CALLER must commit by catching that
  Conflict inside its `write_session()` block (see `routes_user.register_submit`); other errors leak nothing.
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

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, object_session

from app.config import get_settings
from app.models import EMAIL_MAX, USERNAME_MAX, AdminUser, Chair, PendingRegistration, User
from app.services import audit, passwords, ratelimit, signing, users
from app.services.authz import require_global
from app.services.errors import Conflict, Forbidden, InvalidInput, InvalidToken, RateLimited
from app.services.mail import MailMessage, build_message, normalize_address
from app.services.mail_templates import (already_registered, guest_sponsor_request, member_verification,
                                         neutralise_urls)
from app.services.onboarding import OnboardResult, start_session_and_record
from app.timeutil import ensure_utc, utcnow

USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 32
assert USERNAME_MAX_LENGTH <= USERNAME_MAX
_USERNAME_RE = re.compile(r"^[a-z0-9._-]+$")

# Per e-mail address: 5 registration requests per hour (bucket, limit, window seconds).
REGISTRATION_EMAIL = ("register_email", 5, 60 * 60)
# Guests: 3 requests per hour per client address, at most 5 open requests per sponsor.
GUEST_REQUEST_IP = ("guest_request", 3, 60 * 60)
MAX_OPEN_REQUESTS_PER_SPONSOR = 5
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


def _check_username_probe(db: Session, raw: str, ip: str, now: datetime) -> str:
    """`validate_username` plus a per-IP cap on "taken" answers (`ratelimit.USERNAME_PROBE`).

    Usernames are sign-in identifiers (CLI admin names included) and appear nowhere on the site, so the
    "taken" answer of a registration form must not be an unthrottled oracle. Over the cap raises `RateLimited`;
    a "taken" answer records one hit and re-raises the `Conflict`. The hit only survives if the CALLER
    commits despite the exception (catch the Conflict with reason `REASON_USERNAME_TAKEN` INSIDE the
    `write_session()` block, like the login failure counter); other validation errors record nothing."""
    bucket, limit, window = ratelimit.USERNAME_PROBE
    key = ratelimit.ip_key(ip)
    if ratelimit.is_limited(db, bucket, key, limit, window, now):
        raise RateLimited("too many username checks", bucket=bucket)
    try:
        return validate_username(raw, db)
    except Conflict:
        ratelimit.record_hit(db, bucket, key, now)
        raise


def clean_display_name(raw: str) -> str:
    """Strip control, format, private-use and surrogate characters (whitespace controls become spaces),
    collapse whitespace, then apply the profile rules (non-empty, at most 60 characters)."""
    text = unicodedata.normalize("NFC", raw if isinstance(raw, str) else "")
    text = "".join(" " if c in "\t\n\r\x0b\x0c\x85  " else c for c in text)
    text = "".join(c for c in text if unicodedata.category(c) not in ("Cc", "Cf", "Co", "Cs"))
    text = neutralise_urls(text)  # a display name is shown in mails (guest requests): no links
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
                 privacy_ack: bool, ip: str, now: datetime | None = None,
                 password_hash: str | None = None) -> RegistrationResult:
    """Validate a member registration and store a `pending_registrations` row (kind member).

    Raises `RateLimited`, `InvalidInput` (``context["field"]``: username, display_name, chair, email, password,
    privacy), `InvalidPassword` or `Conflict` (username taken). If the e-mail already belongs to a member
    nothing is stored and the result has ``already_registered=True`` (and no token); otherwise the result
    carries the raw token once. The caller mails `mail_for_registration(result)` after its commit.

    `password_hash`: the web route hashes the password BEFORE it opens the write transaction (final audit M1: no
    Argon2 under the SQLite write lock) and passes the hash of `password` here; without it the hash is computed
    inside the caller's transaction (tests, scripts). The password policy is checked either way.
    """
    now = ensure_utc(now) if now is not None else utcnow()
    ip_bucket, ip_limit, ip_window = ratelimit.REGISTRATION
    if ratelimit.is_limited(db, ip_bucket, ratelimit.ip_key(ip), ip_limit, ip_window, now):
        raise RateLimited("too many requests", bucket=ip_bucket)
    normalized = _check_username_probe(db, username, ip, now)  # a "taken" answer counts as a probe, not as a registration
    ratelimit.record_hit(db, ip_bucket, ratelimit.ip_key(ip), now)
    name = clean_display_name(display_name)
    _active_chair(db, chair_id)
    address = validate_email(email)
    passwords.validate_policy(password, normalized, address)
    if privacy_ack is not True:
        raise InvalidInput("the privacy notice must be acknowledged", field="privacy")
    bucket, limit, window = REGISTRATION_EMAIL
    ratelimit.check_rate(db, bucket, _email_key(address), limit, window, now=now)

    password_hash = password_hash or passwords.hash_password(password)  # also on the known-email path (timing)
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
def _find_pending(db: Session, raw_token: str | None, kind: str | None = "member") -> PendingRegistration | None:
    """The pending row of that token; `kind=None` matches member and guest tokens."""
    if not isinstance(raw_token, str) or not raw_token or len(raw_token) > MAX_RAW_TOKEN_LENGTH:
        return None
    query = select(PendingRegistration).where(PendingRegistration.token_hash == hash_token(raw_token))
    if kind is not None:
        query = query.where(PendingRegistration.kind == kind)
    return db.scalar(query)


def _usable(row: PendingRegistration | None, now: datetime) -> bool:
    return row is not None and row.consumed_at is None and ensure_utc(row.expires_at) > now


def peek_pending(db: Session, raw_token: str | None, now: datetime | None = None) -> PendingView | None:
    """Read-only (GET /verify): display data for a valid member or guest token, else None (``kind`` tells which
    page to show). A guest token whose sponsor is no longer an active verified member is not usable either.
    Writes nothing, not even for expired or consumed tokens; the failures are indistinguishable."""
    now = ensure_utc(now) if now is not None else utcnow()
    row = _find_pending(db, raw_token, kind=None)
    if not _usable(row, now):
        return None
    if row.kind == "guest" and _active_member(db, row.sponsor_id) is None:
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


# ----- guests: request, approve, reject ---------------------------------------------------------
@dataclass(frozen=True)
class GuestRequestResult:
    """Outcome of `begin_guest`. Callers show the SAME neutral page whatever the internals were. `token` (the raw
    approval token, only ever mailed to `sponsor_email`) is set exactly when a request was stored; `repr` hides
    it. No match, a full sponsor or a deactivated sponsor all give ``token=None`` and nothing to send."""

    sponsor_email: str
    token: str | None = field(default=None, repr=False)
    pending_id: uuid.UUID | None = None
    guest_display_name: str = ""
    guest_username: str = ""


def _active_member(db: Session, user_id: uuid.UUID | None) -> User | None:
    """The user if it is an active, verified member (the only kind that may sponsor), else None."""
    if user_id is None:
        return None
    user = db.get(User, user_id)
    if (user is None or user.account_kind != "member" or user.verified_at is None or user.status != "active"
            or user.email is None):
        return None
    return user


def begin_guest(db: Session, *, username: str, display_name: str, password: str, sponsor_email: str,
                privacy_ack: bool, ip: str, now: datetime | None = None,
                password_hash: str | None = None) -> GuestRequestResult:
    """Validate a guest registration and, if `sponsor_email` belongs to a verified active member, store a
    `pending_registrations` row (kind guest, chair inherited from the sponsor).

    Same validation as `begin_member` (username incl. CLI-admin namespace, display name, password policy,
    privacy). The sponsor address must pass the domain check (``InvalidInput`` field ``email``, reason
    ``domain``; the allowed domains are public). Beyond that the caller-visible outcome is identical for a
    member's address, a non-member address, a sponsor with 5 open requests and a deactivated sponsor: a result
    without token and no error. Only the per-IP limit (3 per hour) may raise `RateLimited`.
    The caller mails `mail_for_guest_request(result)` (None when there is nothing to send) after its commit.
    `password_hash`: a hash computed before the write transaction, as for `begin_member`.
    """
    now = ensure_utc(now) if now is not None else utcnow()
    bucket, limit, window = GUEST_REQUEST_IP
    if ratelimit.is_limited(db, bucket, ratelimit.ip_key(ip), limit, window, now):
        raise RateLimited("too many requests", bucket=bucket)
    normalized = _check_username_probe(db, username, ip, now)  # a "taken" answer counts as a probe, not as a request
    ratelimit.record_hit(db, bucket, ratelimit.ip_key(ip), now)
    name = clean_display_name(display_name)
    address = validate_email(sponsor_email)
    passwords.validate_policy(password, normalized)
    if privacy_ack is not True:
        raise InvalidInput("the privacy notice must be acknowledged", field="privacy")

    password_hash = password_hash or passwords.hash_password(password)  # always (timing)
    neutral = GuestRequestResult(sponsor_email=address, guest_display_name=name, guest_username=normalized)
    sponsor = db.scalar(select(User).where(User.email == address, User.account_kind == "member",
                                           User.verified_at.is_not(None), User.status == "active"))
    if sponsor is None:
        return neutral
    open_requests = db.scalar(
        select(func.count()).select_from(PendingRegistration)
        .where(PendingRegistration.sponsor_id == sponsor.id, PendingRegistration.kind == "guest",
               PendingRegistration.consumed_at.is_(None), PendingRegistration.expires_at > now))
    if open_requests >= MAX_OPEN_REQUESTS_PER_SPONSOR:
        audit.log(db, actor_type="system", action="registration.guest_request_limited", target_type="user",
                  target_id=sponsor.id, metadata={"username": normalized}, ip=ip, now=now)
        return neutral

    raw_token = secrets.token_urlsafe(TOKEN_BYTES)
    pending = PendingRegistration(
        kind="guest", username=normalized, username_normalized=normalized, display_name=name,
        chair_id=sponsor.chair_id, sponsor_id=sponsor.id, password_hash=password_hash,
        token_hash=hash_token(raw_token), created_at=now,
        expires_at=now + timedelta(days=get_settings().guest_approval_ttl_days))
    db.add(pending)
    db.flush()
    audit.log(db, actor_type="system", action="registration.requested", target_type="pending_registration",
              target_id=pending.id,
              metadata={"kind": "guest", "username": normalized, "sponsor_id": str(sponsor.id),
                        "chair_id": str(sponsor.chair_id)}, ip=ip, now=now)
    return GuestRequestResult(sponsor_email=address, token=raw_token, pending_id=pending.id,
                              guest_display_name=name, guest_username=normalized)


def mail_for_guest_request(result: GuestRequestResult) -> MailMessage | None:
    """The approval request for the SPONSOR's address, or None when no request was stored.

        message = mail_for_guest_request(result)
        if message is not None:
            background_tasks.add_task(send_in_background, message, result.sponsor_email)
    """
    if result.token is None:
        return None
    subject, body = guest_sponsor_request(guest_display_name=result.guest_display_name,
                                          guest_username=result.guest_username, token=result.token)
    return build_message(to=result.sponsor_email, subject=subject, body=body)


def _consume_guest(db: Session, row: PendingRegistration, now: datetime) -> None:
    """Consume the request atomically (``UPDATE ... WHERE consumed_at IS NULL``); `InvalidToken` if somebody
    else got there first."""
    consumed = db.execute(
        update(PendingRegistration)
        .where(PendingRegistration.id == row.id, PendingRegistration.consumed_at.is_(None),
               PendingRegistration.expires_at > now)
        .values(consumed_at=now).execution_options(synchronize_session=False))
    if consumed.rowcount != 1:
        raise InvalidToken("approval link is invalid or expired")


def approve_guest(db: Session, raw_token: str | None, *, ip: str | None = None, now: datetime | None = None) -> User:
    """POST /verify/{token} "Approve": create the guest account. ONE transaction, no session is issued (the
    guest signs in afterwards). The chair is the sponsor's chair at this moment.

    Raises `InvalidToken` (unknown, expired, consumed, or the sponsor is no longer an active verified member),
    `Conflict` (reason ``username_taken``: somebody took the name meanwhile) or `InvalidInput` (the sponsor's
    chair was deactivated). Failures raise out of the caller's transaction, so the token is not burnt.
    """
    now = ensure_utc(now) if now is not None else utcnow()
    row = _find_pending(db, raw_token, kind="guest")
    if not _usable(row, now):
        raise InvalidToken("approval link is invalid or expired")
    sponsor = _active_member(db, row.sponsor_id)
    if sponsor is None:
        raise InvalidToken("approval link is invalid or expired", reason="sponsor_inactive")
    if username_taken(db, row.username_normalized):
        raise Conflict("username is taken", field="username", reason=REASON_USERNAME_TAKEN)
    _consume_guest(db, row, now)
    try:
        with db.begin_nested():
            guest = users.create_account(
                db, kind="guest", username=row.username, username_normalized=row.username_normalized,
                display_name=row.display_name, chair_id=sponsor.chair_id, password_hash=row.password_hash,
                sponsor_id=sponsor.id, verified_at=now, now=now)
    except IntegrityError as exc:  # lost a race on the unique username index
        raise Conflict("username is taken", field="username", reason=REASON_USERNAME_TAKEN) from exc
    audit.log(db, actor_type="user", actor_id=sponsor.id, action="guest.approved", target_type="user",
              target_id=guest.id,
              metadata={"username": guest.username, "sponsor_id": str(sponsor.id), "chair_id": str(guest.chair_id),
                        "pending_registration_id": str(row.id)}, ip=ip, now=now)
    return guest


def reject_guest(db: Session, raw_token: str | None, *, ip: str | None = None, now: datetime | None = None) -> None:
    """POST /verify/{token} "Reject": consume the request without creating anything. `InvalidToken` when
    unknown, expired or consumed."""
    now = ensure_utc(now) if now is not None else utcnow()
    row = _find_pending(db, raw_token, kind="guest")
    if not _usable(row, now):
        raise InvalidToken("approval link is invalid or expired")
    _consume_guest(db, row, now)
    audit.log(db, actor_type="user", actor_id=row.sponsor_id, action="guest.rejected",
              target_type="pending_registration", target_id=row.id,
              metadata={"username": row.username, "sponsor_id": str(row.sponsor_id)}, ip=ip, now=now)


def reassign_sponsor(db: Session, *, head_admin: AdminUser, guest_id: uuid.UUID, new_sponsor_id: uuid.UUID,
                     ip: str | None = None, now: datetime | None = None) -> User:
    """Head admin only (`Forbidden` otherwise): give a guest a new sponsor. The new sponsor must be an active
    verified member (`InvalidInput`, field ``sponsor``); the guest's chair becomes the new sponsor's chair
    (one chair per person, guests inherit it). Audited with old and new sponsor and chair. The same sponsor
    again changes and audits nothing. `NotFound` for an unknown id, `InvalidInput` (field ``guest``) if the
    user is not a guest."""
    require_global(head_admin)
    guest = users.get_user(db, guest_id)
    if guest.account_kind != "guest":
        raise InvalidInput("user is not a guest", field="guest")
    sponsor = _active_member(db, new_sponsor_id)
    if sponsor is None:
        raise InvalidInput("the new sponsor must be an active, verified member", field="sponsor")
    if guest.sponsor_id == sponsor.id:
        return guest
    if not sponsor.chair.active:
        raise InvalidInput("unknown or inactive chair", field="sponsor")
    now = ensure_utc(now) if now is not None else utcnow()
    old_sponsor_id, old_chair_id = guest.sponsor_id, guest.chair_id
    guest.sponsor_id = sponsor.id
    guest.chair_id = sponsor.chair_id
    db.flush()
    db.expire(guest, ["chair"])
    audit.log(db, actor_type="admin", actor_id=head_admin.id, action="guest.sponsor_reassigned",
              target_type="user", target_id=guest.id,
              metadata={"from_sponsor_id": str(old_sponsor_id), "to_sponsor_id": str(sponsor.id),
                        "from_chair_id": str(old_chair_id), "to_chair_id": str(sponsor.chair_id)}, ip=ip, now=now)
    return guest


# ----- guards -----------------------------------------------------------------------------------
def ensure_member(user: User | None) -> User:
    """Service-level guard for member-only roles (task 4.3 calls it before linking an admin account): raises
    `Forbidden` (``reason="not_member"``) for a guest, a legacy profile without account kind, or no user."""
    if user is None or user.account_kind != "member":
        raise Forbidden("only members may do this", reason="not_member")
    return user


def recovery_address(user: User, db: Session | None = None) -> str | None:
    """Where password-recovery mail for `user` goes: a member's own address, a guest's sponsor's address.
    None when there is none (legacy profile; a guest whose sponsor is no longer an active verified member:
    the head admin must reassign first). Never looks anything up by e-mail address."""
    if user.account_kind == "member":
        return user.email
    if user.account_kind == "guest":
        db = db or object_session(user)
        if db is None:
            raise ValueError("a database session is needed to resolve a guest's sponsor")
        sponsor = _active_member(db, user.sponsor_id)
        return sponsor.email if sponsor is not None else None
    return None
