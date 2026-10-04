"""Administrator accounts, passwords, TOTP enrolment and admin sessions (PLAN-v2 section 4).

* Two kinds of admin log in at `/admin/login`: a CLI admin (`admin_users.password_hash`, Argon2id,
  username unique among admins) and a group admin (role `chair`, linked to a user account through
  `admin_users.user_id`): the identifier is then the account username and the password checked is
  the account password (`users.password_hash`). A linked user must be active and verified.
* Sessions: separate table, random 256-bit token (only its SHA-256 is stored), absolute expiry
  `ADMIN_SESSION_HOURS`. A correct password login creates a FULL session with `stepup_until = NULL`;
  there is no TOTP prompt at login. A TOTP step-up (task 4.2) later opens `stepup_until`;
  `has_open_stepup` tells whether it is open.
* TOTP: `pyotp`, enrolled once (`begin_enrollment` / `complete_enrollment`, 8 single-use recovery
  codes stored as keyed hashes). While `BALANCE_TOTP_REQUIRED` is true an admin without TOTP is
  confined to the enrolment pages (`enrolment_required`). Codes cannot be replayed within 120 s.
* Rate limiting: password failures (and failed enrolment codes) share one bucket per
  username+IP plus a per-IP cap across usernames, stored in the database
  (`ratelimit.ADMIN_LOGIN_FAILURES[_IP]`). Rate-limited attempts are audited once per window.
* Every login attempt is audited; neither passwords, codes nor tokens are ever logged.

Login functions never raise for bad credentials: they record the failure (rate-limit hit and
audit entry) in the caller's transaction and return an outcome, so the caller can commit it
and then render an error. Like all services these functions never commit, except `start_login`,
which manages its own short transactions so the Argon2 check runs outside the write lock.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

import pyotp
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import write_session
from app.models import ADMIN_ROLES, AdminSession, AdminUser, User
from app.services import audit, keys, passwords, ratelimit, signing
from app.services.errors import Conflict, InvalidInput, NotFound
from app.timeutil import ensure_utc, utcnow

ADMIN_COOKIE = "coffee_admin"
MIN_PASSWORD_LENGTH = 12  # CLI admins; group admins follow the account password policy
MAX_PASSWORD_LENGTH = passwords.MAX_PASSWORD_LENGTH
MAX_USERNAME_LENGTH = 64
TOUCH_INTERVAL = timedelta(minutes=10)
RECOVERY_CODE_COUNT = 8
MAX_RAW_TOKEN_LENGTH = 100
TOTP_REPLAY_WINDOW_SECONDS = 120


def _now(now: datetime | None) -> datetime:
    return ensure_utc(now) if now is not None else utcnow()


# ----- usernames and passwords ----------------------------------------------------------------
def normalize_username(username: str) -> str:
    return " ".join((username or "").split()).casefold()


def clean_username(username: str) -> str:
    name = " ".join((username or "").split())
    if not name or len(name) > MAX_USERNAME_LENGTH or any(ord(c) < 32 for c in name):
        raise InvalidInput(f"username must be 1-{MAX_USERNAME_LENGTH} printable characters")
    return name


def validate_password(password: str) -> str:
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        raise InvalidInput(f"password must have at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise InvalidInput(f"password must have at most {MAX_PASSWORD_LENGTH} characters")
    return password


def hash_password(password: str) -> str:
    """Argon2id hash of a CLI admin password (policy: 12..128 characters)."""
    return passwords.hash_password(validate_password(password))


def verify_password(password_hash: str, password: str) -> bool:
    """False for a wrong password and for hashes that are not Argon2 (e.g. disabled "!")."""
    return passwords.verify_password(password_hash, password)


# ----- accounts -------------------------------------------------------------------------------
def get_by_username(db: Session, username: str) -> AdminUser | None:
    return db.scalar(select(AdminUser).where(AdminUser.username_normalized == normalize_username(username)))


def get_admin(db: Session, username: str) -> AdminUser:
    admin = get_by_username(db, username)
    if admin is None:
        raise NotFound("administrator not found")
    return admin


def list_admins(db: Session) -> list[AdminUser]:
    return list(db.scalars(select(AdminUser).order_by(AdminUser.username_normalized)))


def any_admin_exists(db: Session) -> bool:
    return db.scalar(select(func.count()).select_from(AdminUser)) > 0


def _sys(admin_actor: AdminUser | None) -> tuple[str, str | None]:
    return audit.admin_actor(admin_actor)


def is_group_admin(admin: AdminUser) -> bool:
    """A group admin (role `chair`) signs in with the password of the linked user account."""
    return admin.user_id is not None


def create_admin(
    db: Session, *, username: str, password: str, role: str,
    actor: AdminUser | None = None, ip: str | None = None, source: str = "cli", now: datetime | None = None,
) -> AdminUser:
    """Create a CLI administrator (`actor=None` is the system actor).

    Only role `global` is available from this path: group admins are promoted members (task 4.3).
    A username that a user account already holds is refused (the login identifier must be unique).
    """
    now = _now(now)
    username = clean_username(username)
    if role not in ADMIN_ROLES:
        raise InvalidInput("role must be 'global' or 'chair'")
    if role == "chair":  # needs a linked user account (admin_users.user_id); built in task 4.3
        raise InvalidInput("group admins are promoted from a member account; not available from this path yet")
    normalized = normalize_username(username)
    if get_by_username(db, username) is not None:
        raise Conflict("an administrator with this username already exists")
    if db.scalar(select(User.id).where(User.username_normalized == normalized)) is not None:
        raise Conflict("a user account with this username already exists")
    admin = AdminUser(username=username, username_normalized=normalized,
                      password_hash=hash_password(password), role=role, active=True, recovery_codes=[],
                      created_at=now)
    db.add(admin)
    db.flush()
    db.refresh(admin)
    actor_type, actor_id = _sys(actor)
    audit.log(db, actor_type=actor_type, actor_id=actor_id, action="admin.created", target_type="admin",
              target_id=admin.id, metadata={"username": username, "role": role, "source": source},
              ip=ip, now=now)
    return admin


def bootstrap_admin(db: Session, *, now: datetime | None = None) -> AdminUser | None:
    """First-start bootstrap from `ADMIN_BOOTSTRAP_USERNAME` / `ADMIN_BOOTSTRAP_PASSWORD`.

    Creates one global administrator, and only while no administrator exists at all; both
    variables must be set (otherwise nothing happens). Returns the new admin or None.
    """
    s = get_settings()
    if not s.admin_bootstrap_username or not s.admin_bootstrap_password:
        return None
    if any_admin_exists(db):
        return None
    return create_admin(db, username=s.admin_bootstrap_username, password=s.admin_bootstrap_password,
                        role="global", source="bootstrap", now=now)


def reset_password(db: Session, admin: AdminUser, new_password: str, *, actor: AdminUser | None = None,
                   ip: str | None = None, now: datetime | None = None) -> AdminUser:
    """Set a new password and revoke every session of the admin (CLI `reset-admin-password`).

    Only for CLI admins: a group admin's password is their account password (forgot-password flow).
    """
    now = _now(now)
    if is_group_admin(admin):
        raise InvalidInput("a group admin's password is the account password; use the forgot-password flow")
    admin.password_hash = hash_password(new_password)
    revoked = revoke_admin_sessions(db, admin.id, now=now)
    db.flush()
    actor_type, actor_id = _sys(actor)
    audit.log(db, actor_type=actor_type, actor_id=actor_id, action="admin.password_reset", target_type="admin",
              target_id=admin.id, metadata={"sessions_revoked": revoked}, ip=ip, now=now)
    return admin


def reset_totp(db: Session, admin: AdminUser, *, actor: AdminUser | None = None, ip: str | None = None,
               now: datetime | None = None) -> AdminUser:
    """Forget the TOTP secret and recovery codes; the admin enrols again (forced while BALANCE_TOTP_REQUIRED)."""
    now = _now(now)
    admin.totp_secret = None
    admin.totp_enabled = False
    admin.recovery_codes = []
    revoked = revoke_admin_sessions(db, admin.id, now=now)
    db.flush()
    actor_type, actor_id = _sys(actor)
    audit.log(db, actor_type=actor_type, actor_id=actor_id, action="admin.totp_reset", target_type="admin",
              target_id=admin.id, metadata={"sessions_revoked": revoked}, ip=ip, now=now)
    return admin


def set_admin_active(db: Session, admin: AdminUser, active: bool, *, actor: AdminUser | None = None,
                     ip: str | None = None, now: datetime | None = None) -> AdminUser:
    now = _now(now)
    admin.active = active
    revoked = 0 if active else revoke_admin_sessions(db, admin.id, now=now)
    db.flush()
    actor_type, actor_id = _sys(actor)
    audit.log(db, actor_type=actor_type, actor_id=actor_id,
              action="admin.enabled" if active else "admin.disabled", target_type="admin", target_id=admin.id,
              metadata={"sessions_revoked": revoked}, ip=ip, now=now)
    return admin


# ----- sessions -------------------------------------------------------------------------------
def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _new_session(db: Session, admin: AdminUser, *, now: datetime,
                 stepup_until: datetime | None = None) -> tuple[AdminSession, str]:
    """A full admin session (`ADMIN_SESSION_HOURS`); `stepup_until` is NULL unless given."""
    raw = secrets.token_urlsafe(32)
    session = AdminSession(admin_id=admin.id, token_hash=hash_token(raw), created_at=now, last_seen_at=now,
                           expires_at=now + timedelta(hours=get_settings().admin_session_hours),
                           stepup_until=stepup_until, csrf_secret=secrets.token_urlsafe(24))
    db.add(session)
    db.flush()
    return session, raw


def revoke_session(db: Session, session_id: uuid.UUID, now: datetime | None = None) -> bool:
    result = db.execute(
        update(AdminSession).where(AdminSession.id == session_id, AdminSession.revoked_at.is_(None))
        .values(revoked_at=_now(now)).execution_options(synchronize_session=False))
    return result.rowcount == 1


def revoke_admin_sessions(db: Session, admin_id: uuid.UUID, *, except_session_id: uuid.UUID | None = None,
                          now: datetime | None = None) -> int:
    q = update(AdminSession).where(AdminSession.admin_id == admin_id, AdminSession.revoked_at.is_(None))
    if except_session_id is not None:
        q = q.where(AdminSession.id != except_session_id)
    return db.execute(q.values(revoked_at=_now(now)).execution_options(synchronize_session=False)).rowcount


def _account_ok(admin: AdminUser) -> bool:
    """Can this admin sign in at all: active, and for a group admin the linked user is active and verified."""
    if not admin.active:
        return False
    if admin.user_id is None:
        return True
    user = admin.user
    return user is not None and user.status == "active" and user.verified_at is not None


def resolve_session(db: Session, raw_token: str | None, now: datetime | None = None) -> tuple[AdminSession, AdminUser] | None:
    """(session, admin) for a live token (not revoked, not expired, admin and linked user usable), else None."""
    if not raw_token or len(raw_token) > MAX_RAW_TOKEN_LENGTH:
        return None
    now = _now(now)
    row = db.execute(
        select(AdminSession, AdminUser).join(AdminUser, AdminUser.id == AdminSession.admin_id)
        .where(AdminSession.token_hash == hash_token(raw_token))
    ).first()
    if row is None:
        return None
    session, admin = row
    if session.revoked_at is not None or ensure_utc(session.expires_at) <= now or not _account_ok(admin):
        return None
    return session, admin


def has_open_stepup(session: AdminSession, now: datetime | None = None) -> bool:
    """True while the session's step-up window (`stepup_until`) is still open."""
    return session.stepup_until is not None and ensure_utc(session.stepup_until) > _now(now)


def enrolment_required(admin: AdminUser) -> bool:
    """TOTP enrolment is compulsory: `BALANCE_TOTP_REQUIRED` is on and the admin has not enrolled yet."""
    return bool(get_settings().balance_totp_required) and not admin.totp_enabled


def needs_touch(session: AdminSession, now: datetime | None = None) -> bool:
    return ensure_utc(session.last_seen_at) <= _now(now) - TOUCH_INTERVAL


def touch_session(db: Session, session_id: uuid.UUID, now: datetime | None = None) -> None:
    db.execute(update(AdminSession).where(AdminSession.id == session_id).values(last_seen_at=_now(now))
               .execution_options(synchronize_session=False))


def list_sessions(db: Session, admin_id: uuid.UUID, now: datetime | None = None) -> list[AdminSession]:
    """The admin's live sessions, newest first."""
    now = _now(now)
    return list(db.scalars(
        select(AdminSession).where(AdminSession.admin_id == admin_id, AdminSession.revoked_at.is_(None),
                                   AdminSession.expires_at > now)
        .order_by(AdminSession.created_at.desc())))


# ----- TOTP and recovery codes ----------------------------------------------------------------
def _normalize_code(code: str | None) -> str:
    return re.sub(r"[\s-]", "", code or "").upper()


def _recovery_hash(code: str) -> str:
    return signing.mac("admin-recovery", _normalize_code(code))


def new_recovery_codes() -> list[str]:
    """8 random codes like `ABCD-EFGH-JKLM` (60 bits each)."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    codes = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = "".join(secrets.choice(alphabet) for _ in range(12))
        codes.append("-".join(raw[i:i + 4] for i in range(0, 12, 4)))
    return codes


def totp_uri(admin: AdminUser, secret: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=admin.username, issuer_name=get_settings().app_title)


def _attached(db: Session, admin: AdminUser) -> AdminUser:
    """The admin as loaded in `db` (callers may hold a detached copy from an earlier read session)."""
    current = db.get(AdminUser, admin.id)
    if current is None:
        raise NotFound("administrator not found")
    return current


def begin_enrollment(db: Session, admin: AdminUser) -> str:
    """Make sure the admin has a (not yet enabled) TOTP secret; returns it. Refuses if enabled."""
    admin = _attached(db, admin)
    if admin.totp_enabled:
        raise Conflict("TOTP is already enabled")
    if not admin.totp_secret:
        admin.totp_secret = pyotp.random_base32()
        db.flush()
    return admin.totp_secret


def _totp_matches(db: Session, admin: AdminUser, code: str, now: datetime) -> bool:
    """Valid 6-digit TOTP code (+-1 step) that was not accepted before (no replay, 120 s)."""
    code = _normalize_code(code)
    if not admin.totp_secret or not re.fullmatch(r"[0-9]{6}", code):
        return False
    if not pyotp.TOTP(admin.totp_secret).verify(code, for_time=now, valid_window=1):
        return False
    key = signing.mac("admin-totp-used", f"{admin.id}:{code}")
    if ratelimit.count_hits(db, "admin_totp_used", key, TOTP_REPLAY_WINDOW_SECONDS, now) > 0:
        return False
    ratelimit.record_hit(db, "admin_totp_used", key, now)
    return True


def _consume_recovery_code(admin: AdminUser, code: str) -> bool:
    """Remove a matching single-use recovery code (used by `open_stepup`; call it on an admin loaded inside the write transaction)."""
    wanted = _recovery_hash(code)
    stored = list(admin.recovery_codes or [])
    for h in stored:
        if secrets.compare_digest(h, wanted):
            admin.recovery_codes = [x for x in stored if x != h]
            return True
    return False


def open_stepup(db: Session, *, session_id: uuid.UUID, admin: AdminUser, code: str, ip: str,
                now: datetime | None = None) -> str:
    """Open the session's step-up window with a TOTP or recovery code (task 4.2; caller commits).

    Returns `"window"` (it was already open: the code is NOT consumed, the window is not extended),
    `"totp"` or `"recovery_code"` (code accepted: `stepup_until = now + STEPUP_WINDOW_SECONDS`, fixed),
    `"invalid"` (wrong code or replay: counted by the admin rate limiter and audited), `"limited"`
    (rate limit hit; nothing is checked) or `"no_session"`. Must run in a write transaction: the admin
    row is re-read inside it, so a recovery code can be spent only once even under concurrency
    (writers are serialized by `BEGIN IMMEDIATE`). The code itself is never logged.
    """
    now = _now(now)
    admin = _attached(db, admin)
    session = db.get(AdminSession, session_id)
    if session is None or session.revoked_at is not None or session.admin_id != admin.id \
            or ensure_utc(session.expires_at) <= now:
        return "no_session"
    if has_open_stepup(session, now):
        return "window"
    if _limited(db, username=admin.username, ip=ip, step="stepup", admin=admin, now=now):
        return "limited"
    normalized = _normalize_code(code)
    method = "totp" if re.fullmatch(r"[0-9]{6}", normalized) else "recovery_code"
    if not admin.totp_enabled:
        ok = False
    elif method == "totp":
        ok = _totp_matches(db, admin, normalized, now)
    else:
        ok = _consume_recovery_code(admin, normalized)
    if not ok:
        _fail(db, username=admin.username, ip=ip, step="stepup", admin=admin, now=now, action="admin.stepup.failed")
        return "invalid"
    session.stepup_until = now + timedelta(seconds=get_settings().stepup_window_seconds)
    db.flush()
    meta = {"method": method, "window_seconds": get_settings().stepup_window_seconds}
    if method == "recovery_code":
        meta["recovery_codes_left"] = len(admin.recovery_codes or [])
    audit.log(db, actor_type="admin", actor_id=admin.id, action="admin.stepup.opened", target_type="admin",
              target_id=admin.id, metadata=meta, ip=ip, now=now)
    return method


# ----- login flow -----------------------------------------------------------------------------
@dataclass
class LoginOutcome:
    status: str  # "ok" | "invalid" | "limited"
    admin: AdminUser | None = None
    session: AdminSession | None = None
    raw_token: str | None = None
    recovery_codes: list[str] | None = None  # shown once after enrolment


def _credential_hash(admin: AdminUser) -> str | None:
    """The stored password hash that logs this admin in: the linked user's for a group admin."""
    if admin.user_id is not None:
        return admin.user.password_hash if admin.user is not None else None
    return admin.password_hash


def _login_target(db: Session, identifier: str) -> tuple[AdminUser | None, str | None]:
    """(admin, password hash to check) for a login identifier.

    A CLI admin username wins; otherwise the identifier is the account username of a user linked to
    an admin row. The hash is None when the account cannot sign in (unknown, disabled, group admin
    whose user is inactive/unverified, no usable hash): the caller then burns a decoy hash check.
    """
    normalized = normalize_username(identifier)
    if not normalized:
        return None, None
    admin = db.scalar(select(AdminUser).where(AdminUser.username_normalized == normalized,
                                              AdminUser.user_id.is_(None)))
    if admin is None:
        admin = db.scalar(select(AdminUser).join(User, User.id == AdminUser.user_id)
                          .where(User.username_normalized == normalized))
    if admin is None or not _account_ok(admin):
        return admin, None
    return admin, _credential_hash(admin)


def _attempt_meta(username: str, admin: AdminUser | None, step: str) -> dict:
    """Audit metadata for a failed or limited login. The attempted text is never stored as typed (people
    paste passwords into the username field): only a short keyed hash (HKDF key `admin-login-username`, 16 hex
    characters, enough to correlate repeated attempts), plus the name itself when it matches an existing
    admin account."""
    digest = hmac.new(keys.derive_key("admin-login-username"),
                      normalize_username(username or "")[:MAX_USERNAME_LENGTH].encode("utf-8"),
                      hashlib.sha256).hexdigest()[:16]
    meta = {"step": step, "username_hash": digest}
    if admin is not None:
        meta["username"] = (username or "")[:MAX_USERNAME_LENGTH]
    return meta


def _limit_key(username: str, ip: str) -> str:
    return f"{normalize_username(username)[:MAX_USERNAME_LENGTH]}|{ip}"


def _limit_checks(username: str, ip: str):
    """(bucket, key, limit, window) for every cap a login attempt counts against."""
    user_bucket, user_limit, window = ratelimit.ADMIN_LOGIN_FAILURES
    ip_bucket, ip_limit, ip_window = ratelimit.ADMIN_LOGIN_FAILURES_IP
    return ((user_bucket, _limit_key(username, ratelimit.ip_key(ip)), user_limit, window), (ip_bucket, ratelimit.ip_key(ip), ip_limit, ip_window))


def _fail(db: Session, *, username: str, ip: str, step: str, admin: AdminUser | None, now: datetime,
          record_hits: bool = True, action: str = "admin.login.failed") -> LoginOutcome:
    if record_hits:
        for bucket, key, _limit, _window in _limit_checks(username, ip):
            ratelimit.record_hit(db, bucket, key, now)
    audit.log(db, actor_type="admin" if admin else "system", actor_id=admin.id if admin else None,
              action=action, target_type="admin", target_id=admin.id if admin else None,
              metadata=_attempt_meta(username, admin, step), ip=ip, now=now)
    return LoginOutcome("invalid")


def _tripped_key(db: Session, username: str, ip: str, now: datetime) -> str | None:
    """Key of the first cap that is exhausted (`bucket|key`), or None when the attempt may proceed."""
    for bucket, key, limit, window in _limit_checks(username, ip):
        if ratelimit.is_limited(db, bucket, key, limit, window, now):
            return f"{bucket}|{key}"
    return None


def _limited(db: Session, *, username: str, ip: str, step: str, admin: AdminUser | None, now: datetime) -> bool:
    """True when rate limited. The refusal is audited at most once per window and exhausted cap
    (username+IP or whole IP), so an anonymous client cannot grow the append-only audit log with
    every rejected attempt."""
    marker = _tripped_key(db, username, ip, now)
    if marker is None:
        return False
    if ratelimit.count_hits(db, "admin_login_audit", marker, ratelimit.ADMIN_LOGIN_FAILURES[2], now) == 0:
        ratelimit.record_hit(db, "admin_login_audit", marker, now)
        audit.log(db, actor_type="system", action="admin.login.rate_limited", target_type="admin",
                  target_id=admin.id if admin else None,
                  metadata=_attempt_meta(username, admin, step), ip=ip, now=now)
    return True


def start_login(*, username: str, password: str, ip: str, old_raw_token: str | None = None,
                now: datetime | None = None) -> LoginOutcome:
    """Password login. `old_raw_token` (a previous admin cookie) is revoked: sessions rotate on login.

    A correct password yields a full session with `stepup_until = NULL`; there is no second factor
    at login. Unlike the other services this opens and commits its own short transactions: the
    Argon2 check must never run while the SQLite write lock is held, or unauthenticated requests
    could stall every writer. Steps: (1) write txn: limit check and up-front count of this attempt
    as a failure (keeps the budget strict for parallel guesses); (2) no transaction: password /
    decoy hash check; (3) write txn: audit, or release the counted failure and issue the session.
    """
    now = _now(now)
    with write_session() as db:
        admin, password_hash = _login_target(db, username)
        if _limited(db, username=username, ip=ip, step="password", admin=admin, now=now):
            return LoginOutcome("limited")
        hit_ids = [ratelimit.record_hit(db, bucket, key, now) for bucket, key, _l, _w in _limit_checks(username, ip)]
        admin_id = admin.id if admin else None
    if password_hash is not None:
        ok = verify_password(password_hash, password)
    else:
        passwords.verify_dummy(password)
        ok = False
    with write_session() as db:
        admin = db.get(AdminUser, admin_id) if admin_id else None
        # The account may have been disabled or its password changed while we were hashing.
        if not ok or admin is None or not _account_ok(admin) or _credential_hash(admin) != password_hash:
            outcome = _fail(db, username=username, ip=ip, step="password", admin=admin, now=now, record_hits=False)
            db.expunge_all()
            return outcome
        ratelimit.release_hits(db, hit_ids)
        old = resolve_session(db, old_raw_token, now) if old_raw_token else None
        if old is not None:
            revoke_session(db, old[0].id, now)
        session, raw = _new_session(db, admin, now=now)
        admin.last_login_at = now
        db.flush()
        audit.log(db, actor_type="admin", actor_id=admin.id, action="admin.login.success", target_type="admin",
                  target_id=admin.id, metadata={"method": "password", "group_admin": is_group_admin(admin)},
                  ip=ip, now=now)
        db.expunge_all()
    return LoginOutcome("ok", admin, session, raw)


def complete_enrollment(db: Session, *, session: AdminSession, admin: AdminUser, code: str, ip: str,
                        now: datetime | None = None) -> LoginOutcome:
    """Verify the first TOTP code, enable TOTP and issue the recovery codes (shown once).

    The session stays; its `stepup_until` opens for `STEPUP_WINDOW_SECONDS` (enrolling proves possession).
    """
    now = _now(now)
    admin = _attached(db, admin)
    if admin.totp_enabled:
        raise Conflict("TOTP is already enabled")
    if _limited(db, username=admin.username, ip=ip, step="enroll", admin=admin, now=now):
        return LoginOutcome("limited")
    if not _totp_matches(db, admin, code, now):
        return _fail(db, username=admin.username, ip=ip, step="enroll", admin=admin, now=now)
    codes = new_recovery_codes()
    admin.totp_enabled = True
    admin.recovery_codes = [_recovery_hash(c) for c in codes]
    attached = db.get(AdminSession, session.id)
    if attached is None:
        raise NotFound("session not found")
    attached.stepup_until = now + timedelta(seconds=get_settings().stepup_window_seconds)
    db.flush()
    audit.log(db, actor_type="admin", actor_id=admin.id, action="admin.totp_enrolled", target_type="admin",
              target_id=admin.id, ip=ip, now=now)
    return LoginOutcome("ok", admin, attached, None, codes)


def logout(db: Session, session: AdminSession, admin: AdminUser, *, ip: str | None = None,
           now: datetime | None = None) -> None:
    revoke_session(db, session.id, now)
    audit.log(db, actor_type="admin", actor_id=admin.id, action="admin.logout", target_type="admin",
              target_id=admin.id, ip=ip, now=_now(now))


# ----- password change / session revocation by the admin themselves -----------------------------
def check_new_password(admin: AdminUser, new_password: str) -> None:
    """Policy for a new own password: CLI admins 12..128 characters, group admins the account policy."""
    if is_group_admin(admin) and admin.user is not None:
        passwords.validate_policy(new_password, admin.user.username or "", admin.user.email)
    else:
        validate_password(new_password)


def change_password(db: Session, *, session: AdminSession, admin: AdminUser, current_password: str,
                    new_password: str, ip: str, now: datetime | None = None) -> bool:
    """Change the own password; revokes all *other* admin sessions. False if the current password is
    wrong (counted as a login failure). Raises `InvalidInput` for a weak new password, `RateLimited` never
    (the caller checks `change_password_limited` first). For a group admin this is the account password."""
    now = _now(now)
    admin = _attached(db, admin)
    current_hash = _credential_hash(admin)
    if current_hash is None or not verify_password(current_hash, current_password):
        _fail(db, username=admin.username, ip=ip, step="password_change", admin=admin, now=now)
        return False
    check_new_password(admin, new_password)
    new_hash = passwords.hash_password(new_password)
    if is_group_admin(admin):
        admin.user.password_hash = new_hash
    else:
        admin.password_hash = new_hash
    revoked = revoke_admin_sessions(db, admin.id, except_session_id=session.id, now=now)
    db.flush()
    audit.log(db, actor_type="admin", actor_id=admin.id, action="admin.password_changed", target_type="admin",
              target_id=admin.id, metadata={"sessions_revoked": revoked}, ip=ip, now=now)
    return True


def change_password_limited(db: Session, admin: AdminUser, ip: str, now: datetime | None = None) -> bool:
    return _limited(db, username=admin.username, ip=ip, step="password_change", admin=admin, now=_now(now))


def revoke_other_sessions(db: Session, *, session: AdminSession, admin: AdminUser, ip: str | None = None,
                          now: datetime | None = None) -> int:
    now = _now(now)
    revoked = revoke_admin_sessions(db, admin.id, except_session_id=session.id, now=now)
    audit.log(db, actor_type="admin", actor_id=admin.id, action="admin.sessions_revoked", target_type="admin",
              target_id=admin.id, metadata={"sessions_revoked": revoked}, ip=ip, now=now)
    return revoked
