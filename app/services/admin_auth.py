"""Administrator accounts, passwords, TOTP and admin sessions (PROMPT §6, §7, §9).

* Passwords: Argon2id (`argon2-cffi` default type), minimum 12 characters.
* Sessions: separate table, random 256-bit token (only its SHA-256 is stored), absolute expiry
  `ADMIN_SESSION_HOURS`. A login first yields a short-lived *pending* session
  (`totp_verified = False`); the second factor (or enrollment) swaps it for a full session with
  a **new** token (rotation). Without a required/enabled TOTP the password step yields a full
  session directly.
* TOTP: `pyotp`, 8 single-use recovery codes stored as keyed hashes. Codes cannot be replayed
  within their validity window.
* Rate limiting: password and TOTP failures share one bucket per username+IP, stored in the
  database (`ratelimit.ADMIN_LOGIN_FAILURES`).
* Every login attempt is audited; neither passwords, codes nor tokens are ever logged.

Login functions never raise for bad credentials: they record the failure (rate-limit hit and
audit entry) in the caller's transaction and return an outcome, so the caller can commit it
and then render an error. Like all services these functions never commit.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import ADMIN_ROLES, AdminChair, AdminSession, AdminUser, Chair
from app.services import audit, ratelimit, signing
from app.services.errors import Conflict, InvalidInput, NotFound
from app.timeutil import ensure_utc, utcnow

ADMIN_COOKIE = "coffee_admin"
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256
MAX_USERNAME_LENGTH = 64
PENDING_SESSION_TTL = timedelta(minutes=10)
TOUCH_INTERVAL = timedelta(minutes=10)
RECOVERY_CODE_COUNT = 8
MAX_RAW_TOKEN_LENGTH = 100
TOTP_REPLAY_WINDOW_SECONDS = 120

_hasher = PasswordHasher()  # Argon2id
_dummy_hash: str | None = None


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
    return _hasher.hash(validate_password(password))


def verify_password(password_hash: str, password: str) -> bool:
    """False for a wrong password and for hashes that are not Argon2 (e.g. disabled "!")."""
    if not isinstance(password, str) or len(password) > MAX_PASSWORD_LENGTH:
        return False
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def _verify_against_dummy(password: str) -> None:
    """Burn comparable time for unknown usernames so timing does not reveal them."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = _hasher.hash(secrets.token_urlsafe(16))
    verify_password(_dummy_hash, password)


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


def _resolve_chairs(db: Session, chairs: Iterable) -> list[Chair]:
    found: dict[uuid.UUID, Chair] = {}
    for item in chairs:
        chair = item if isinstance(item, Chair) else db.get(Chair, item)
        if chair is None:
            raise NotFound("chair not found")
        found[chair.id] = chair
    return list(found.values())


def _sys(admin_actor: AdminUser | None) -> tuple[str, str | None]:
    return audit.admin_actor(admin_actor)


def create_admin(
    db: Session, *, username: str, password: str, role: str, chairs: Iterable = (),
    actor: AdminUser | None = None, ip: str | None = None, source: str = "cli", now: datetime | None = None,
) -> AdminUser:
    """Create an administrator (CLI/bootstrap use; `actor=None` is the system actor)."""
    now = _now(now)
    username = clean_username(username)
    if role not in ADMIN_ROLES:
        raise InvalidInput("role must be 'global' or 'chair'")
    chair_list = _resolve_chairs(db, chairs)
    if role == "chair" and not chair_list:
        raise InvalidInput("a chair administrator needs at least one chair")
    if role == "global" and chair_list:
        raise InvalidInput("global administrators are not tied to chairs")
    if get_by_username(db, username) is not None:
        raise Conflict("an administrator with this username already exists")
    admin = AdminUser(username=username, username_normalized=normalize_username(username),
                      password_hash=hash_password(password), role=role, active=True, recovery_codes=[],
                      created_at=now)
    db.add(admin)
    db.flush()
    for chair in chair_list:
        db.add(AdminChair(admin_id=admin.id, chair_id=chair.id))
    db.flush()
    db.refresh(admin)
    actor_type, actor_id = _sys(actor)
    audit.log(db, actor_type=actor_type, actor_id=actor_id, action="admin.created", target_type="admin",
              target_id=admin.id,
              metadata={"username": username, "role": role, "chairs": sorted(c.short_name for c in chair_list),
                        "source": source},
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


def set_admin_chairs(db: Session, admin: AdminUser, chairs: Iterable, *, actor: AdminUser | None = None,
                     ip: str | None = None) -> AdminUser:
    chair_list = _resolve_chairs(db, chairs)
    if admin.role != "chair":
        raise InvalidInput("only chair administrators have chair assignments")
    if not chair_list:
        raise InvalidInput("a chair administrator needs at least one chair")
    db.execute(delete(AdminChair).where(AdminChair.admin_id == admin.id))
    for chair in chair_list:
        db.add(AdminChair(admin_id=admin.id, chair_id=chair.id))
    db.flush()
    db.refresh(admin)
    actor_type, actor_id = _sys(actor)
    audit.log(db, actor_type=actor_type, actor_id=actor_id, action="admin.chairs_set", target_type="admin",
              target_id=admin.id, metadata={"chairs": sorted(c.short_name for c in chair_list)}, ip=ip)
    return admin


def reset_password(db: Session, admin: AdminUser, new_password: str, *, actor: AdminUser | None = None,
                   ip: str | None = None, now: datetime | None = None) -> AdminUser:
    """Set a new password and revoke every session of the admin (CLI `reset-admin-password`)."""
    now = _now(now)
    admin.password_hash = hash_password(new_password)
    revoked = revoke_admin_sessions(db, admin.id, now=now)
    db.flush()
    actor_type, actor_id = _sys(actor)
    audit.log(db, actor_type=actor_type, actor_id=actor_id, action="admin.password_reset", target_type="admin",
              target_id=admin.id, metadata={"sessions_revoked": revoked}, ip=ip, now=now)
    return admin


def reset_totp(db: Session, admin: AdminUser, *, actor: AdminUser | None = None, ip: str | None = None,
               now: datetime | None = None) -> AdminUser:
    """Forget the TOTP secret and recovery codes; the admin enrolls again at the next login."""
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


def _new_session(db: Session, admin: AdminUser, *, verified: bool, now: datetime) -> tuple[AdminSession, str]:
    raw = secrets.token_urlsafe(32)
    ttl = timedelta(hours=get_settings().admin_session_hours) if verified else PENDING_SESSION_TTL
    session = AdminSession(admin_id=admin.id, token_hash=hash_token(raw), created_at=now, last_seen_at=now,
                           expires_at=now + ttl, totp_verified=verified, csrf_secret=secrets.token_urlsafe(24))
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


def resolve_session(db: Session, raw_token: str | None, now: datetime | None = None) -> tuple[AdminSession, AdminUser] | None:
    """(session, admin) for a live token (not revoked, not expired, admin active), else None.

    The caller decides what a *pending* session (`is_complete` false) may do.
    """
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
    if session.revoked_at is not None or ensure_utc(session.expires_at) <= now or not admin.active:
        return None
    return session, admin


def is_complete(session: AdminSession, admin: AdminUser) -> bool:
    """A fully authenticated session: second factor done, and enrolled if TOTP is required."""
    if not session.totp_verified:
        return False
    return admin.totp_enabled or not get_settings().admin_totp_required


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
                                   AdminSession.expires_at > now, AdminSession.totp_verified.is_(True))
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
    """Valid 6-digit TOTP code (±1 step) that was not accepted before (no replay)."""
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
    wanted = _recovery_hash(code)
    stored = list(admin.recovery_codes or [])
    for h in stored:
        if secrets.compare_digest(h, wanted):
            admin.recovery_codes = [x for x in stored if x != h]
            return True
    return False


# ----- login flow -----------------------------------------------------------------------------
@dataclass
class LoginOutcome:
    status: str  # "ok" | "invalid" | "limited"
    admin: AdminUser | None = None
    session: AdminSession | None = None
    raw_token: str | None = None
    stage: str | None = None  # "done" | "totp" | "enroll" (next step)
    recovery_codes: list[str] | None = None  # shown once after enrollment


def _limit_key(username: str, ip: str) -> str:
    return f"{normalize_username(username)[:MAX_USERNAME_LENGTH]}|{ip}"


def _fail(db: Session, *, username: str, ip: str, step: str, admin: AdminUser | None, now: datetime) -> LoginOutcome:
    bucket = ratelimit.ADMIN_LOGIN_FAILURES[0]
    ratelimit.record_hit(db, bucket, _limit_key(username, ip), now)
    audit.log(db, actor_type="admin" if admin else "system", actor_id=admin.id if admin else None,
              action="admin.login.failed", target_type="admin", target_id=admin.id if admin else None,
              metadata={"step": step, "username_attempted": (username or "")[:MAX_USERNAME_LENGTH]},
              ip=ip, now=now)
    return LoginOutcome("invalid")


def _limited(db: Session, *, username: str, ip: str, step: str, admin: AdminUser | None, now: datetime) -> bool:
    bucket, limit, window = ratelimit.ADMIN_LOGIN_FAILURES
    if not ratelimit.is_limited(db, bucket, _limit_key(username, ip), limit, window, now):
        return False
    audit.log(db, actor_type="system", action="admin.login.rate_limited", target_type="admin",
              target_id=admin.id if admin else None,
              metadata={"step": step, "username_attempted": (username or "")[:MAX_USERNAME_LENGTH]}, ip=ip, now=now)
    return True


def _complete_login(db: Session, admin: AdminUser, *, ip: str, now: datetime, old_session_id: uuid.UUID | None,
                    method: str) -> tuple[AdminSession, str]:
    """Issue the full session (new token), drop the pending one, stamp and audit the login."""
    session, raw = _new_session(db, admin, verified=True, now=now)
    if old_session_id is not None:
        revoke_session(db, old_session_id, now)
    admin.last_login_at = now
    db.flush()
    audit.log(db, actor_type="admin", actor_id=admin.id, action="admin.login.success", target_type="admin",
              target_id=admin.id, metadata={"method": method}, ip=ip, now=now)
    return session, raw


def start_login(db: Session, *, username: str, password: str, ip: str, old_raw_token: str | None = None,
                now: datetime | None = None) -> LoginOutcome:
    """Password step. `old_raw_token` (a previous admin cookie) is revoked: sessions rotate on login."""
    now = _now(now)
    admin = get_by_username(db, username) if username else None
    if _limited(db, username=username, ip=ip, step="password", admin=admin, now=now):
        return LoginOutcome("limited")
    if admin is None or not admin.active:
        _verify_against_dummy(password)
        return _fail(db, username=username, ip=ip, step="password", admin=admin, now=now)
    if not verify_password(admin.password_hash, password):
        return _fail(db, username=username, ip=ip, step="password", admin=admin, now=now)

    old = resolve_session(db, old_raw_token, now) if old_raw_token else None
    old_id = old[0].id if old else None
    if admin.totp_enabled:
        stage = "totp"
    elif get_settings().admin_totp_required:
        stage = "enroll"
    else:
        stage = "done"
    if stage == "done":
        session, raw = _complete_login(db, admin, ip=ip, now=now, old_session_id=old_id, method="password")
    else:
        session, raw = _new_session(db, admin, verified=False, now=now)
        if old_id is not None:
            revoke_session(db, old_id, now)
        audit.log(db, actor_type="admin", actor_id=admin.id, action="admin.login.password_ok",
                  target_type="admin", target_id=admin.id, metadata={"next": stage}, ip=ip, now=now)
    return LoginOutcome("ok", admin, session, raw, stage)


def verify_second_factor(db: Session, *, session: AdminSession, admin: AdminUser, code: str, ip: str,
                         now: datetime | None = None) -> LoginOutcome:
    """TOTP or recovery code for a pending session; success swaps it for a full session."""
    now = _now(now)
    admin = _attached(db, admin)
    if _limited(db, username=admin.username, ip=ip, step="totp", admin=admin, now=now):
        return LoginOutcome("limited")
    method = None
    if admin.totp_enabled:
        if _totp_matches(db, admin, code, now):
            method = "totp"
        elif _consume_recovery_code(admin, code):
            method = "recovery_code"
            db.flush()
            audit.log(db, actor_type="admin", actor_id=admin.id, action="admin.recovery_code_used",
                      target_type="admin", target_id=admin.id,
                      metadata={"remaining": len(admin.recovery_codes)}, ip=ip, now=now)
    if method is None:
        return _fail(db, username=admin.username, ip=ip, step="totp", admin=admin, now=now)
    new_session, raw = _complete_login(db, admin, ip=ip, now=now, old_session_id=session.id, method=method)
    return LoginOutcome("ok", admin, new_session, raw, "done")


def complete_enrollment(db: Session, *, session: AdminSession, admin: AdminUser, code: str, ip: str,
                        now: datetime | None = None) -> LoginOutcome:
    """Verify the first TOTP code, enable TOTP and issue the recovery codes (shown once).

    A pending session is swapped for a full one; an already complete session is kept.
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
    db.flush()
    audit.log(db, actor_type="admin", actor_id=admin.id, action="admin.totp_enrolled", target_type="admin",
              target_id=admin.id, ip=ip, now=now)
    if session.totp_verified:
        return LoginOutcome("ok", admin, session, None, "done", codes)
    new_session, raw = _complete_login(db, admin, ip=ip, now=now, old_session_id=session.id, method="totp_enrollment")
    return LoginOutcome("ok", admin, new_session, raw, "done", codes)


def logout(db: Session, session: AdminSession, admin: AdminUser, *, ip: str | None = None,
           now: datetime | None = None) -> None:
    revoke_session(db, session.id, now)
    audit.log(db, actor_type="admin", actor_id=admin.id, action="admin.logout", target_type="admin",
              target_id=admin.id, ip=ip, now=_now(now))


# ----- password change / session revocation by the admin themselves -----------------------------
def change_password(db: Session, *, session: AdminSession, admin: AdminUser, current_password: str,
                    new_password: str, ip: str, now: datetime | None = None) -> bool:
    """Change the own password; revokes all *other* sessions. False if the current password is wrong
    (counted as a login failure). Raises `InvalidInput` for a weak new password, `RateLimited` never
    (the caller checks `change_password_limited` first)."""
    now = _now(now)
    admin = _attached(db, admin)
    if not verify_password(admin.password_hash, current_password):
        _fail(db, username=admin.username, ip=ip, step="password_change", admin=admin, now=now)
        return False
    admin.password_hash = hash_password(new_password)
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
