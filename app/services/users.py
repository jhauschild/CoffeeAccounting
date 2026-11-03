"""User profiles: names, search, profile edits, status changes, merges, effective users."""

from __future__ import annotations

import unicodedata
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import Select, delete, func, select, update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import (
    DISPLAY_NAME_MAX,
    AdminUser,
    AnonymizationCounter,
    Chair,
    User,
    UserIdentityRestore,
    UserSession,
    effective_users,
)
from app.services import admin_auth, audit, sessions
from app.services.authz import ensure_admin_can_access_user, require_global
from app.services.errors import Conflict, Forbidden, InvalidInput, NotFound, UserInactive
from app.timeutil import ensure_utc, utcnow

ACTOR_USER = "user"
ACTOR_ADMIN = "admin"

_UMLAUTS = str.maketrans({"ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss",
                          # letters whose diacritic does not decompose under NFKD
                          "ł": "l", "ø": "o", "đ": "d", "ı": "i", "æ": "ae", "œ": "oe"})
_FOLD = (("ae", "a"), ("oe", "o"), ("ue", "u"))


@dataclass(frozen=True)
class PublicProfile:
    """What profile lists may show: name and chair only."""

    id: uuid.UUID
    display_name: str
    chair_id: uuid.UUID
    chair_short_name: str
    chair_full_name: str


# ----- names --------------------------------------------------------------------------------
def normalize_name(s: str) -> str:
    """Casefold, transliterate German umlauts (ä→ae, ö→oe, ü→ue, ß→ss), strip other
    diacritics, collapse whitespace. Applied to stored names and to search queries."""
    s = unicodedata.normalize("NFC", s or "").casefold().translate(_UMLAUTS)
    s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))
    return " ".join(s.split())


def _fold(s: str) -> str:
    """Search-only folding so that "muller" and "mueller" both find "Müller" (stored "mueller")."""
    for a, b in _FOLD:
        s = s.replace(a, b)
    return s


def _fold_sql(col):
    for a, b in _FOLD:
        col = func.replace(col, a, b)
    return col


def _escape_like(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def clean_display_name(name: str) -> str:
    name = " ".join(unicodedata.normalize("NFC", name or "").split())
    if not name:
        raise InvalidInput("display name is required")
    if len(name) > DISPLAY_NAME_MAX:
        raise InvalidInput(f"display name longer than {DISPLAY_NAME_MAX} characters")
    if any(unicodedata.category(c) in ("Cc", "Cf", "Co", "Cs") for c in name):
        raise InvalidInput("display name contains invalid characters")
    return name


# ----- effective users ----------------------------------------------------------------------
def effective_user_id(db: Session, user_id: uuid.UUID) -> uuid.UUID | None:
    """The id this user's events count for (follows merges); None if unknown/cyclic."""
    return db.scalar(select(effective_users.c.effective_id).where(effective_users.c.id == user_id))


def member_ids_select(effective_id: uuid.UUID) -> Select:
    """SELECT of all user ids whose events count for `effective_id` (itself + merged profiles)."""
    return select(effective_users.c.id).where(effective_users.c.effective_id == effective_id)


def get_user(db: Session, user_id: uuid.UUID) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise NotFound("user not found")
    return user


def _active_chair(db: Session, chair_id: uuid.UUID) -> Chair:
    chair = db.get(Chair, chair_id) if chair_id is not None else None
    if chair is None or not chair.active:
        raise InvalidInput("unknown or inactive chair")
    return chair


def _profile(user: User) -> PublicProfile:
    return PublicProfile(user.id, user.display_name, user.chair_id, user.chair.short_name, user.chair.full_name)


# ----- queries ------------------------------------------------------------------------------
def search_profiles(db: Session, query: str | None, limit: int = 50) -> list[PublicProfile]:
    """Active profiles whose normalized name contains the normalized query (empty: all)."""
    q = select(User).join(User.chair).where(User.status == "active")
    needle = _fold(normalize_name(query or ""))[:DISPLAY_NAME_MAX * 2]
    if needle:
        q = q.where(_fold_sql(User.normalized_name).like(f"%{_escape_like(needle)}%", escape="\\"))
    q = q.order_by(User.normalized_name, Chair.short_name).limit(max(1, min(limit, 200)))
    return [_profile(u) for u in db.scalars(q)]


def find_same_name(db: Session, *, display_name: str, chair_id: uuid.UUID) -> list[PublicProfile]:
    """Active profiles in `chair_id` whose normalized name equals that of `display_name`."""
    q = select(User).where(
        User.status == "active", User.chair_id == chair_id, User.normalized_name == normalize_name(display_name)
    )
    return [_profile(u) for u in db.scalars(q)]


# ----- mutations ----------------------------------------------------------------------------
def create_user(db: Session, *, display_name: str, chair_id: uuid.UUID, now: datetime | None = None,
                user_id: uuid.UUID | None = None) -> User:
    name = clean_display_name(display_name)
    _active_chair(db, chair_id)
    now = now or utcnow()
    user = User(display_name=name, normalized_name=normalize_name(name), chair_id=chair_id, status="active",
                created_at=now, last_activity_at=now)
    if user_id is not None:
        user.id = user_id
    db.add(user)
    db.flush()
    return user


def create_account(db: Session, *, kind: str, username: str, username_normalized: str, display_name: str,
                   chair_id: uuid.UUID, password_hash: str, email: str | None = None,
                   sponsor_id: uuid.UUID | None = None, verified_at: datetime | None = None,
                   now: datetime | None = None) -> User:
    """Create a v2 account row (member: email, no sponsor; guest: sponsor, no email). The caller has
    validated username, email and password; the DB CHECKs and unique indexes are the last line.
    Raises `InvalidInput` for a bad display name or an unknown/inactive chair."""
    if kind not in ("member", "guest"):
        raise InvalidInput("invalid account kind")
    name = clean_display_name(display_name)
    _active_chair(db, chair_id)
    now = now or utcnow()
    user = User(display_name=name, normalized_name=normalize_name(name), chair_id=chair_id, status="active",
                created_at=now, last_activity_at=now, username=username, username_normalized=username_normalized,
                account_kind=kind, email=email, sponsor_id=sponsor_id, verified_at=verified_at or now,
                password_hash=password_hash)
    db.add(user)
    db.flush()
    return user


def _is_active_group_admin(db: Session, user_id: uuid.UUID) -> bool:
    return db.scalar(select(AdminUser.id).where(AdminUser.user_id == user_id, AdminUser.role == "chair",
                                                AdminUser.active.is_(True))) is not None


def update_profile(
    db: Session,
    *,
    user_id: uuid.UUID,
    display_name: str | None = None,
    chair_id: uuid.UUID | None = None,
    actor_type: str,
    actor_id: uuid.UUID | None = None,
    ip: str | None = None,
) -> User:
    """Edit name and/or chair. `actor_type` is "user" (the profile owner, already
    authenticated by the caller) or "admin" (`actor_id` = admin id; scope-checked, and
    only global admins may change a chair). Every chair change is audited.

    A user linked to an ACTIVE group admin row (role "chair") cannot change chair, whoever asks
    (`Forbidden`): the scope of a group admin derives from the chair of the linked account. A
    head admin may move the user after removing the role."""
    user = get_user(db, user_id)
    if user.status == "merged":
        raise Conflict("profile has been merged")
    if chair_id is not None and chair_id != user.chair_id and _is_active_group_admin(db, user.id):
        raise Forbidden("a group admin cannot change chair; remove the role first")
    if actor_type == ACTOR_ADMIN:
        admin = db.get(AdminUser, actor_id) if actor_id is not None else None
        if admin is None:
            raise Forbidden("unknown admin")
        ensure_admin_can_access_user(db, admin, user_id)
        if chair_id is not None and chair_id != user.chair_id:
            require_global(admin)
    elif actor_type == ACTOR_USER:
        if user.status != "active":
            raise UserInactive("profile is not active")
        actor_id = user.id
    else:
        raise ValueError(f"invalid actor_type {actor_type!r}")

    changes: dict[str, list[str]] = {}
    if display_name is not None:
        name = clean_display_name(display_name)
        if name != user.display_name:
            changes["display_name"] = [user.display_name, name]
            user.display_name = name
            user.normalized_name = normalize_name(name)
    old_chair_id = user.chair_id
    if chair_id is not None and chair_id != user.chair_id:
        _active_chair(db, chair_id)
        user.chair_id = chair_id
    db.flush()
    if user.chair_id != old_chair_id:
        db.expire(user, ["chair"])
        audit.log(db, actor_type=actor_type, actor_id=actor_id, action="user.chair_changed", target_type="user",
                  target_id=user.id, metadata={"from_chair_id": str(old_chair_id), "to_chair_id": str(chair_id)},
                  ip=ip)
    if changes and actor_type == ACTOR_ADMIN:
        audit.log(db, actor_type=actor_type, actor_id=actor_id, action="user.updated", target_type="user",
                  target_id=user.id, metadata=changes, ip=ip)
    return user


def get_identity_restore(db: Session, user_id: uuid.UUID, *, now: datetime | None = None) -> UserIdentityRestore | None:
    """Non-expired restore stash for `user_id`, or None."""
    now = ensure_utc(now) if now is not None else utcnow()
    return db.scalar(
        select(UserIdentityRestore).where(
            UserIdentityRestore.user_id == user_id, UserIdentityRestore.expires_at > now
        )
    )


def get_identity_restore_by_username(
    db: Session, username_normalized: str, *, now: datetime | None = None
) -> UserIdentityRestore | None:
    """Non-expired restore stash for an original login name, or None."""
    if not username_normalized:
        return None
    now = ensure_utc(now) if now is not None else utcnow()
    return db.scalar(
        select(UserIdentityRestore).where(
            UserIdentityRestore.username_normalized == username_normalized,
            UserIdentityRestore.expires_at > now,
        )
    )


def _next_alumni_index(db: Session) -> int:
    row = db.get(AnonymizationCounter, "alumni")
    if row is None:
        row = AnonymizationCounter(name="alumni", value=0)
        db.add(row)
        db.flush()
    row.value += 1
    db.flush()
    return int(row.value)


def _revoke_linked_admin_sessions(db: Session, user_id: uuid.UUID, now: datetime) -> int:
    revoked = 0
    for admin_id in db.scalars(select(AdminUser.id).where(AdminUser.user_id == user_id)).all():
        revoked += admin_auth.revoke_admin_sessions(db, admin_id, now=now)
    return revoked


def active_group_admins_for_chair(
    db: Session, chair_id: uuid.UUID, *, exclude_user_id: uuid.UUID | None = None
) -> list[tuple[AdminUser, User]]:
    """Active group admins whose linked member is in `chair_id` and has an email."""
    rows = db.execute(
        select(AdminUser, User)
        .join(User, User.id == AdminUser.user_id)
        .where(
            AdminUser.role == "chair",
            AdminUser.active.is_(True),
            User.chair_id == chair_id,
            User.email.is_not(None),
        )
        .order_by(User.normalized_name, User.id)
    ).all()
    out: list[tuple[AdminUser, User]] = []
    for admin, linked in rows:
        if exclude_user_id is not None and linked.id == exclude_user_id:
            continue
        out.append((admin, linked))
    return out


def _deactivate_notify_address(db: Session, user: User) -> str | None:
    """Member email, or guest sponsor email, for user-facing deactivation mails."""
    if user.email:
        return user.email
    if user.sponsor_id is not None:
        sponsor = db.get(User, user.sponsor_id)
        return sponsor.email if sponsor is not None else None
    return None


def _ga_contact_lines(gas: list[tuple[AdminUser, User]]) -> str:
    from app.strings import t

    if not gas:
        return t("mail.deactivate.contacts_none")
    return "\n".join(f"- {linked.display_name} <{linked.email}>" for _admin, linked in gas)


def _build_deactivate_mails(
    db: Session,
    *,
    user: User,
    reason: str,
    expires_at: datetime,
    has_login: bool,
) -> tuple[list, dict]:
    """Build mails using the pre-anonymize identity. Returns `(messages, audit_meta)`."""
    from app.money import format_money
    from app.services import ledger, mail_templates
    from app.services.mail import MailMessage, build_message
    from app.strings import t

    messages: list[MailMessage] = []
    meta: dict = {
        "balance_cents": 0,
        "balance_mails": {"deactivate": 0, "please_pay": 0, "has_credit": 0, "collect_owed": 0, "no_group_admin": 0},
        "balance_notify_head_skipped": False,
    }
    to_user = _deactivate_notify_address(db, user)
    if has_login and to_user:
        subject, body = mail_templates.account_deactivated(
            username=user.username or user.display_name, restore_until=expires_at, reason=reason
        )
        messages.append(build_message(to=to_user, subject=subject, body=body))
        meta["balance_mails"]["deactivate"] = 1

    balance = ledger.get_totals(db, user.id).balance_cents
    meta["balance_cents"] = balance
    if balance == 0:
        return messages, meta

    amount = format_money(abs(balance))
    gas = active_group_admins_for_chair(db, user.chair_id, exclude_user_id=user.id)
    contacts = _ga_contact_lines(gas)
    chair = db.get(Chair, user.chair_id)
    chair_name = chair.short_name if chair is not None else str(user.chair_id)
    admin_url = f"{get_settings().public_base_url.rstrip('/')}/admin/users/{user.id}"
    username = user.username or user.display_name

    if balance > 0 and to_user:
        subject, body = mail_templates.deactivate_please_pay(
            username=username, amount=amount, contacts=contacts
        )
        messages.append(build_message(to=to_user, subject=subject, body=body))
        meta["balance_mails"]["please_pay"] = 1
        for _admin, linked in gas:
            subject, body = mail_templates.deactivate_collect_owed(
                display_name=user.display_name,
                username=username,
                chair_name=chair_name,
                amount=amount,
                admin_url=admin_url,
            )
            messages.append(build_message(to=linked.email, subject=subject, body=body))
            meta["balance_mails"]["collect_owed"] += 1
    elif balance < 0 and to_user:
        subject, body = mail_templates.deactivate_has_credit(
            username=username, amount=amount, contacts=contacts
        )
        messages.append(build_message(to=to_user, subject=subject, body=body))
        meta["balance_mails"]["has_credit"] = 1

    if not gas:
        head_to = get_settings().head_admin_notify_email.strip()
        if head_to:
            kind = (
                t("mail.deactivate.balance_kind_owed")
                if balance > 0
                else t("mail.deactivate.balance_kind_credit")
            )
            subject, body = mail_templates.deactivate_no_group_admin(
                display_name=user.display_name,
                username=username,
                chair_name=chair_name,
                amount=amount,
                balance_kind=kind,
                admin_url=admin_url,
            )
            messages.append(build_message(to=head_to, subject=subject, body=body))
            meta["balance_mails"]["no_group_admin"] = 1
        else:
            meta["balance_notify_head_skipped"] = True

    return messages, meta


def anonymize_deactivate(
    db: Session,
    *,
    user: User,
    reason: str,
    actor_type: str,
    actor_id: uuid.UUID | None = None,
    ip: str | None = None,
    now: datetime | None = None,
    notify: bool = True,
) -> tuple[User, list]:
    """Anonymize display name / username / email, stash originals for restore, set inactive.

    Returns `(user, mail_messages)`. Callers send messages after commit (background or CLI).
    `chair_id` and `password_hash` are kept. Idempotent if already inactive with a live stash.
    """
    if reason not in ("self", "admin", "inactive"):
        raise InvalidInput("invalid deactivation reason")
    now = ensure_utc(now) if now is not None else utcnow()
    if user.status == "merged":
        raise Conflict("profile has been merged")

    existing = get_identity_restore(db, user.id, now=now)
    if user.status == "inactive" and existing is not None:
        return user, []
    if (
        user.status == "inactive"
        and existing is None
        and user.username_normalized
        and user.username_normalized.startswith("alumni-")
    ):
        return user, []  # already anonymized and restore window expired

    settings = get_settings()
    expires_at = now + timedelta(days=settings.identity_restore_days)
    has_login = bool(user.username and user.username_normalized)
    messages: list = []
    balance_meta: dict = {}
    if notify:
        messages, balance_meta = _build_deactivate_mails(
            db, user=user, reason=reason, expires_at=expires_at, has_login=has_login
        )

    if existing is not None:
        db.delete(existing)
        db.flush()

    if has_login:
        db.add(
            UserIdentityRestore(
                user_id=user.id,
                display_name=user.display_name,
                username=user.username,
                username_normalized=user.username_normalized,
                email=user.email,
                reason=reason,
                created_at=now,
                expires_at=expires_at,
            )
        )
        db.flush()

    n = _next_alumni_index(db)
    display = f"Alumni {n}"
    user.display_name = display
    user.normalized_name = normalize_name(display)
    if has_login:
        user.username = f"alumni-{n}"
        user.username_normalized = f"alumni-{n}"
        if user.account_kind == "member":
            user.email = f"anonymous-{n}@example.org"
    user.status = "inactive"
    db.flush()

    sessions_revoked = sessions.revoke_user_sessions(db, user.id, now)
    admin_revoked = _revoke_linked_admin_sessions(db, user.id, now)
    meta = {
        "anonymized": True,
        "reason": reason,
        "restore_until": expires_at.isoformat(),
        "sessions_revoked": sessions_revoked,
        "admin_sessions_revoked": admin_revoked,
    }
    if balance_meta:
        meta.update(balance_meta)
    audit.log(
        db,
        actor_type=actor_type,
        actor_id=actor_id,
        action="user.deactivated",
        target_type="user",
        target_id=user.id,
        metadata=meta,
        ip=ip,
        now=now,
    )
    return user, messages


def restore_identity(
    db: Session,
    *,
    user: User,
    actor_type: str,
    actor_id: uuid.UUID | None = None,
    ip: str | None = None,
    now: datetime | None = None,
) -> User:
    """Put back stashed name/username/email, set active, delete the stash. Raises `Conflict` if taken."""
    now = ensure_utc(now) if now is not None else utcnow()
    stash = get_identity_restore(db, user.id, now=now)
    if stash is None:
        raise NotFound("no identity restore available")

    clash_user = db.scalar(
        select(User.id).where(
            User.id != user.id,
            User.username_normalized == stash.username_normalized,
        )
    )
    if clash_user is not None:
        raise Conflict("username is already in use")
    if stash.email:
        clash_email = db.scalar(select(User.id).where(User.id != user.id, User.email == stash.email))
        if clash_email is not None:
            raise Conflict("email is already in use")

    user.display_name = stash.display_name
    user.normalized_name = normalize_name(stash.display_name)
    user.username = stash.username
    user.username_normalized = stash.username_normalized
    if user.account_kind == "member":
        user.email = stash.email
    user.status = "active"
    user.last_activity_at = now
    db.delete(stash)
    db.flush()
    audit.log(
        db,
        actor_type=actor_type,
        actor_id=actor_id,
        action="user.reactivated",
        target_type="user",
        target_id=user.id,
        metadata={"restored_identity": True},
        ip=ip,
        now=now,
    )
    return user


def set_user_status(
    db: Session,
    *,
    admin: AdminUser,
    user_id: uuid.UUID,
    active: bool,
    ip: str | None = None,
    now: datetime | None = None,
    notify: bool = True,
) -> tuple[User, list]:
    """Deactivate (anonymize) or reactivate (restore if possible). Returns `(user, mail_messages)`.

    Deactivating a user linked to an ACTIVE group admin row (role "chair") needs a head admin.
    """
    ensure_admin_can_access_user(db, admin, user_id)
    user = get_user(db, user_id)
    if user.status == "merged":
        raise Conflict("profile has been merged")
    now = ensure_utc(now) if now is not None else utcnow()
    if not active:
        if admin.role != "global" and _is_active_group_admin(db, user.id):
            raise Forbidden("only a head admin may deactivate a group admin's profile")
        return anonymize_deactivate(
            db,
            user=user,
            reason="admin",
            actor_type=ACTOR_ADMIN,
            actor_id=admin.id,
            ip=ip,
            now=now,
            notify=notify,
        )
    if get_identity_restore(db, user.id, now=now) is not None:
        return restore_identity(
            db, user=user, actor_type=ACTOR_ADMIN, actor_id=admin.id, ip=ip, now=now
        ), []
    if user.status != "active":
        user.status = "active"
        user.last_activity_at = now
        db.flush()
        audit.log(
            db,
            actor_type=ACTOR_ADMIN,
            actor_id=admin.id,
            action="user.reactivated",
            target_type="user",
            target_id=user.id,
            ip=ip,
            now=now,
        )
    return user, []


def self_deactivate(
    db: Session, *, user: User, ip: str | None = None, now: datetime | None = None
) -> tuple[User, list]:
    """Signed-in account deactivates itself (anonymizing). Group admins must be demoted first."""
    if _is_active_group_admin(db, user.id):
        raise Forbidden("a group admin cannot deactivate their own account; ask a head admin to remove the role first")
    return anonymize_deactivate(
        db, user=user, reason="self", actor_type=ACTOR_USER, actor_id=user.id, ip=ip, now=now, notify=True
    )


def list_inactive_due(db: Session, *, now: datetime | None = None) -> list[User]:
    """Active accounts with no activity for `INACTIVE_ACCOUNT_DAYS` (login or coffee)."""
    now = ensure_utc(now) if now is not None else utcnow()
    cutoff = now - timedelta(days=get_settings().inactive_account_days)
    activity = func.coalesce(User.last_activity_at, User.created_at)
    return list(
        db.scalars(
            select(User).where(
                User.status == "active",
                User.account_kind.in_(("member", "guest")),
                activity < cutoff,
            )
        ).all()
    )


def purge_expired_identity_restores(db: Session, *, now: datetime | None = None) -> int:
    now = ensure_utc(now) if now is not None else utcnow()
    return db.execute(delete(UserIdentityRestore).where(UserIdentityRestore.expires_at < now)).rowcount


def merge_users(
    db: Session, *, admin: AdminUser, duplicate_id: uuid.UUID, target_id: uuid.UUID, ip: str | None = None,
    now: datetime | None = None,
) -> User:
    """Merge `duplicate_id` into `target_id` (global admins only).

    No ledger event is modified or moved: totals follow `effective_users`. Profiles that
    were previously merged into the duplicate are re-pointed to the target, and all of the
    duplicate's sessions are revoked. Returns the target.
    """
    require_global(admin)
    if duplicate_id == target_id:
        raise InvalidInput("cannot merge a profile into itself")
    duplicate = get_user(db, duplicate_id)
    target = get_user(db, target_id)
    if duplicate.status == "merged" or target.status == "merged":
        raise Conflict("profile has already been merged")
    now = now or utcnow()
    repointed = list(db.scalars(select(User.id).where(User.merged_into_id == duplicate.id)))
    if repointed:
        db.execute(update(User).where(User.merged_into_id == duplicate.id).values(merged_into_id=target.id))
    duplicate.status = "merged"
    duplicate.merged_into_id = target.id
    revoked = sessions.revoke_user_sessions(db, duplicate.id, now)
    db.flush()
    audit.log(db, actor_type="admin", actor_id=admin.id, action="user.merged", target_type="user",
              target_id=duplicate.id,
              metadata={"merged_into_id": str(target.id), "repointed_ids": [str(i) for i in repointed],
                        "sessions_revoked": revoked},
              ip=ip, now=now)
    return target
