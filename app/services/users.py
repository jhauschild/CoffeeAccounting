"""User profiles: names, search, profile edits, status changes, merges, effective users."""

from __future__ import annotations

import unicodedata
import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import Select, func, select, update
from sqlalchemy.orm import Session

from app.models import DISPLAY_NAME_MAX, AdminUser, Chair, User, UserSession, effective_users
from app.services import audit
from app.services.authz import ensure_admin_can_access_user, require_global
from app.services.errors import Conflict, Forbidden, InvalidInput, NotFound, UserInactive
from app.timeutil import utcnow

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
def create_user(db: Session, *, display_name: str, chair_id: uuid.UUID, now: datetime | None = None) -> User:
    name = clean_display_name(display_name)
    _active_chair(db, chair_id)
    now = now or utcnow()
    user = User(display_name=name, normalized_name=normalize_name(name), chair_id=chair_id, status="active",
                created_at=now, last_activity_at=now)
    db.add(user)
    db.flush()
    return user


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
    only global admins may change a chair). Every chair change is audited."""
    user = get_user(db, user_id)
    if user.status == "merged":
        raise Conflict("profile has been merged")
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


def set_user_status(db: Session, *, admin: AdminUser, user_id: uuid.UUID, active: bool, ip: str | None = None) -> User:
    """Deactivate/reactivate (scope-checked). Sessions of inactive users stop resolving immediately."""
    ensure_admin_can_access_user(db, admin, user_id)
    user = get_user(db, user_id)
    if user.status == "merged":
        raise Conflict("profile has been merged")
    new_status = "active" if active else "inactive"
    if user.status != new_status:
        user.status = new_status
        db.flush()
        audit.log(db, actor_type="admin", actor_id=admin.id,
                  action="user.reactivated" if active else "user.deactivated",
                  target_type="user", target_id=user.id, ip=ip)
    return user


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
    # Temporary until sessions.revoke_user_sessions (core-b) exists; same semantics.
    revoked = db.execute(
        update(UserSession)
        .where(UserSession.user_id == duplicate.id, UserSession.revoked_at.is_(None))
        .values(revoked_at=now)
    ).rowcount
    db.flush()
    audit.log(db, actor_type="admin", actor_id=admin.id, action="user.merged", target_type="user",
              target_id=duplicate.id,
              metadata={"merged_into_id": str(target.id), "repointed_ids": [str(i) for i in repointed],
                        "sessions_revoked": revoked},
              ip=ip, now=now)
    return target
