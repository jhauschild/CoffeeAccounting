"""Group-admin roles: promote a member, demote, list role holders, sponsor search (task 4.3).

A group admin is an `admin_users` row with role `chair` linked to a member account (`user_id`). It has no
password of its own (the account password is used), its login name mirrors the account username, and its
scope is the member's own chair (`authz.visible_chair_ids`). Several group admins per chair are allowed.

Promotion needs an ACTIVE, VERIFIED MEMBER (guests are refused). Demotion sets `active = False`, revokes every
admin session of that admin and KEEPS the row, `role = 'chair'` and the user link: group balance history
(collected / remitted) hangs on the row, and a former group admin who still holds money stays listed by
`groups.list_group_balances`. Re-promotion re-activates the same row. Only the head admin (a global admin)
may do any of this, never to themselves. Role changes are not balance-changing, so no step-up applies.

Services never commit; the caller owns the transaction.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AdminUser, User
from app.services import admin_auth, audit, groups, registration
from app.services.authz import require_global
from app.services.errors import Conflict, Forbidden, InvalidInput, NotFound, UserInactive
from app.services.users import _escape_like, _fold, _fold_sql, normalize_name
from app.timeutil import ensure_utc, utcnow

SPONSOR_SEARCH_LIMIT = 30


def _now(now: datetime | None) -> datetime:
    return ensure_utc(now) if now is not None else utcnow()


def _group_admin_row(db: Session, user_id: uuid.UUID) -> AdminUser | None:
    return db.scalars(select(AdminUser).where(AdminUser.user_id == user_id)).first()


def _usable_member(user: User | None) -> User:
    """Member account that may hold the role: a member (`Forbidden`, reason not_member, for a guest or legacy
    profile), active and verified (`UserInactive` otherwise)."""
    user = registration.ensure_member(user)
    if user.status != "active" or user.verified_at is None:
        raise UserInactive("only an active, verified member can be a group admin")
    return user


def _check_username_free(db: Session, user: User, own_row: AdminUser | None) -> None:
    other = admin_auth.get_by_username(db, user.username)
    if other is not None and (own_row is None or other.id != own_row.id):
        raise Conflict("an administrator with this username already exists", reason="username_taken")


def promote_group_admin(db: Session, *, head_admin: AdminUser, user_id: uuid.UUID, ip: str | None = None,
                        now: datetime | None = None) -> AdminUser:
    """Make an active verified member a group admin (head admin only, never oneself).

    Creates the admin row (role `chair`, linked to the user, no password hash, username = the account's) or
    re-activates the existing row of a former group admin. `Forbidden` for a guest (reason ``not_member``), a
    non-head admin or oneself (reason ``self``); `UserInactive` for an inactive/unverified/merged member;
    `NotFound` for an unknown user; `Conflict` if the member already is an active group admin or the login
    name is taken by a CLI admin. Audited as `admin.group_admin_promoted` (target: the user)."""
    require_global(head_admin)
    if head_admin.user_id is not None and head_admin.user_id == user_id:
        raise Forbidden("the head admin cannot change their own role", reason="self")
    user = db.get(User, user_id)
    if user is None:
        raise NotFound("user not found")
    user = _usable_member(user)
    now = _now(now)
    row = _group_admin_row(db, user.id)
    reactivated = row is not None
    if row is not None:
        if row.role != "chair":
            raise InvalidInput("this account is linked to a head admin", field="user")
        if row.active:
            raise Conflict("already a group admin", reason="already_group_admin")
        if row.username_normalized != user.username_normalized:  # keep the mirror of the account username
            _check_username_free(db, user, row)
            row.username, row.username_normalized = user.username, user.username_normalized
        row.active = True
    else:
        _check_username_free(db, user, None)
        row = AdminUser(username=user.username, username_normalized=user.username_normalized, password_hash=None,
                        role="chair", user_id=user.id, active=True, recovery_codes=[], created_at=now)
        db.add(row)
    db.flush()
    audit.log(db, actor_type="admin", actor_id=head_admin.id, action="admin.group_admin_promoted",
              target_type="user", target_id=user.id,
              metadata={"admin_id": str(row.id), "chair_id": str(user.chair_id), "reactivated": reactivated},
              ip=ip, now=now)
    return row


def active_global_count(db: Session) -> int:
    return int(db.scalar(select(func.count()).select_from(AdminUser)
                         .where(AdminUser.role == "global", AdminUser.active.is_(True))))


def demote_group_admin(db: Session, *, head_admin: AdminUser, user_id: uuid.UUID, ip: str | None = None,
                       now: datetime | None = None) -> int:
    """Remove the group-admin role of a member (head admin only, never oneself).

    The row stays (`active = False`, role `chair` and user link kept) and all of its admin sessions are
    revoked. Returns the amount the person still holds (`groups.held`, cents) so the page can warn; it stays
    visible under group balances. `NotFound` if the user is not a group admin, `Conflict` if the role was
    already removed, `Forbidden` (reason ``self``) for oneself or (reason ``last_global_admin``) if the row
    is the last active head admin; an account linked to another head admin row is `InvalidInput`.
    Audited as `admin.group_admin_demoted` (target: the user)."""
    require_global(head_admin)
    if head_admin.user_id is not None and head_admin.user_id == user_id:
        raise Forbidden("the head admin cannot change their own role", reason="self")
    row = _group_admin_row(db, user_id)
    if row is None:
        raise NotFound("this person is not a group admin")
    if row.id == head_admin.id:
        raise Forbidden("the head admin cannot change their own role", reason="self")
    if row.role == "global":
        if row.active and active_global_count(db) <= 1:
            raise Forbidden("the last head admin cannot be removed", reason="last_global_admin")
        raise InvalidInput("this account is linked to a head admin", field="user")
    if not row.active:
        raise Conflict("the group admin role was already removed", reason="already_removed")
    now = _now(now)
    row.active = False
    revoked = admin_auth.revoke_admin_sessions(db, row.id, now=now)
    db.flush()
    held = groups.held(db, row.id)
    audit.log(db, actor_type="admin", actor_id=head_admin.id, action="admin.group_admin_demoted",
              target_type="user", target_id=user_id,
              metadata={"admin_id": str(row.id), "sessions_revoked": revoked, "held_cents": held}, ip=ip, now=now)
    return held


# ----- read models -------------------------------------------------------------------------------
@dataclass(frozen=True)
class RoleInfo:
    """What the user detail page needs about roles and sponsorship (head admin view)."""

    kind: str                     # "member" | "guest" | "other"
    is_group_admin: bool          # active role
    former: bool                  # role removed (row kept)
    held_cents: int               # group money held by this person's admin row (0 without a row)
    can_promote: bool
    sponsor: User | None = None   # guests only


def role_info(db: Session, user: User) -> RoleInfo:
    if user.account_kind == "guest":
        sponsor = db.get(User, user.sponsor_id) if user.sponsor_id else None
        return RoleInfo("guest", False, False, 0, False, sponsor=sponsor)
    if user.account_kind != "member":
        return RoleInfo("other", False, False, 0, False)
    row = _group_admin_row(db, user.id)
    usable = user.status == "active" and user.verified_at is not None
    if row is None or row.role != "chair":
        return RoleInfo("member", False, False, 0, usable)
    held = groups.held(db, row.id)
    return RoleInfo("member", bool(row.active), not row.active, held, usable and not row.active)


@dataclass(frozen=True)
class GroupAdminRow:
    admin_id: uuid.UUID
    user_id: uuid.UUID
    display_name: str
    username: str
    chair_short_name: str
    chair_full_name: str
    active: bool
    held_cents: int
    negative: bool


@dataclass(frozen=True)
class HeadAdminRow:
    admin_id: uuid.UUID
    username: str
    active: bool
    totp_enabled: bool


@dataclass(frozen=True)
class RoleHolders:
    head_admins: list[HeadAdminRow]
    group_admins: list[GroupAdminRow]


def list_role_holders(db: Session, head_admin: AdminUser) -> RoleHolders:
    """Head admins (CLI) and group admins, current and former (head admin only)."""
    require_global(head_admin)
    heads = [HeadAdminRow(a.id, a.username, bool(a.active), bool(a.totp_enabled))
             for a in db.scalars(select(AdminUser).where(AdminUser.role == "global")
                                 .order_by(AdminUser.username_normalized))]
    rows: list[GroupAdminRow] = []
    for a in db.scalars(select(AdminUser).where(AdminUser.role == "chair")):
        u = a.user
        held = groups.held(db, a.id)
        rows.append(GroupAdminRow(a.id, a.user_id, u.display_name if u else a.username, u.username if u else a.username,
                                  u.chair.short_name if u else "", u.chair.full_name if u else "",
                                  bool(a.active), held, held < 0))
    rows.sort(key=lambda r: (not r.active, r.chair_short_name.casefold(), r.display_name.casefold()))
    return RoleHolders(heads, rows)


def sponsor_candidates(db: Session, head_admin: AdminUser, q: str | None, *, exclude: uuid.UUID | None = None,
                       limit: int = SPONSOR_SEARCH_LIMIT) -> list[User]:
    """Active verified members whose display name contains `q` (accent/case-insensitive), for the
    "change sponsor" search (head admin only)."""
    require_global(head_admin)
    needle = _fold(normalize_name(q or ""))[:120]
    if not needle:
        return []
    stmt = select(User).where(User.account_kind == "member", User.status == "active",
                              User.verified_at.is_not(None), User.email.is_not(None),
                              _fold_sql(User.normalized_name).like(f"%{_escape_like(needle)}%", escape="\\"))
    if exclude is not None:
        stmt = stmt.where(User.id != exclude)
    return list(db.scalars(stmt.order_by(User.normalized_name).limit(limit)))
