"""Scope checks for admin actors (PROMPT §6 "Authorization").

Global (head) admins may access everything. Chair (group) admins may access only users whose
*current* chair is the chair of the member account linked to them (v2: no `admin_chairs`).
Inactive admins may access nothing.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AdminUser, User
from app.services.errors import Forbidden, NotFound


def require_active(admin: AdminUser | None) -> AdminUser:
    if admin is None or not admin.active:
        raise Forbidden("admin account is not active")
    return admin


def is_global(admin: AdminUser | None) -> bool:
    return admin is not None and admin.active and admin.role == "global"


def require_global(admin: AdminUser | None) -> AdminUser:
    require_active(admin)
    if admin.role != "global":
        raise Forbidden("global administrator required")
    return admin


def visible_chair_ids(db: Session, admin: AdminUser) -> set[uuid.UUID] | None:
    """Chair ids the admin may see; `None` means all chairs (global admin)."""
    require_active(admin)
    if admin.role == "global":
        return None
    # v2: a group admin sees exactly the chair of the linked user account, read from the database
    # (not from a cached relationship) so a chair change takes effect immediately.
    if admin.user_id is None:
        return set()
    chair_id = db.scalar(select(User.chair_id).where(User.id == admin.user_id))
    return {chair_id} if chair_id is not None else set()


def ensure_admin_can_access_chair(db: Session, admin: AdminUser, chair_id: uuid.UUID) -> None:
    visible = visible_chair_ids(db, admin)
    if visible is not None and chair_id not in visible:
        raise Forbidden("chair outside the administrator's scope")


def ensure_admin_can_access_user(db: Session, admin: AdminUser, user_id: uuid.UUID) -> None:
    """Raise `NotFound` if the user does not exist, `Forbidden` if out of scope."""
    require_active(admin)
    user = db.get(User, user_id)
    if user is None:
        raise NotFound("user not found")
    ensure_admin_can_access_chair(db, admin, user.chair_id)
