"""Scope checks for admin actors (PROMPT §6 "Authorization").

Global admins may access everything. Chair admins may access only users whose *current*
chair is one of their assigned chairs. Inactive admins may access nothing.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AdminChair, AdminUser, User
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
    rows = db.scalars(select(AdminChair.chair_id).where(AdminChair.admin_id == admin.id))
    return set(rows)


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
