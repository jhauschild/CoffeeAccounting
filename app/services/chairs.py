"""Chairs (coffee groups). Never deleted; only global admins (or the CLI, admin=None) manage them."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import CHAIR_FULL_NAME_MAX, CHAIR_SHORT_NAME_MAX, AdminUser, Chair
from app.services import audit
from app.services.authz import require_global
from app.services.errors import Conflict, InvalidInput, NotFound
from app.timeutil import utcnow


def _clean(value: str, max_len: int, what: str) -> str:
    value = " ".join((value or "").split())
    if not value:
        raise InvalidInput(f"{what} is required")
    if len(value) > max_len:
        raise InvalidInput(f"{what} longer than {max_len} characters")
    if any(ord(c) < 32 for c in value):
        raise InvalidInput(f"{what} contains control characters")
    return value


def _check_admin(admin: AdminUser | None) -> None:
    if admin is not None:
        require_global(admin)


def _ensure_short_name_free(db: Session, short_name: str, exclude_id: uuid.UUID | None = None) -> None:
    q = select(Chair.id).where(func.lower(Chair.short_name) == short_name.lower())
    if exclude_id is not None:
        q = q.where(Chair.id != exclude_id)
    if db.scalar(q) is not None:
        raise Conflict("a chair with this short name already exists")


def get_chair(db: Session, chair_id: uuid.UUID) -> Chair:
    chair = db.get(Chair, chair_id)
    if chair is None:
        raise NotFound("chair not found")
    return chair


def get_chair_by_short_name(db: Session, short_name: str) -> Chair | None:
    return db.scalars(select(Chair).where(func.lower(Chair.short_name) == short_name.strip().lower())).first()


def list_chairs(db: Session, *, active_only: bool = False) -> list[Chair]:
    q = select(Chair).order_by(Chair.short_name)
    if active_only:
        q = q.where(Chair.active.is_(True))
    return list(db.scalars(q))


def create_chair(
    db: Session, *, admin: AdminUser | None, full_name: str, short_name: str, ip: str | None = None,
    now: datetime | None = None,
) -> Chair:
    _check_admin(admin)
    full_name = _clean(full_name, CHAIR_FULL_NAME_MAX, "full name")
    short_name = _clean(short_name, CHAIR_SHORT_NAME_MAX, "short name")
    _ensure_short_name_free(db, short_name)
    now = now or utcnow()
    chair = Chair(full_name=full_name, short_name=short_name, active=True, created_at=now)
    db.add(chair)
    db.flush()
    actor_type, actor_id = audit.admin_actor(admin)
    audit.log(db, actor_type=actor_type, actor_id=actor_id, action="chair.created", target_type="chair",
              target_id=chair.id, metadata={"full_name": full_name, "short_name": short_name}, ip=ip, now=now)
    return chair


def rename_chair(
    db: Session, *, admin: AdminUser | None, chair_id: uuid.UUID, full_name: str | None = None,
    short_name: str | None = None, ip: str | None = None,
) -> Chair:
    _check_admin(admin)
    chair = get_chair(db, chair_id)
    changes: dict[str, list[str]] = {}
    if full_name is not None:
        full_name = _clean(full_name, CHAIR_FULL_NAME_MAX, "full name")
        if full_name != chair.full_name:
            changes["full_name"] = [chair.full_name, full_name]
            chair.full_name = full_name
    if short_name is not None:
        short_name = _clean(short_name, CHAIR_SHORT_NAME_MAX, "short name")
        if short_name != chair.short_name:
            _ensure_short_name_free(db, short_name, exclude_id=chair.id)
            changes["short_name"] = [chair.short_name, short_name]
            chair.short_name = short_name
    if changes:
        db.flush()
        actor_type, actor_id = audit.admin_actor(admin)
        audit.log(db, actor_type=actor_type, actor_id=actor_id, action="chair.renamed", target_type="chair",
                  target_id=chair.id, metadata=changes, ip=ip)
    return chair


def set_chair_active(
    db: Session, *, admin: AdminUser | None, chair_id: uuid.UUID, active: bool, ip: str | None = None
) -> Chair:
    _check_admin(admin)
    chair = get_chair(db, chair_id)
    if chair.active != active:
        chair.active = active
        db.flush()
        actor_type, actor_id = audit.admin_actor(admin)
        audit.log(db, actor_type=actor_type, actor_id=actor_id,
                  action="chair.reactivated" if active else "chair.deactivated",
                  target_type="chair", target_id=chair.id, ip=ip)
    return chair
