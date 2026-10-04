"""Read-only view data for the head admin's group balance page (owner: admin agent)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AdminUser, Chair, GroupRemittance


@dataclass(frozen=True)
class RemittanceRow:
    id: uuid.UUID
    created_at: datetime
    group_admin_name: str
    chair_short: str
    amount_cents: int
    note: str | None
    recorded_by: str
    is_correction: bool
    corrected: bool

    @property
    def can_correct(self) -> bool:
        return not self.is_correction and not self.corrected


def remittance_rows(db: Session, limit: int = 500) -> list[RemittanceRow]:
    """Remittance entries, newest first, with the group admin's name (linked member) and chair at event time."""
    entries = list(db.scalars(select(GroupRemittance).order_by(GroupRemittance.created_at.desc(),
                                                              GroupRemittance.id).limit(limit)))
    if not entries:
        return []
    admin_ids = {e.group_admin_id for e in entries} | {e.recorded_by_admin_id for e in entries}
    admins = {a.id: a for a in db.scalars(select(AdminUser).where(AdminUser.id.in_(admin_ids)))}
    chairs = {c.id: c.short_name for c in db.scalars(select(Chair))}
    corrected = {e.correction_of_id for e in entries if e.correction_of_id}

    def name(admin_id) -> str:
        a = admins.get(admin_id)
        if a is None:
            return "?"
        return a.user.display_name if a.user is not None else a.username

    return [RemittanceRow(
        id=e.id, created_at=e.created_at, group_admin_name=name(e.group_admin_id),
        chair_short=chairs.get(e.chair_id, "?"), amount_cents=e.amount_cents, note=e.note,
        recorded_by=admins[e.recorded_by_admin_id].username if e.recorded_by_admin_id in admins else "?",
        is_correction=e.correction_of_id is not None, corrected=e.id in corrected) for e in entries]
