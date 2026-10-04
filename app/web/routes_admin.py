"""All `/admin` routes (owner: admin agent). The sub-routers live in `admin_*.py`."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import APIRouter
from sqlalchemy.exc import OperationalError

from app.db import write_session
from app.services import admin_auth
from app.services.errors import ServiceError
from app.web import admin_groups, admin_login, admin_manage, admin_stepup, admin_users

log = logging.getLogger(__name__)


@asynccontextmanager
async def _lifespan(app):
    """First start: create the bootstrap administrator from ADMIN_BOOTSTRAP_* (ignored once any admin exists)."""
    try:
        with write_session() as db:
            admin = admin_auth.bootstrap_admin(db)
            if admin is not None:
                log.info("bootstrap administrator %r created", admin.username)
    except ServiceError as exc:  # e.g. password shorter than 12 characters; never log the password
        log.error("ADMIN_BOOTSTRAP_* ignored: %s", exc)
    except OperationalError:
        log.warning("bootstrap administrator skipped: database not ready (run the migrations)")
    yield


router = APIRouter(lifespan=_lifespan)
for _sub in (admin_login, admin_users, admin_groups, admin_stepup, admin_manage):
    router.include_router(_sub.router, prefix="/admin")
