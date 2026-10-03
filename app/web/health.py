"""`/healthz` (process up) and `/readyz` (database reachable and migrated to the Alembic head)."""

from __future__ import annotations

import logging
from functools import lru_cache

from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.db import get_engine
from app.web.templating import ROOT

router = APIRouter()
log = logging.getLogger(__name__)


@lru_cache
def expected_heads() -> frozenset[str]:
    return frozenset(ScriptDirectory.from_config(Config(str(ROOT / "alembic.ini"))).get_heads())


def readiness() -> tuple[bool, str]:
    try:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
            current = frozenset(MigrationContext.configure(conn).get_current_heads())
    except Exception:  # noqa: BLE001 - any failure means "not ready"; details only in the log
        log.warning("readiness check: database unreachable", exc_info=True)
        return False, "database"
    if current != expected_heads():
        return False, "migrations"
    return True, "ok"


@router.get("/healthz", include_in_schema=False)
def healthz() -> JSONResponse:
    return JSONResponse({"status": "ok"})


@router.get("/readyz", include_in_schema=False)
def readyz() -> JSONResponse:
    ok, reason = readiness()
    return JSONResponse({"status": "ok" if ok else "unavailable", "check": reason}, status_code=200 if ok else 503)
