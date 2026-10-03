"""Engine pragmas, transaction helpers, and Alembic migrations (up/down/up, check)."""

import sqlite3

import pytest
from alembic import command
from sqlalchemy import func, inspect, select, text

from app.db import make_engine, read_session, write_session
from app.models import Chair
from tests.conftest import alembic_config


def test_sqlite_pragmas_on_every_connection(engine):
    with engine.connect() as conn:
        assert conn.exec_driver_sql("PRAGMA journal_mode").scalar() == "wal"
        assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
        assert conn.exec_driver_sql("PRAGMA busy_timeout").scalar() == 5000


def test_write_session_takes_write_lock_up_front(db_path, engine):
    with write_session():
        other = sqlite3.connect(db_path, timeout=0, isolation_level=None)
        try:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                other.execute("BEGIN IMMEDIATE")
        finally:
            other.close()


def test_write_session_commits_and_rolls_back(engine):
    with write_session() as s:
        s.add(Chair(full_name="Kept", short_name="K"))
    with pytest.raises(RuntimeError):
        with write_session() as s:
            s.add(Chair(full_name="Dropped", short_name="D"))
            s.flush()
            raise RuntimeError("boom")
    with read_session() as s:
        assert s.scalars(select(Chair.short_name)).all() == ["K"]
        s.add(Chair(full_name="Never", short_name="N"))
        s.flush()
    with read_session() as s:
        assert s.scalar(select(func.count()).select_from(Chair)) == 1


def test_timestamps_round_trip_as_aware_utc(db, chair):
    db.expire_all()
    loaded = db.get(Chair, chair.id)
    assert loaded.created_at.tzinfo is not None and loaded.created_at.utcoffset().total_seconds() == 0


def test_migrations_up_down_up_and_check(tmp_path):
    url = f"sqlite:///{tmp_path / 'mig.db'}"
    cfg = alembic_config(url)
    command.upgrade(cfg, "head")
    eng = make_engine(url)
    try:
        insp = inspect(eng)
        tables = set(insp.get_table_names())
        assert {"chairs", "users", "prices", "consumption_events", "payment_events", "user_sessions",
                "pending_actions", "admin_users", "admin_chairs", "admin_sessions", "rate_limit_events",
                "audit_log"} <= tables
        assert "effective_users" in insp.get_view_names()
        with eng.connect() as conn:
            triggers = conn.execute(text("SELECT name FROM sqlite_master WHERE type='trigger'")).scalars().all()
        assert {"audit_log_no_update", "audit_log_no_delete"} <= set(triggers)
        command.check(cfg)  # raises if models and migrations differ

        command.downgrade(cfg, "base")
        insp = inspect(eng)
        assert set(insp.get_table_names()) == {"alembic_version"} and insp.get_view_names() == []

        command.upgrade(cfg, "head")
        command.check(cfg)
    finally:
        eng.dispose()
