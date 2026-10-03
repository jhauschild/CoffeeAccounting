"""Database engine and session helpers.

* `get_engine()` returns the process-wide engine for `Settings.database_url`.
  For SQLite every new DBAPI connection gets `journal_mode=WAL`, `foreign_keys=ON`,
  `busy_timeout` and `synchronous=NORMAL`, and pysqlite's implicit transaction
  handling is disabled so that SQLAlchemy emits `BEGIN` itself.
* `write_session()` opens a transaction with `BEGIN IMMEDIATE` (write lock taken up
  front), commits on success and rolls back on exception.
* `read_session()` opens a plain (deferred) transaction and always rolls back.

Services never commit; callers own the transaction (see docs/ARCHITECTURE.md).
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from app.config import get_settings

BUSY_TIMEOUT_MS = 5000
_BEGIN_OPTION = "coffee_sqlite_begin"

_engine: Engine | None = None
_engine_lock = threading.Lock()


def make_engine(url: str, **kwargs) -> Engine:
    """Create an engine; SQLite engines get the pragmas and BEGIN handling described above."""
    sa_url = make_url(url)
    if sa_url.get_backend_name() != "sqlite":
        return create_engine(url, pool_pre_ping=True, **kwargs)

    connect_args = kwargs.pop("connect_args", {})
    connect_args.setdefault("check_same_thread", False)
    connect_args.setdefault("timeout", BUSY_TIMEOUT_MS / 1000)
    engine = create_engine(url, connect_args=connect_args, **kwargs)
    in_memory = sa_url.database in (None, "", ":memory:")

    @event.listens_for(engine, "connect")
    def _on_connect(dbapi_conn, _record):  # pragma: no branch - trivial
        # Let SQLAlchemy control transactions (pysqlite's implicit BEGIN is unreliable).
        dbapi_conn.isolation_level = None
        cur = dbapi_conn.cursor()
        if not in_memory:
            cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.close()

    @event.listens_for(engine, "begin")
    def _on_begin(conn):
        mode = conn.get_execution_options().get(_BEGIN_OPTION)
        conn.exec_driver_sql("BEGIN IMMEDIATE" if mode == "immediate" else "BEGIN")

    return engine


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = make_engine(get_settings().database_url)
    return _engine


def reset_engine() -> None:
    """Dispose the cached engine (tests, or after changing DATABASE_URL)."""
    global _engine
    with _engine_lock:
        if _engine is not None:
            _engine.dispose()
        _engine = None


@contextmanager
def write_session(engine: Engine | None = None) -> Iterator[Session]:
    """Yield a Session inside a write transaction (`BEGIN IMMEDIATE` on SQLite).

    Commits when the block exits normally, rolls back on exception.
    """
    eng = (engine or get_engine()).execution_options(**{_BEGIN_OPTION: "immediate"})
    with Session(eng, expire_on_commit=False) as session:
        with session.begin():
            session.connection()  # take the write lock now, before any read
            yield session


@contextmanager
def read_session(engine: Engine | None = None) -> Iterator[Session]:
    """Yield a Session for reads; the transaction is always rolled back."""
    with Session(engine or get_engine(), expire_on_commit=False) as session:
        try:
            yield session
        finally:
            session.rollback()
