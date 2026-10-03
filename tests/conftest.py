"""Shared pytest fixtures (core-a). Names are stable; other agents rely on them.

Every test runs against its own temp-file SQLite database created by Alembic (a migrated
template file is built once per session and copied per test; never `:memory:`, never
`create_all`).

Fixtures
--------
settings_env (autouse)  Development settings via environment variables; DATABASE_URL points
                        at the per-test DB. Clears `get_settings` cache and resets the
                        `app.db` engine before and after each test. Tests may
                        `monkeypatch.setenv(...)` then call `reload_settings()`.
db_path / db_url        Path / SQLAlchemy URL of the per-test database file.
engine                  `app.db.get_engine()` for that database.
db                      An ORM `Session` on the engine (ordinary deferred transaction).
                        Factories commit by default so other connections (threads, the
                        web app) see their rows.
chair, other_chair      Two active chairs.
user                    Active user in `chair`.
global_admin            Active global admin.
chair_admin             Active chair admin assigned to `chair` only.
price                   A price of 50 cents per shot, effective since one day ago.

Helpers: `reload_settings()` (below) and the factories in `tests/factories.py`.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

from app import db as app_db
from app.config import get_settings
from tests import factories

ROOT = Path(__file__).resolve().parent.parent

TEST_ENV = {
    "ENVIRONMENT": "development",
    "PUBLIC_BASE_URL": "http://testserver",
    "SECRET_KEY": "test-secret-key-0123456789abcdef0123456789",
    "ACCESS_CODE": "test-access-code",
    "LOCAL_TIMEZONE": "Europe/Berlin",
    "UNDO_WINDOW_SECONDS": "300",
    "MAX_COFFEES_PER_SESSION_PER_HOUR": "30",
    "ADMIN_TOTP_REQUIRED": "true",
    "CURRENCY": "EUR",
    "CSV_DELIMITER": ";",
    "CSV_DECIMAL_SEPARATOR": ",",
    "TRUSTED_PROXY_IPS": "",
    # Cheap Argon2 parameters for the test suite only (production defaults live in app/config.py).
    "ARGON2_TIME_COST": "1",
    "ARGON2_MEMORY_COST_KIB": "8",
    "ARGON2_PARALLELISM": "1",
}


def alembic_config(url: str) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.attributes["url"] = url
    cfg.attributes["configure_logger"] = False
    return cfg


def reload_settings() -> None:
    """Re-read settings from the environment and drop the cached engine."""
    get_settings.cache_clear()
    app_db.reset_engine()


@pytest.fixture(scope="session")
def _template_db(tmp_path_factory) -> Path:
    path = tmp_path_factory.mktemp("template") / "template.db"
    command.upgrade(alembic_config(f"sqlite:///{path}"), "head")
    return path


@pytest.fixture
def db_path(tmp_path, _template_db) -> Path:
    path = tmp_path / "test.db"
    shutil.copyfile(_template_db, path)
    return path


@pytest.fixture
def db_url(db_path) -> str:
    return f"sqlite:///{db_path}"


@pytest.fixture(autouse=True)
def settings_env(monkeypatch, db_url):
    for key, value in TEST_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("DATABASE_URL", db_url)
    reload_settings()
    yield get_settings()
    reload_settings()


@pytest.fixture
def engine(db_url, settings_env):
    return app_db.get_engine()


@pytest.fixture
def db(engine):
    from sqlalchemy.orm import Session

    session = Session(engine, expire_on_commit=False)
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def chair(db):
    return factories.make_chair(db, short_name="CHA", full_name="Chair A")


@pytest.fixture
def other_chair(db):
    return factories.make_chair(db, short_name="CHB", full_name="Chair B")


@pytest.fixture
def user(db, chair):
    return factories.make_user(db, display_name="Alice Example", chair=chair)


@pytest.fixture
def global_admin(db):
    return factories.make_admin(db, role="global")


@pytest.fixture
def chair_admin(db, chair):
    return factories.make_admin(db, role="chair", chairs=[chair])


@pytest.fixture
def price(db):
    return factories.set_price(db, 50)


# ----- core-b (platform) fixtures ---------------------------------------------------------------
@pytest.fixture
def app(settings_env):
    """A fresh FastAPI app built with the per-test settings."""
    from app.main import create_app

    return create_app()


@pytest.fixture
def client(app):
    """TestClient (base URL http://testserver = PUBLIC_BASE_URL); server errors become 500 pages."""
    from fastapi.testclient import TestClient

    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture
def login(client, db):
    """`login(user)` gives `client` a valid `coffee_session` cookie for `user`; returns the raw token."""
    from app.db import write_session
    from app.services.sessions import SESSION_COOKIE, issue_session

    def _login(user) -> str:
        with write_session() as w:
            raw = issue_session(w, user.id)
        client.cookies.set(SESSION_COOKIE, raw)
        return raw

    return _login


@pytest.fixture
def gate_cookie(client):
    """Give `client` a valid `coffee_gate` cookie (access gate passed)."""
    from app.services.gate import GATE_COOKIE, make_gate_cookie

    value = make_gate_cookie()
    client.cookies.set(GATE_COOKIE, value)
    return value
