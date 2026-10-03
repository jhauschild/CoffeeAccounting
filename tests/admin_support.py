"""Shared helpers for the admin tests (owner: admin agent).

Import the fixtures into a test module with
`from tests.admin_support import fast_hasher  # noqa: F401`.
"""

from __future__ import annotations

import pyotp
import pytest
from argon2 import PasswordHasher

from app.db import write_session
from app.services import admin_auth
from app.timeutil import utcnow

PASSWORD = "correct horse battery"
NEW_PASSWORD = "another long passphrase"


@pytest.fixture(autouse=True)
def fast_hasher(monkeypatch):
    """Cheap Argon2id parameters so the tests stay fast (production uses the library defaults)."""
    monkeypatch.setattr(admin_auth, "_hasher", PasswordHasher(time_cost=1, memory_cost=8, parallelism=1))
    monkeypatch.setattr(admin_auth, "_dummy_hash", None)


def make_real_admin(role="global", chairs=(), username="boss", password=PASSWORD, totp=True):
    """Create an admin with a real password hash (and enabled TOTP). Returns (admin_id, secret|None)."""
    with write_session() as w:
        admin = admin_auth.create_admin(w, username=username, password=password, role=role, chairs=chairs)
        secret = None
        if totp:
            secret = admin_auth.begin_enrollment(w, admin)
            admin.totp_enabled = True
        w.flush()
        return admin.id, secret


def current_code(secret: str, offset_steps: int = 0) -> str:
    return pyotp.TOTP(secret).at(utcnow().timestamp() + 30 * offset_steps)


# ----- web helpers ------------------------------------------------------------------------------
import re  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

from app.models import AdminSession  # noqa: E402
from app.services.admin_auth import ADMIN_COOKIE  # noqa: E402
from app.web import tokens  # noqa: E402

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


def login_as(client: TestClient, admin_id) -> str:
    """Give `client` a complete admin session (no password/TOTP round trip); returns its CSRF token."""
    from app.models import AdminUser
    with write_session() as w:
        admin = w.get(AdminUser, admin_id)
        session, raw = admin_auth._new_session(w, admin, verified=True, now=utcnow())
        csrf = tokens.csrf_token("admin", session.csrf_secret)
    client.cookies.set(ADMIN_COOKIE, raw, path="/admin")
    return csrf


def new_client(app) -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


def page_csrf(client: TestClient, path: str) -> str:
    html = client.get(path).text
    m = CSRF_RE.search(html)
    assert m, f"no csrf token on {path}"
    return m.group(1)
