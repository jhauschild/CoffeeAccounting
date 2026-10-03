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
