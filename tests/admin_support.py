"""Shared helpers for the admin tests (owner: admin agent).

Import the fixtures into a test module with
`from tests.admin_support import fast_hasher  # noqa: F401`.
"""

from __future__ import annotations

import pyotp
import pytest

from app.db import write_session
from app.models import AdminUser
from app.services import admin_auth, passwords
from app.timeutil import utcnow

PASSWORD = "correct horse battery"
NEW_PASSWORD = "another long passphrase"


@pytest.fixture(autouse=True)
def fast_hasher():
    """Kept for the tests that import it: the cheap Argon2 parameters now come from the ARGON2_* test
    settings (tests/conftest.py), which `app.services.passwords` reads for every hash."""
    return None


def make_real_admin(role="global", chairs=(), username="boss", password=PASSWORD, totp=True):
    """Create an admin with a real password hash (and enabled TOTP). Returns (admin_id, secret|None).

    role "global": a CLI admin (own hash). role "chair": a group admin, i.e. a verified member in
    chairs[0] (or a new chair) whose ACCOUNT password is `password`; the admin signs in with the
    member's username `member-<username>`.
    """
    from tests import factories
    with write_session() as w:
        if role == "chair":
            admin = factories.make_admin(w, role="chair", chairs=chairs, username=username, commit=False)
            admin.user.password_hash = passwords.hash_password(password)
            admin.password_hash = None
        else:
            admin = admin_auth.create_admin(w, username=username, password=password, role=role)
        secret = None
        if totp:
            secret = admin_auth.begin_enrollment(w, admin)
            admin.totp_enabled = True
        w.flush()
        return admin.id, secret


def login_name(admin_id) -> str:
    """The identifier to type at /admin/login for this admin (account username for a group admin)."""
    with write_session() as w:
        admin = w.get(AdminUser, admin_id)
        return admin.user.username if admin.user_id else admin.username


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
        session, raw = admin_auth._new_session(w, admin, now=utcnow())
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


# ----- step-up (two-step balance changes) ---------------------------------------------------------
BALANCE_PATH = re.compile(r"^/admin/users/[^/]+/(payment|adjustment|merge|balance|events/[^/]+/reverse)$"
                          r"|^/admin/groups/remittances(/[^/]+/correct)?$")
CONFIRM_PATH = "/admin/stepup/confirm"


def confirm_fields(html: str) -> dict:
    """The hidden fields (csrf_token, payload, nonce) of the confirm form on a confirm page."""
    out = {}
    for name in ("csrf_token", "payload", "nonce"):
        m = re.search(rf'name="{name}" value="([^"]*)"', html)
        assert m, f"confirm page has no {name} field"
        out[name] = m.group(1)
    return out


def confirm(client: TestClient, html: str, *, code: str | None = None, **override):
    """POST the confirm form found in `html` (optionally with a code / overridden fields)."""
    data = confirm_fields(html)
    if code is not None:
        data["code"] = code
    data.update(override)
    return client.post(CONFIRM_PATH, data=data, follow_redirects=False)


def submit(client: TestClient, csrf: str, path: str, data: dict | None = None, *, code: str | None = None):
    """POST an admin form. A balance-changing action (payment, adjustment, reversal, merge) goes through
    both steps: entry form -> confirm page -> confirm POST; the final response is returned (an entry-step
    error redirect is returned as it is)."""
    r = client.post(path, data={"csrf_token": csrf, **(data or {})}, follow_redirects=False)
    if BALANCE_PATH.match(path) and r.status_code == 200 and f'action="{CONFIRM_PATH}"' in r.text:
        r = confirm(client, r.text, code=code)
    return r
