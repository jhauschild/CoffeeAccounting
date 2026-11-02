"""Shared pieces of the browser (Playwright, headless Chromium) end-to-end tests (task 7.1).

Test modules import the fixtures by name::

    from tests.e2e_support import browser, live, new_page  # noqa: F401

Fixtures
--------
browser (module)   One headless Chromium per test module. Skips the module with an explicit reason when
                   Playwright or the browser cannot be started.
live (function)    A running app (uvicorn on a free port, in a thread) on a fresh Alembic-migrated SQLite
                   database. Development environment, cheap Argon2 (tests/conftest.py), MAIL_BACKEND=file
                   with MAIL_FILE_DIR in a temp directory, BALANCE_TOTP_REQUIRED=true. Seeded: one chair
                   ("E2E"), a price of 50 cents and a head administrator with TOTP enrolled.
new_page           `new_page()` -> a Page in a NEW browser context (own cookies: "another browser").

Helpers: `Mailbox` (reads the `.eml` files), `Live.make_member/make_guest`, `Live.session()` (read-only DB
access for assertions), `totp_now`, `sign_in`.
"""

from __future__ import annotations

import os
import re
import socket
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from email import message_from_bytes, policy
from email.utils import getaddresses
from pathlib import Path
from urllib.parse import urlsplit

import pytest

# Use a shared browser dir only when the caller already set one, or when /opt/pw-browsers
# exists (local/container convention). Do not force that path: CI's `playwright install`
# writes to the default cache, and pointing elsewhere makes every e2e test skip.
if "PLAYWRIGHT_BROWSERS_PATH" not in os.environ and Path("/opt/pw-browsers").is_dir():
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = "/opt/pw-browsers"

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright is not installed")
pyotp = pytest.importorskip("pyotp", reason="pyotp is not installed")
from sqlalchemy import select  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app import db as app_db  # noqa: E402
from app.db import write_session  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import User  # noqa: E402
from app.services import admin_auth  # noqa: E402
from tests import factories  # noqa: E402
from tests.conftest import reload_settings  # noqa: E402
from tests.user_support import PASSWORD  # noqa: E402

ADMIN_USERNAME = "boss"
ADMIN_PASSWORD = "head admin passphrase 1"
PAGE_TIMEOUT_MS = 10_000
MAIL_TIMEOUT_S = 10.0


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def totp_now(secret: str) -> str:
    return pyotp.TOTP(secret.replace(" ", "")).now()


# ----- mail files --------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Mail:
    name: str
    to: tuple[str, ...]
    subject: str
    body: str

    def link(self, path_prefix: str) -> str:
        """The first URL in the body whose path starts with `path_prefix` (e.g. "/verify/")."""
        for url in re.findall(r"https?://[^\s<>\"']+", self.body):
            if urlsplit(url).path.startswith(path_prefix):
                return url
        raise AssertionError(f"no {path_prefix} link in mail {self.subject!r}:\n{self.body}")


class Mailbox:
    """The `.eml` files the file mail backend wrote (one per message; names sort by send time)."""

    def __init__(self, directory: Path):
        self.directory = directory

    def messages(self, to: str | None = None) -> list[Mail]:
        out: list[Mail] = []
        for path in sorted(self.directory.glob("*.eml")):
            msg = message_from_bytes(path.read_bytes(), policy=policy.default)
            recipients = tuple(addr.lower() for _, addr in getaddresses(msg.get_all("To", [])))
            if to is not None and to.lower() not in recipients:
                continue
            part = msg.get_body(preferencelist=("plain",))
            out.append(Mail(path.name, recipients, str(msg["Subject"] or ""), part.get_content() if part else ""))
        return out

    def count(self, to: str | None = None) -> int:
        return len(self.messages(to))

    def wait_new(self, to: str, since: int, timeout: float = MAIL_TIMEOUT_S) -> Mail:
        """The newest mail for `to` once there are more than `since` of them (the app sends in the background,
        after the response). Polls the directory; no fixed sleep."""
        deadline = time.monotonic() + timeout
        while True:
            found = self.messages(to)
            if len(found) > since:
                return found[-1]
            if time.monotonic() > deadline:
                raise AssertionError(f"no new mail for {to} within {timeout:.0f} s ({len(found)} present)")
            time.sleep(0.02)


# ----- the live app ------------------------------------------------------------------------------------------------
@dataclass
class Live:
    base: str
    mail: Mailbox
    chair_id: object
    chair_name: str
    admin_secret: str
    admin_username: str = ADMIN_USERNAME
    admin_password: str = ADMIN_PASSWORD
    _extra: dict = field(default_factory=dict)

    def url(self, path: str) -> str:
        return f"{self.base}{path}"

    @contextmanager
    def session(self):
        """A read session on the live database, for assertions."""
        s = Session(app_db.get_engine(), expire_on_commit=False)
        try:
            yield s
        finally:
            s.rollback()
            s.close()

    def count(self, model) -> int:
        from sqlalchemy import func
        with self.session() as s:
            return s.scalar(select(func.count()).select_from(model))

    def user(self, username: str) -> User | None:
        with self.session() as s:
            found = s.scalar(select(User).where(User.username_normalized == username.casefold()))
            if found is not None:
                s.expunge(found)  # keep the loaded columns usable after the session ends
            return found

    def make_chair(self, short_name: str, full_name: str | None = None):
        with write_session() as w:
            return factories.make_chair(w, short_name=short_name, full_name=full_name or f"{short_name} Chair",
                                        commit=False)

    def make_member(self, name: str, username: str, *, chair_id=None, password: str = PASSWORD) -> User:
        """A verified member with a real (cheap) Argon2 hash, e-mail `<username>@tum.de`."""
        from app.models import Chair
        with write_session() as w:
            return _member(w, name, w.get(Chair, chair_id or self.chair_id), username, password)

    def make_guest(self, sponsor: User, name: str, username: str, *, password: str = PASSWORD) -> User:
        from app.services.passwords import hash_password
        with write_session() as w:
            return factories.make_guest(w, w.get(User, sponsor.id), name, username=username,
                                        password_hash=hash_password(password), commit=False)

    def add_coffees(self, user: User, kinds=("single",)) -> None:
        with write_session() as w:
            factories.add_events(w, w.get(User, user.id), list(kinds), commit=False)


def _member(w, name, chair, username, password) -> User:
    from app.services.passwords import hash_password
    return factories.make_member(w, name, chair, username=username, password_hash=hash_password(password),
                                 commit=False)


@pytest.fixture
def live(monkeypatch, tmp_path, db_url):
    """See the module docstring. (`db_url` comes from tests/conftest.py: a migrated copy of the template DB.)"""
    import uvicorn

    mail_dir = tmp_path / "mail"
    port = free_port()
    monkeypatch.setenv("PUBLIC_BASE_URL", f"http://127.0.0.1:{port}")
    monkeypatch.setenv("MAIL_BACKEND", "file")
    monkeypatch.setenv("MAIL_FILE_DIR", str(mail_dir))
    monkeypatch.setenv("BALANCE_TOTP_REQUIRED", "true")
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path / "secrets"))
    reload_settings()

    with write_session() as w:
        chair = factories.make_chair(w, short_name="E2E", full_name="End to End Chair", commit=False)
        factories.set_price(w, 50, commit=False)
        admin = admin_auth.create_admin(w, username=ADMIN_USERNAME, password=ADMIN_PASSWORD, role="global")
        secret = admin_auth.begin_enrollment(w, admin)  # the service path the enrolment page uses
        admin.totp_enabled = True
        w.flush()
        chair_id, chair_name = chair.id, chair.short_name

    server = uvicorn.Server(uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started, "uvicorn did not start"
    try:
        yield Live(base=f"http://127.0.0.1:{port}", mail=Mailbox(mail_dir), chair_id=chair_id,
                   chair_name=chair_name, admin_secret=secret)
    finally:
        server.should_exit = True
        thread.join(timeout=10)


# ----- the browser -------------------------------------------------------------------------------------------------
def _browsers_root() -> Path:
    """Directory where `playwright install` places browsers (env override or Playwright default)."""
    override = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if override and override != "0":
        return Path(override)
    return Path.home() / ".cache" / "ms-playwright"


def _installed_chromium() -> list[str]:
    root = _browsers_root()
    if not root.is_dir():
        return []
    found = sorted(root.glob("chromium_headless_shell-*/chrome-linux/headless_shell"))
    found += sorted(root.glob("chromium-*/chrome-linux/chrome"))
    return [str(p) for p in found]


@pytest.fixture(scope="module")
def browser():
    """One headless Chromium for the module. The module is skipped, with the reason, if it cannot start."""
    try:
        pw = sync_api.sync_playwright().start()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Playwright cannot be started here: {str(exc).splitlines()[0][:150]}")
    b, error = None, None
    try:
        for exe in [None, *_installed_chromium()]:  # Playwright's own revision first, then what is installed
            try:
                b = pw.chromium.launch(executable_path=exe, args=["--no-sandbox"])
                break
            except Exception as exc:  # noqa: BLE001
                error = exc
        if b is None:
            pytest.skip(f"headless Chromium cannot be launched here: {str(error).splitlines()[0][:150]}")
        yield b
    finally:
        if b is not None:
            b.close()
        pw.stop()


@pytest.fixture
def new_page(browser):
    """`new_page()` opens a page in a fresh browser context (separate cookies = another browser)."""
    contexts = []

    def _new():
        context = browser.new_context()
        context.set_default_timeout(PAGE_TIMEOUT_MS)
        context.set_default_navigation_timeout(PAGE_TIMEOUT_MS)
        contexts.append(context)
        return context.new_page()

    yield _new
    for context in contexts:
        context.close()


# ----- page helpers ------------------------------------------------------------------------------------------------
def sign_in(page, live: Live, username: str, password: str = PASSWORD, *, expect: str | None = "**/account") -> None:
    """The member sign-in form at /login. `expect` is the URL pattern to wait for (None: do not wait)."""
    page.goto(live.url("/login"))
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("form[action='/login'] button[type=submit]")
    if expect:
        page.wait_for_url(expect)


def admin_sign_in(page, live: Live, username: str, password: str, *, expect: str = "**/admin") -> None:
    page.goto(live.url("/admin/login"))
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("form[action='/admin/login'] button[type=submit]")
    page.wait_for_url(expect)


def register_member(page, live: Live, *, username: str, name: str, email: str, password: str = PASSWORD) -> None:
    """Fill and submit the member registration form at /register (waits for the neutral "check your mail" page)."""
    page.goto(live.url("/register"))
    page.fill("form[action='/register'] #username", username)
    page.fill("form[action='/register'] #display_name", name)
    page.select_option("#chair_id", value=str(live.chair_id))
    page.fill("#email", email)
    page.fill("form[action='/register'] #password", password)
    page.fill("form[action='/register'] #password2", password)
    page.check("#privacy_ack")
    page.click("form[action='/register'] button[type=submit]")
    page.wait_for_selector("form[action='/register']", state="detached")


def dd_for(page, label: str):
    """The text of the <dd> that follows the <dt> with this label."""
    return page.locator(f"dt:text-is('{label}') + dd").first.inner_text().strip()
