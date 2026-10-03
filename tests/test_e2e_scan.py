"""End-to-end browser test (Playwright, headless Chromium): scan -> auto-submit -> access code ->
registration -> success -> refresh -> second scan without any prompt (PROMPT §12).

Skipped with an explicit reason if Playwright or the browser cannot be started."""

from __future__ import annotations

import os
import socket
import threading
import time
from pathlib import Path

import pytest
from sqlalchemy import select

from app import db as app_db
from app.main import create_app
from app.models import ConsumptionEvent, PendingAction, User
from tests import factories
from tests.conftest import TEST_ENV, reload_settings

os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", "/opt/pw-browsers")

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright is not installed")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def live_server(monkeypatch, db_url):
    import uvicorn

    port = _free_port()
    monkeypatch.setenv("PUBLIC_BASE_URL", f"http://127.0.0.1:{port}")
    reload_settings()
    server = uvicorn.Server(uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started, "uvicorn did not start"
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=10)


def _installed_chromium() -> list[str]:
    root = Path(os.environ["PLAYWRIGHT_BROWSERS_PATH"])
    found = sorted(root.glob("chromium_headless_shell-*/chrome-linux/headless_shell"))
    found += sorted(root.glob("chromium-*/chrome-linux/chrome"))
    return [str(p) for p in found]


@pytest.fixture
def browser():
    with sync_api.sync_playwright() as p:
        b, error = None, None
        for exe in [None, *_installed_chromium()]:  # Playwright's own revision first, then what is installed
            try:
                b = p.chromium.launch(executable_path=exe, args=["--no-sandbox"])
                break
            except Exception as exc:  # noqa: BLE001
                error = exc
        if b is None:
            pytest.skip(f"headless Chromium cannot be launched here: {str(error).splitlines()[0][:150]}")
        yield b
        b.close()


def test_scan_register_refresh_scan_again(live_server, browser, db, engine):
    chair = factories.make_chair(db, short_name="E2E", full_name="End to End Chair")
    factories.set_price(db, 50)
    page = browser.new_context().new_page()

    # 1. First scan: no session -> auto-submit -> /join asks for the access code.
    page.goto(f"{live_server}/coffee/double")
    page.wait_for_url("**/join")
    assert "will be recorded" in page.content()

    # 2. Access code -> choice page -> registration form.
    page.fill("#code", TEST_ENV["ACCESS_CODE"])
    page.click("button[type=submit]")
    page.wait_for_selector("a[href='/register']")
    page.click("a[href='/register']")
    page.fill("#display_name", "Erika E2E")
    page.select_option("#chair_id", str(chair.id))
    page.check("#privacy_ack")
    page.click("button[type=submit]")

    # 3. Success page for the pending double.
    page.wait_for_url("**/coffee/done/*")
    assert "Double recorded" in page.content() and "€1.00" in page.content()
    done_url = page.url

    # 4. Refresh does not record anything new.
    page.reload()
    assert page.url == done_url and "Double recorded" in page.content()

    # 5. A second scan has no prompt at all: scan -> auto-submit -> success.
    page.goto(f"{live_server}/coffee/single")
    page.wait_for_url("**/coffee/done/*")
    assert page.url != done_url and "Single recorded" in page.content()

    with engine.connect() as conn:
        events = conn.execute(select(ConsumptionEvent.type, ConsumptionEvent.quantity, ConsumptionEvent.amount_cents)
                              .order_by(ConsumptionEvent.created_at)).all()
        assert [tuple(e) for e in events] == [("double", 2, 100), ("single", 1, 50)]
        assert conn.execute(select(User.id)).all().__len__() == 1
        assert conn.execute(select(PendingAction.consumed_at)).scalar_one() is not None
