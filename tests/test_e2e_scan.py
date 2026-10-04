"""Browser e2e (Playwright, headless Chromium): the scan flows (PROMPT section 12, PLAN-v2 section 7).

* the original purpose: an anonymous scan keeps the coffee, /login, sign in, the pending coffee is recorded
  once, refresh creates nothing, the next scan has no prompt;
* a signed-in scan: success page ("Outstanding", "Shots this month"), refresh, rescan, undo;
* anonymous scan followed by registration: the coffee is recorded only when the verify link is opened in the
  SAME browser; in another browser it is dropped.

Skipped with an explicit reason if Playwright or the browser cannot be started (see tests/e2e_support.py)."""

from __future__ import annotations

import re

from sqlalchemy import func, select

from app.models import ConsumptionEvent, PendingAction, User
from tests.e2e_support import PASSWORD, browser, dd_for, live, new_page, register_member, sign_in  # noqa: F401


def _events(live):
    with live.session() as s:
        rows = s.execute(select(ConsumptionEvent.type, ConsumptionEvent.quantity, ConsumptionEvent.amount_cents,
                                ConsumptionEvent.reversal_of_id).order_by(ConsumptionEvent.created_at)).all()
    return [tuple(r) for r in rows]


def test_anonymous_scan_login_records_pending_coffee_then_rescan(live, new_page):
    """The old v1 test, migrated: scan without a session -> /login -> sign in -> success -> refresh -> rescan."""
    member = live.make_member("Erika E2E", "erika.e2e")
    page = new_page()

    page.goto(live.url("/coffee/double"))  # auto-submit: no session, so the coffee is kept and /login is shown
    page.wait_for_url("**/login")
    assert "will be recorded" in page.content()
    assert page.locator("a[href='/register']").count() == 1
    assert _events(live) == []

    page.fill("#username", member.username)
    page.fill("#password", PASSWORD)
    page.click("form[action='/login'] button[type=submit]")
    page.wait_for_url("**/coffee/done/*")
    assert "Double recorded" in page.content() and "€1.00" in page.content()
    done_url = page.url

    page.reload()
    assert page.url == done_url and "Double recorded" in page.content()
    assert _events(live) == [("double", 2, 100, None)]

    page.goto(live.url("/coffee/single"))  # no prompt at all: scan -> auto-submit -> success
    page.wait_for_url("**/coffee/done/*")
    assert page.url != done_url and "Single recorded" in page.content()

    assert _events(live) == [("double", 2, 100, None), ("single", 1, 50, None)]
    assert live.count(User) == 1
    with live.session() as s:
        assert s.execute(select(PendingAction.consumed_at)).scalar_one() is not None


def test_signed_in_scan_success_page_refresh_rescan_undo(live, new_page):
    member = live.make_member("Sam Scanner", "sam.scanner")
    page = new_page()
    sign_in(page, live, member.username)

    # First scan: auto-submit records one single; the success page speaks of what is outstanding.
    page.goto(live.url("/coffee/single"))
    page.wait_for_url("**/coffee/done/*")
    first_url = page.url
    assert "Single recorded" in page.content()
    assert page.locator(".headline").inner_text().strip() == "Outstanding: €0.50"
    assert dd_for(page, "Shots this month") == "1"
    assert len(_events(live)) == 1

    # Refresh (a GET of the success page) creates nothing.
    page.reload()
    assert page.url == first_url and dd_for(page, "Shots this month") == "1"
    assert len(_events(live)) == 1

    # Rescan: a second coffee, with no prompt in between (scan page -> success page only).
    page.goto(live.url("/coffee/single"))
    page.wait_for_url("**/coffee/done/*")
    assert page.url != first_url
    assert dd_for(page, "Shots this month") == "2"
    assert page.locator(".headline").inner_text().strip() == "Outstanding: €1.00"
    assert len(_events(live)) == 2

    # Undo the latest coffee.
    page.click("form[action^='/coffee/undo/'] button[type=submit]")
    page.wait_for_selector("form[action^='/coffee/undo/']", state="detached")
    assert "This coffee was undone" in page.content()
    assert dd_for(page, "Shots this month") == "1"
    assert page.locator(".headline").inner_text().strip() == "Outstanding: €0.50"
    events = _events(live)
    assert len(events) == 3 and events[2][3] is not None  # the reversal row; nothing was deleted


def _scan_then_register(page, live, username: str, email: str):
    page.goto(live.url("/coffee/single"))
    page.wait_for_url("**/login")
    page.click("a[href='/register']")
    page.wait_for_url("**/register")
    register_member(page, live, username=username, name="Nora Pending", email=email)


def test_pending_coffee_is_dropped_when_verified_in_another_browser(live, new_page):
    before = live.mail.count("nora@tum.de")
    first = new_page()
    _scan_then_register(first, live, "nora.pending", "nora@tum.de")
    mail = live.mail.wait_new("nora@tum.de", before)

    second = new_page()  # another browser: it never held the pending coffee
    second.goto(mail.link("/verify/"))
    assert second.locator("form[action^='/verify/'] button[type=submit]").count() == 1
    assert live.user("nora.pending") is None  # GET wrote nothing
    second.click("form[action^='/verify/'] button[type=submit]")
    second.wait_for_url(re.compile(r".*/account.*"))
    assert "Nora Pending" in second.content()

    assert live.user("nora.pending") is not None
    assert _events(live) == []  # the pending coffee was dropped, not transferred


def test_pending_coffee_is_recorded_when_verified_in_the_same_browser(live, new_page):
    before = live.mail.count("nora@tum.de")
    page = new_page()
    _scan_then_register(page, live, "nora.pending", "nora@tum.de")
    mail = live.mail.wait_new("nora@tum.de", before)
    assert _events(live) == []  # nothing is recorded while the address is unverified

    page.goto(mail.link("/verify/"))
    assert live.user("nora.pending") is None
    page.click("form[action^='/verify/'] button[type=submit]")
    page.wait_for_url("**/coffee/done/*")
    assert "Single recorded" in page.content()
    assert _events(live) == [("single", 1, 50, None)]
    page.reload()  # a refresh of the success page records nothing more
    assert len(_events(live)) == 1
    with live.session() as s:
        assert s.scalar(select(func.count()).select_from(ConsumptionEvent)) == 1
