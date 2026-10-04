"""Browser e2e (Playwright, headless Chromium): the open site and the administrator flows with step-up.

* open site: sign-in required, people list, search that folds accents, chairs page, no e-mail or username text;
* admin: head admin payment with a TOTP step-up (code once, then the window), role button, group admin sign-in
  with the ACCOUNT password and first-login TOTP enrolment, cash payment in the own chair, remittance on
  /admin/groups, and the open-site chairs page agreeing with the admin page on the held amount."""

from __future__ import annotations

import re

from sqlalchemy import func, select

from app.models import PaymentEvent
from tests.e2e_support import (PASSWORD, admin_sign_in, browser, dd_for, live, new_page, sign_in,  # noqa: F401
                               totp_now)

CONFIRM_FORM = "form[action='/admin/stepup/confirm']"


def _no_private_text(page, *forbidden: str) -> None:
    html = page.content().casefold()
    for text in forbidden:
        assert text.casefold() not in html, f"{text!r} must not appear on {page.url}"


# ----- the open site -----------------------------------------------------------------------------------------------
def test_open_site_requires_login_and_shows_people_without_private_data(live, new_page):
    erika = live.make_member("Erika Viewer", "erika.viewer")
    other_chair = live.make_chair("ZZ", "Zeta Chair")
    mueller = live.make_member("Jonas Müller", "jonas.mueller", chair_id=other_chair.id)
    live.add_coffees(mueller, ["single", "double"])
    page = new_page()

    # Anonymous: the site is not open to the world; sign-in brings the visitor to the overview.
    page.goto(live.url("/overview"))
    page.wait_for_url("**/login")
    page.fill("#username", erika.username)
    page.fill("#password", PASSWORD)
    page.click("form[action='/login'] button[type=submit]")
    page.wait_for_url("**/overview")
    forbidden = [u.email for u in (erika, mueller)] + [u.username for u in (erika, mueller)]
    _no_private_text(page, *forbidden)

    # People: display names and chairs, the accent-folding search.
    page.goto(live.url("/overview/people"))
    table = page.locator("table.people")
    assert table.locator("tr", has_text="Erika Viewer").locator("td").first.inner_text().strip() == live.chair_name
    assert table.locator("tr", has_text="Jonas Müller").locator("td").first.inner_text().strip() == "ZZ"
    _no_private_text(page, *forbidden)

    page.fill("#q", "muller")
    page.press("#q", "Enter")
    page.wait_for_url(re.compile(r".*[?&]q=muller.*"))
    assert table.locator("tbody tr").count() == 1
    assert "Jonas Müller" in table.inner_text() and "Erika Viewer" not in table.inner_text()
    _no_private_text(page, *forbidden)

    # The person page, chairs page and prices page.
    page.click("table.people a[href^='/overview/people/']")
    page.wait_for_url(re.compile(r".*/overview/people/[0-9a-f-]{36}$"))
    assert "Jonas Müller" in page.inner_text("h1")
    _no_private_text(page, *forbidden)

    page.goto(live.url("/overview/chairs"))
    cards = page.locator("section.chair")
    assert cards.count() == 2
    assert "Zeta Chair" in page.inner_text("main") or "ZZ" in page.inner_text("main")
    _no_private_text(page, *forbidden)
    page.goto(live.url("/overview/prices"))
    assert "€0.50" in page.content()
    _no_private_text(page, *forbidden)

    # Nobody else can read a page without signing in: a clean browser is sent to /login again.
    anon = new_page()
    anon.goto(live.url("/overview/people"))
    anon.wait_for_url("**/login")


# ----- administrators ----------------------------------------------------------------------------------------------
def _pay(page, live, user_id, amount: str, *, needs_code: bool, secret: str | None = None) -> None:
    """Entry form -> confirm page (TOTP code only when the step-up window is closed) -> confirm."""
    page.goto(live.url(f"/admin/users/{user_id}"))
    with live.session() as s:
        recorded = s.scalar(select(func.count()).select_from(PaymentEvent))
    page.fill("#pay_amount", amount)
    page.click("form[action$='/payment'] button[type=submit]")
    page.wait_for_selector(CONFIRM_FORM)
    with live.session() as s:  # the entry step only previews
        assert s.scalar(select(func.count()).select_from(PaymentEvent)) == recorded
    assert page.locator(f"{CONFIRM_FORM} #code").count() == (1 if needs_code else 0)
    if needs_code:
        page.fill(f"{CONFIRM_FORM} #code", totp_now(secret))
    page.click(f"{CONFIRM_FORM} button[type=submit]")
    page.wait_for_selector(CONFIRM_FORM, state="detached")
    assert "Payment recorded." in page.inner_text("main")


def _held(row) -> str:
    return row.locator("td.num").last.inner_text().strip()


def test_admin_payment_step_up_group_admin_and_group_balances(live, new_page):
    mia = live.make_member("Mia Member", "mia.member")
    ben = live.make_member("Ben Same-Chair", "ben.samechair")
    live.add_coffees(mia, ["single"] * 3)  # owes 1.50

    # --- head admin: payment with step-up -------------------------------------------------------------------------
    head = new_page()
    admin_sign_in(head, live, live.admin_username, live.admin_password)
    _pay(head, live, mia.id, "5.00", needs_code=True, secret=live.admin_secret)  # window closed: code asked once
    _pay(head, live, mia.id, "1.00", needs_code=False)  # inside the window: no code

    member_page = new_page()
    sign_in(member_page, live, mia.username)
    assert member_page.locator(".headline").inner_text().strip() == "Credit: €4.50"  # 1.50 owed, 6.00 paid

    # --- head admin makes the member a group admin ----------------------------------------------------------------
    head.goto(live.url(f"/admin/users/{mia.id}"))
    head.click("form[action$='/group-admin/promote'] button[type=submit]")
    head.wait_for_selector("form[action$='/group-admin/demote']")

    # --- the group admin signs in at /admin/login with the ACCOUNT username and password --------------------------
    group = new_page()
    group.goto(live.url("/admin/login"))
    group.fill("#username", mia.username)
    group.fill("#password", PASSWORD)
    group.click("form[action='/admin/login'] button[type=submit]")
    group.wait_for_url("**/admin/totp/setup")  # first login: enrol TOTP
    secret = group.locator("code.secret").inner_text()
    group.fill("#code", totp_now(secret))
    group.click("form[action='/admin/totp/setup'] button[type=submit]")
    group.wait_for_selector("ul.recovery-codes")  # shown once, after a correct first code
    group.click("a[href='/admin']")
    group.wait_for_url("**/admin")

    # Enrolling opened the step-up window, so the cash payment for a member of the own chair needs no code.
    _pay(group, live, ben.id, "3.00", needs_code=False)

    # --- head admin: money received from the group admin ------------------------------------------------------------
    head.goto(live.url("/admin/groups"))
    mia_row = head.locator("table").first.locator("tr", has_text="Mia Member")
    assert _held(mia_row) == "€3.00"
    head.select_option("#remit_admin", label=f"Mia Member ({live.chair_name})")
    head.fill("#remit_amount", "2.00")
    head.click("form[action='/admin/groups/remittances'] button[type=submit]")
    head.wait_for_selector(CONFIRM_FORM)
    assert dd_for(head, "Held by group now") == "€3.00"
    assert dd_for(head, "Held by group afterwards") == "€1.00"
    assert head.locator(f"{CONFIRM_FORM} #code").count() == 0  # window still open
    head.click(f"{CONFIRM_FORM} button[type=submit]")
    head.wait_for_url("**/admin/groups*")
    assert "Money received from the group admin recorded." in head.inner_text("main")
    admin_held = _held(head.locator("table").first.locator("tr", has_text="Mia Member"))
    assert admin_held == "€1.00"  # decreased from 3.00
    chair_row = head.locator("table").nth(1).locator("tr", has_text=live.chair_name)
    admin_chair_held = _held(chair_row)
    assert admin_chair_held == "€1.00"

    # --- the open site agrees with the admin page -------------------------------------------------------------------
    member_page.goto(live.url("/overview/chairs"))
    card = member_page.locator("section.chair", has=member_page.locator("h2", has_text=live.chair_name))
    assert card.locator(".chair-held").inner_text().strip() == admin_chair_held
    assert card.locator(".chair-collected").inner_text().strip() == "€3.00"
    assert card.locator(".chair-handed").inner_text().strip() == "€2.00"
    assert "Mia Member" in card.locator(".chair-admins").inner_text()
