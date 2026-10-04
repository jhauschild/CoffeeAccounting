"""Browser e2e (Playwright, headless Chromium): registration by QR code, guest with sponsor approval, password
recovery. Mail is read from the `.eml` files of the file backend (tests/e2e_support.py)."""

from __future__ import annotations

import re

from tests.e2e_support import PASSWORD, browser, dd_for, live, new_page, register_member, sign_in  # noqa: F401

NEW_PASSWORD = "brand new passphrase 42"


def test_register_member_by_mail_link(live, new_page):
    page = new_page()
    before = live.mail.count("nina@tum.de")
    register_member(page, live, username="nina.newbie", name="Nina Newbie", email="nina@tum.de")
    assert live.user("nina.newbie") is None  # nothing is created before the e-mail is verified

    mail = live.mail.wait_new("nina@tum.de", before)
    link = mail.link("/verify/")

    page.goto(link)  # GET shows what will be created and writes nothing
    assert dd_for(page, "Username") == "nina.newbie"
    assert dd_for(page, "Name") == "Nina Newbie"
    assert live.user("nina.newbie") is None

    page.click("form[action^='/verify/'] button[type=submit]")  # confirm
    page.wait_for_url(re.compile(r".*/account.*"))
    assert dd_for(page, "Display name") == "Nina Newbie"
    assert dd_for(page, "Chair") == live.chair_name
    created = live.user("nina.newbie")
    assert created is not None and created.account_kind == "member" and created.verified_at is not None

    # Signed in: the account page opens without a login, and the link cannot be used a second time.
    page.goto(live.url("/account"))
    assert page.url.endswith("/account")
    other = new_page()
    other.goto(link)
    assert other.locator("form[action^='/verify/']").count() == 0


def test_guest_registers_and_sponsor_approves_without_login(live, new_page):
    sponsor = live.make_member("Maria Sponsor", "maria.sponsor")
    before = live.mail.count(sponsor.email)

    guest_page = new_page()
    guest_page.goto(live.url("/register?kind=guest"))
    form = "form[action='/register/guest']"
    guest_page.fill(f"{form} #username", "gerda.guest")
    guest_page.fill(f"{form} #display_name", "Gerda Guest")
    guest_page.fill(f"{form} #password", PASSWORD)
    guest_page.fill(f"{form} #password2", PASSWORD)
    guest_page.fill(f"{form} #sponsor_email", sponsor.email)
    guest_page.check("#privacy_ack")
    guest_page.click(f"{form} button[type=submit]")
    guest_page.wait_for_selector(form, state="detached")

    # The sponsor's mail file holds the request (name, username and a link).
    mail = live.mail.wait_new(sponsor.email, before)
    assert "Gerda Guest" in mail.body and "gerda.guest" in mail.body
    link = mail.link("/verify/")

    # No account yet: the guest cannot sign in.
    sign_in(guest_page, live, "gerda.guest", expect=None)
    guest_page.wait_for_selector("[role=alert]")
    assert guest_page.url.endswith("/login")
    assert live.user("gerda.guest") is None

    # The sponsor opens the link in a clean browser (no login at all); GET writes nothing.
    sponsor_page = new_page()
    sponsor_page.goto(link)
    assert dd_for(sponsor_page, "Username") == "gerda.guest"
    assert sponsor_page.locator("button[value=approve]").count() == 1
    assert sponsor_page.locator("button[value=reject]").count() == 1
    assert live.user("gerda.guest") is None
    sponsor_page.click("button[value=approve]")
    sponsor_page.wait_for_selector("button[value=approve]", state="detached")
    assert "gerda.guest" in sponsor_page.content() and "can now sign in" in sponsor_page.content()
    assert "coffee_session" not in {c["name"] for c in sponsor_page.context.cookies()}  # no login for the sponsor

    # Now the guest signs in; the guest belongs to the sponsor's chair.
    sign_in(guest_page, live, "gerda.guest")
    assert dd_for(guest_page, "Display name") == "Gerda Guest"
    assert dd_for(guest_page, "Chair") == live.chair_name
    guest = live.user("gerda.guest")
    assert guest.account_kind == "guest" and guest.sponsor_id == sponsor.id and guest.email is None


def test_forgot_password_member_reset_logs_out_old_session(live, new_page):
    member = live.make_member("Rosa Reset", "rosa.reset")
    old_session = new_page()
    sign_in(old_session, live, member.username)

    page = new_page()
    before = live.mail.count(member.email)
    page.goto(live.url("/forgot"))
    page.fill("#username", member.username)  # by username, never by e-mail address
    page.click("form[action='/forgot'] button[type=submit]")
    page.wait_for_selector("form[action='/forgot']", state="detached")
    mail = live.mail.wait_new(member.email, before)
    assert mail.to == (member.email,)

    page.goto(mail.link("/reset/"))
    page.fill("#password", NEW_PASSWORD)
    page.fill("#password2", NEW_PASSWORD)
    page.click("form[action^='/reset/'] button[type=submit]")
    page.wait_for_url("**/login?notice=reset")

    # The old password is refused, the new one works.
    sign_in(page, live, member.username, PASSWORD, expect=None)
    page.wait_for_selector("[role=alert]")
    assert page.url.endswith("/login")
    sign_in(page, live, member.username, NEW_PASSWORD)
    assert dd_for(page, "Display name") == "Rosa Reset"

    # The browser that was signed in before the reset is signed out.
    old_session.goto(live.url("/account"))
    old_session.wait_for_url("**/login")


def test_forgot_password_for_a_guest_goes_to_the_sponsor(live, new_page):
    sponsor = live.make_member("Sven Sponsor", "sven.sponsor")
    live.make_guest(sponsor, "Gus Guest", "gus.guest")
    page = new_page()
    before = live.mail.count(sponsor.email)
    total_before = live.mail.count()

    page.goto(live.url("/forgot"))
    page.fill("#username", "gus.guest")
    page.click("form[action='/forgot'] button[type=submit]")
    page.wait_for_selector("form[action='/forgot']", state="detached")

    mail = live.mail.wait_new(sponsor.email, before)
    assert mail.to == (sponsor.email,)  # the guest has no address of their own
    assert "gus.guest" in mail.body
    assert live.mail.count() == total_before + 1

    page.goto(mail.link("/reset/"))
    page.fill("#password", NEW_PASSWORD)
    page.fill("#password2", NEW_PASSWORD)
    page.click("form[action^='/reset/'] button[type=submit]")
    page.wait_for_url("**/login?notice=reset")
    sign_in(page, live, "gus.guest", NEW_PASSWORD)
    assert dd_for(page, "Display name") == "Gus Guest"
