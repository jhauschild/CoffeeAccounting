"""user-web (task 3.1): the member/guest choice on /register, the guest request and the sponsor's Approve / Reject
page, the 'temporarily unavailable' state, the privacy rewrite, and the login redirects (memory mail backend)."""

from __future__ import annotations

import re
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from app.db import write_session
from app.models import (AuditLog, PasswordResetToken, PendingRegistration, RateLimitEvent, User, UserSession)
from app.services import mail, mail_credentials, passwords, pending, registration
from app.timeutil import utcnow
from tests import factories
from tests.conftest import reload_settings
from tests.user_support import PASSWORD, field, make_account, sign_in

SPONSOR_EMAIL = "sabine@tum.de"


@pytest.fixture(autouse=True)
def memory_mail(monkeypatch):
    monkeypatch.setenv("MAIL_BACKEND", "memory")
    reload_settings()
    mail.clear_outbox()
    mail.reset_status()
    yield
    mail.clear_outbox()
    mail.reset_status()


@pytest.fixture
def sponsor(db, chair):
    return make_account(db, "Sabine Sponsor", chair, username="sabine")


def _counts(db):
    db.rollback()
    return {m.__name__: db.scalar(select(func.count()).select_from(m))
            for m in (User, UserSession, PendingRegistration, PasswordResetToken, AuditLog, RateLimitEvent)}


def _guest_form(**over):
    data = {"username": "gerda", "display_name": "Gerda Gast", "sponsor_email": SPONSOR_EMAIL,
            "password": PASSWORD, "password2": PASSWORD, "privacy_ack": "1"}
    data.update(over)
    return data


def _register_guest(client, **over):
    data = _guest_form(**over)
    data["csrf_token"] = field(client.get("/register?kind=guest").text, "csrf_token")
    return client.post("/register/guest", data=data, follow_redirects=False)


def _approval_link():
    (message,) = [m for m in mail.get_outbox() if "/verify/" in m.body]
    (url,) = [u for u in mail.extract_links(message) if "/verify/" in u]
    return "/" + url.split("/", 3)[3]


def _decide(client, link, action, *, csrf=True):
    data = {"action": action}
    if csrf:
        data["csrf_token"] = field(client.get(link).text, "csrf_token")
    return client.post(link, data=data, follow_redirects=False)


# ----- the choice and the two forms -------------------------------------------------------------------------
def test_register_defaults_to_the_member_form_and_offers_the_choice(client, db, chair):
    page = client.get("/register")
    assert page.status_code == 200
    assert "I am a member" in page.text and "I am a guest" in page.text and 'href="/register?kind=guest"' in page.text
    for name in ("username", "display_name", "chair_id", "email", "password", "password2", "privacy_ack"):
        assert f'name="{name}"' in page.text
    assert 'name="sponsor_email"' not in page.text and 'action="/register"' in page.text
    assert "verified TUM" in page.text or "university e-mail address" in page.text
    assert "vouch" in page.text  # the page says guests need a member to vouch for them


def test_register_guest_form_has_the_sponsor_field_and_no_chair_or_own_email(client, db, chair):
    page = client.get("/register?kind=guest")
    assert page.status_code == 200 and 'action="/register/guest"' in page.text
    for name in ("username", "display_name", "password", "password2", "sponsor_email", "privacy_ack", "csrf_token"):
        assert f'name="{name}"' in page.text
    assert 'name="chair_id"' not in page.text and 'name="email"' not in page.text
    assert "vouch" in page.text and 'href="/register"' in page.text
    assert client.get("/register?kind=whatever").text == client.get("/register").text  # unknown value: member form


def test_register_pages_write_nothing(client, db, chair):
    before = _counts(db)
    client.get("/register")
    client.get("/register?kind=guest")
    assert _counts(db) == before


def test_privacy_checkbox_text_names_what_is_visible(client, db, chair):
    for url in ("/register", "/register?kind=guest"):
        text = client.get(url).text.lower()
        assert "visible to every verified, signed-in account" in text
        assert "no e-mail address, username or password" in text


# ----- guest request: the neutral page ----------------------------------------------------------------------
def test_guest_request_mails_the_member_and_shows_the_neutral_page(client, db, sponsor):
    before = _counts(db)
    r = _register_guest(client)
    assert r.status_code == 200
    assert "If this address belongs to a registered member" in r.text and "spam folder" in r.text
    assert "double-check" in r.text
    (message,) = mail.get_outbox()
    assert message.to == SPONSOR_EMAIL and "/verify/" in message.body and "gerda" in message.body
    after = _counts(db)
    assert after["PendingRegistration"] == before["PendingRegistration"] + 1 and after["User"] == before["User"]


def test_the_neutral_page_is_identical_for_member_non_member_and_unknown_address(client, db, sponsor):
    factories.make_member(db, "Other Member", sponsor.chair, username="other", email="other@tum.de")
    member = _register_guest(client, username="g-one")
    stranger = _register_guest(client, username="g-two", sponsor_email="nobody@tum.de")
    unknown = _register_guest(client, username="g-three", sponsor_email="never.heard.of@mytum.de")
    assert member.status_code == stranger.status_code == unknown.status_code == 200
    assert member.text == stranger.text == unknown.text
    assert member.headers["content-type"] == stranger.headers["content-type"] == unknown.headers["content-type"]
    assert [m.to for m in mail.get_outbox()] == [SPONSOR_EMAIL]  # only the real member is mailed
    assert _counts(db)["PendingRegistration"] == 1


def test_a_sponsor_with_too_many_open_requests_gets_the_same_page(client, db, sponsor):
    for i in range(registration.MAX_OPEN_REQUESTS_PER_SPONSOR):
        with write_session() as w:
            registration.begin_guest(w, username=f"open{i}", display_name=f"Open {i}", password=PASSWORD,
                                     sponsor_email=SPONSOR_EMAIL, privacy_ack=True, ip=f"10.0.0.{i}")
    mail.clear_outbox()
    full = _register_guest(client, username="late")
    stranger = _register_guest(client, username="late2", sponsor_email="nobody@tum.de")
    assert full.status_code == 200 and full.text == stranger.text
    assert mail.get_outbox() == []


def test_a_guest_whose_sponsor_is_gone_still_gets_the_neutral_page_on_forgot(client, db, sponsor):
    factories.make_guest(db, sponsor, "Gerda", username="gerda",
                         password_hash=passwords.hash_password(PASSWORD))
    sponsor.status = "inactive"
    db.commit()
    page = client.get("/forgot")
    csrf = field(page.text, "csrf_token")
    gone = client.post("/forgot", data={"csrf_token": csrf, "username": "gerda"}, follow_redirects=False)
    unknown = client.post("/forgot", data={"csrf_token": csrf, "username": "nosuchuser"}, follow_redirects=False)
    assert gone.status_code == unknown.status_code == 200 and gone.text == unknown.text
    assert mail.get_outbox() == []  # nobody to send it to: the head admin has to reassign the guest
    assert _counts(db)["PasswordResetToken"] == 0


def test_forgot_uses_the_registration_recovery_address(db, sponsor):
    from app.services import recovery

    assert not hasattr(recovery, "_recovery_address")
    guest = factories.make_guest(db, sponsor, "Gerda", username="gerda")
    with write_session() as w:
        outcome = recovery.request_reset(w, "gerda", "10.9.9.9")
    assert outcome.recipient == SPONSOR_EMAIL
    sponsor.status = "inactive"
    db.commit()
    with write_session() as w:
        assert recovery.request_reset(w, "gerda", "10.9.9.9").message is None
    assert guest.id


@pytest.mark.parametrize("over,needle", [
    ({"sponsor_email": "stranger@gmail.com"}, "university e-mail address of a member"),
    ({"sponsor_email": "nonsense"}, "valid e-mail"),
    ({"username": "x"}, "3 to 32 characters"),
    ({"password": "short", "password2": "short"}, "too short"),
    ({"password2": "different battery"}, "not the same"),
    ({"privacy_ack": ""}, "privacy information"),
    ({"display_name": "  "}, "Please enter a name"),
])
def test_guest_validation_errors_are_shown_and_send_nothing(client, db, sponsor, over, needle):
    before = _counts(db)
    r = _register_guest(client, **over)
    assert r.status_code == 400 and needle in r.text
    assert 'action="/register/guest"' in r.text and PASSWORD not in r.text  # stays on the guest form
    assert mail.get_outbox() == []
    after = _counts(db)
    assert after["PendingRegistration"] == before["PendingRegistration"]
    assert after["RateLimitEvent"] == before["RateLimitEvent"]


def test_guest_form_requires_csrf(client, db, sponsor):
    client.get("/register?kind=guest")
    r = client.post("/register/guest", data=_guest_form(), follow_redirects=False)
    assert r.status_code == 403 and mail.get_outbox() == []


def test_guest_request_is_rate_limited_per_ip(client, db, sponsor):
    for i in range(3):
        assert _register_guest(client, username=f"user{i}").status_code == 200
    r = _register_guest(client, username="onetoomany")
    assert r.status_code == 429 and "Too many attempts" in r.text


def test_username_probe_limit_survives_through_the_guest_form(client, db, sponsor, global_admin):
    for i in range(10):
        r = _register_guest(client, username="sabine" if i % 2 == 0 else global_admin.username)
        assert r.status_code == 400 and "already taken" in r.text
    r = _register_guest(client, username="sabine")
    assert r.status_code == 429 and "Too many attempts" in r.text
    assert mail.get_outbox() == []
    db.rollback()
    assert db.scalar(select(func.count()).select_from(RateLimitEvent).where(RateLimitEvent.bucket == "username_probe")) >= 10


def test_the_probe_budget_is_shared_between_the_member_and_guest_forms(client, db, sponsor, chair):
    for _ in range(10):
        assert _register_guest(client, username="sabine").status_code == 400
    page = client.get("/register")
    data = {"csrf_token": field(page.text, "csrf_token"), "username": "sabine", "display_name": "X Y",
            "chair_id": str(chair.id), "email": "xy@tum.de", "password": PASSWORD, "password2": PASSWORD,
            "privacy_ack": "1"}
    assert client.post("/register", data=data, follow_redirects=False).status_code == 429


# ----- sponsor approval -------------------------------------------------------------------------------------
def test_get_shows_the_guest_and_what_vouching_means_and_writes_nothing(client, db, sponsor):
    _register_guest(client)
    link = _approval_link()
    before = _counts(db)
    for _ in range(2):  # a mail scanner prefetching the link
        r = client.get(link)
        assert r.status_code == 200 and "Gerda Gast" in r.text and "gerda" in r.text
        assert "vouch" in r.text.lower() and "uses the coffee machine" in r.text
        assert 'value="approve"' in r.text and 'value="reject"' in r.text and 'name="csrf_token"' in r.text
        assert "sign in with the username" not in r.text
    assert _counts(db) == before


def test_approve_creates_the_guest_without_a_login_and_says_so(client, db, sponsor, chair):
    _register_guest(client)
    link = _approval_link()
    client.cookies.clear()  # the sponsor needs no login
    r = _decide(client, link, "approve")
    assert r.status_code == 200 and "Gerda Gast can now sign in with the username gerda" in r.text
    assert "coffee_session" not in r.headers.get("set-cookie", "")
    db.rollback()
    guest = db.scalar(select(User).where(User.username == "gerda"))
    assert guest.account_kind == "guest" and guest.sponsor_id == sponsor.id and guest.chair_id == sponsor.chair_id
    assert db.scalar(select(func.count()).select_from(UserSession)) == 0
    # ... and the guest can now sign in
    guest_client = client.__class__(client.app)
    r = sign_in(guest_client, "gerda")
    assert r.status_code == 303 and r.headers["location"] == "/account"


def test_approve_twice_is_a_dead_link(client, db, sponsor):
    _register_guest(client)
    link = _approval_link()
    assert _decide(client, link, "approve").status_code == 200
    users_after = _counts(db)["User"]
    csrf = field(_fresh_csrf(client), "csrf_token")
    replay = client.post(link, data={"action": "approve", "csrf_token": csrf}, follow_redirects=False)
    assert replay.status_code == 400 and "not valid" in replay.text
    assert client.get(link).status_code == 400
    assert _counts(db)["User"] == users_after


def _fresh_csrf(client):
    return client.get("/login").text


def test_reject_creates_nothing_and_kills_the_link(client, db, sponsor):
    _register_guest(client)
    link = _approval_link()
    r = _decide(client, link, "reject")
    assert r.status_code == 200 and "rejected" in r.text.lower() and "No account was created" in r.text
    db.rollback()
    assert db.scalar(select(User).where(User.username == "gerda")) is None
    csrf = field(_fresh_csrf(client), "csrf_token")
    assert client.post(link, data={"action": "approve", "csrf_token": csrf}).status_code == 400
    assert client.post(link, data={"action": "reject", "csrf_token": csrf}).status_code == 400
    assert client.get(link).status_code == 400
    # the guest cannot sign in
    assert sign_in(client.__class__(client.app), "gerda").status_code == 401


def test_a_guest_cannot_sign_in_before_approval_and_gets_the_generic_failure(client, db, sponsor):
    _register_guest(client)
    pending_guest = sign_in(client.__class__(client.app), "gerda")
    unknown = sign_in(client.__class__(client.app), "nobody-at-all")
    assert pending_guest.status_code == unknown.status_code == 401
    def plain(html: str) -> str:  # the body without the per-browser CSRF token and the echoed username
        html = re.sub(r'name="csrf_token" value="[^"]*"', "", html)
        return re.sub(r'(id="username"[^>]*?) value="[^"]*"', r"\1", html)

    assert plain(pending_guest.text) == plain(unknown.text)
    assert "Username or password is not correct" in pending_guest.text


def test_expired_links_are_refused_on_get_and_post(client, db, sponsor):
    _register_guest(client)
    link = _approval_link()
    csrf = field(client.get(link).text, "csrf_token")
    db.rollback()
    row = db.scalar(select(PendingRegistration))
    row.expires_at = utcnow() - timedelta(minutes=1)
    db.commit()
    assert client.get(link).status_code == 400
    for action in ("approve", "reject"):
        r = client.post(link, data={"action": action, "csrf_token": csrf}, follow_redirects=False)
        assert r.status_code == 400 and "expired" in r.text
    db.rollback()
    assert db.scalar(select(User).where(User.username == "gerda")) is None


def test_approve_needs_a_csrf_token(client, db, sponsor):
    _register_guest(client)
    link = _approval_link()
    before = _counts(db)
    r = _decide(client, link, "approve", csrf=False)
    assert r.status_code == 403
    assert _counts(db)["User"] == before["User"]
    assert _decide(client, link, "approve").status_code == 200  # the link was not burnt


def test_sponsor_who_is_no_longer_active_cannot_approve(client, db, sponsor):
    _register_guest(client)
    link = _approval_link()
    csrf = field(client.get(link).text, "csrf_token")
    sponsor.status = "inactive"
    db.commit()
    assert client.get(link).status_code == 400  # peek: nothing to approve any more
    r = client.post(link, data={"action": "approve", "csrf_token": csrf}, follow_redirects=False)
    assert r.status_code == 403 and "no longer" in r.text
    db.rollback()
    assert db.scalar(select(User).where(User.username == "gerda")) is None


def test_username_taken_in_the_meantime_is_explained_and_does_not_burn_the_link(client, db, sponsor):
    _register_guest(client)
    link = _approval_link()
    csrf = field(client.get(link).text, "csrf_token")
    factories.make_member(db, "Squatter", sponsor.chair, username="gerda")
    r = client.post(link, data={"action": "approve", "csrf_token": csrf}, follow_redirects=False)
    assert r.status_code == 409 and "username has been taken" in r.text
    assert client.get(link).status_code == 200  # still pending; the sponsor may reject it
    assert _decide(client, link, "reject").status_code == 200


def test_member_tokens_are_not_guest_tokens_and_vice_versa(client, db, sponsor, chair):
    _register_guest(client)
    guest_link = _approval_link()
    mail.clear_outbox()
    page = client.get("/register")
    data = {"csrf_token": field(page.text, "csrf_token"), "username": "erika", "display_name": "Erika",
            "chair_id": str(chair.id), "email": "erika@tum.de", "password": PASSWORD, "password2": PASSWORD,
            "privacy_ack": "1"}
    client.post("/register", data=data)
    (message,) = mail.get_outbox()
    (url,) = [u for u in mail.extract_links(message) if "/verify/" in u]
    member_link = "/" + url.split("/", 3)[3]
    csrf = field(client.get(member_link).text, "csrf_token")
    # a member link cannot be approved as a guest, and a plain POST of a guest link does not create a member
    assert client.post(member_link, data={"action": "approve", "csrf_token": csrf}).status_code == 400
    assert client.post(guest_link, data={"csrf_token": csrf}).status_code == 400
    assert client.get(member_link).status_code == 200 and "Confirm and sign in" in client.get(member_link).text
    assert "Approve" in client.get(guest_link).text and "Confirm and sign in" not in client.get(guest_link).text


# ----- temporarily unavailable ------------------------------------------------------------------------------
@pytest.fixture
def smtp_without_login(monkeypatch, tmp_path):
    monkeypatch.setenv("MAIL_BACKEND", "smtp")
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path / "secrets"))
    reload_settings()
    assert not mail_credentials.status().configured


@pytest.mark.parametrize("url", ["/register", "/register?kind=guest", "/forgot"])
def test_forms_are_unavailable_without_a_mail_login(client, db, sponsor, smtp_without_login, url):
    r = client.get(url)
    assert r.status_code == 503 and "Temporarily unavailable" in r.text and "ask an administrator" in r.text
    assert 'name="username"' not in r.text and 'name="password"' not in r.text


@pytest.mark.parametrize("url,data", [
    ("/register", {"username": "erika", "display_name": "E", "chair_id": "x", "email": "erika@tum.de",
                   "password": PASSWORD, "password2": PASSWORD, "privacy_ack": "1"}),
    ("/register/guest", _guest_form()),
    ("/forgot", {"username": "sabine"}),
])
def test_posts_collect_nothing_without_a_mail_login(client, db, sponsor, smtp_without_login, url, data):
    before = _counts(db)
    r = client.post(url, data={**data, "csrf_token": "x"}, follow_redirects=False)  # even a CSRF-less post
    assert r.status_code in (403, 503)
    csrf = field(client.get("/login").text, "csrf_token")
    r = client.post(url, data={**data, "csrf_token": csrf}, follow_redirects=False)
    assert r.status_code == 503 and "Temporarily unavailable" in r.text
    assert _counts(db) == before and mail.get_outbox() == []


def test_login_and_privacy_stay_available_without_a_mail_login(client, db, sponsor, smtp_without_login):
    assert client.get("/login").status_code == 200 and client.get("/privacy").status_code == 200
    assert 'href="/register"' in client.get("/login").text


def test_forms_are_available_once_the_mail_login_is_stored(client, db, sponsor, smtp_without_login):
    mail_credentials.save_credentials("coffee@lrz.de", "pw-for-the-mail-account")
    assert client.get("/register").status_code == 200 and client.get("/forgot").status_code == 200
    assert client.get("/register?kind=guest").status_code == 200


@pytest.mark.parametrize("backend", ["memory", "console", "file"])
def test_development_backends_stay_available(client, db, monkeypatch, tmp_path, backend):
    monkeypatch.setenv("MAIL_BACKEND", backend)
    monkeypatch.setenv("MAIL_FILE_DIR", str(tmp_path / "mails"))
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path / "nothing-here"))
    reload_settings()
    for url in ("/register", "/register?kind=guest", "/forgot"):
        assert client.get(url).status_code == 200, url


# ----- login: redirects and links ---------------------------------------------------------------------------
def test_login_with_a_view_site_pending_redirects_to_the_overview_with_no_parameter(client, db, chair):
    alice = make_account(db, "Alice", chair)
    with write_session() as w:
        pid = pending.create_view_site_pending(w)
    client.cookies.set("coffee_pending", pid)
    r = sign_in(client, alice)
    assert r.status_code == 303 and r.headers["location"] == "/overview"


def test_a_redirect_parameter_is_ignored(client, db, chair):
    alice = make_account(db, "Alice", chair)
    page = client.get("/login?next=https://evil.example/")
    data = {"csrf_token": field(page.text, "csrf_token"), "username": alice.username, "password": PASSWORD}
    r = client.post("/login?next=https://evil.example/", data=data, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/account"


def test_login_page_links_to_registration(client):
    page = client.get("/login")
    assert 'href="/register"' in page.text and "Create account" in page.text


# ----- privacy ----------------------------------------------------------------------------------------------
def test_privacy_page_states_who_sees_what(client, monkeypatch):
    monkeypatch.setenv("RETENTION_TEXT", "We keep everything for seven years.")
    monkeypatch.setenv("OPERATOR_CONTACT", "Coffee Admin <coffee-admin@example.org>")
    reload_settings()
    text = client.get("/privacy").text
    low = text.lower()
    assert "seven years" in text and "Coffee Admin" in text  # retention and contact name stay
    assert "coffee-admin@example.org" not in text  # anonymous: no operator e-mail
    assert "every verified, signed-in account" in low
    for visible in ("display name", "balance", "history", "group balances", "group admins"):
        assert visible in low
    assert "no e-mail address, no username and no password data is ever shown" in low
    assert "visitors who are not signed in cannot see" in low
