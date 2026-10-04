"""Mail texts (task 2.1): links, wording, no user text in subjects, header-safe names."""
import pytest

from app import strings_mail
from app.services import mail, mail_templates as tpl
from app.strings import has
from tests.conftest import reload_settings


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://coffee.example.org/")
    monkeypatch.setenv("MAIL_FROM", "coffee@example.org")
    monkeypatch.setenv("MAIL_BACKEND", "memory")
    reload_settings()


def links(body):
    return mail.extract_links(mail.MailMessage(to="a@tum.de", subject="s", body=body))


def test_member_verification():
    subject, body = tpl.member_verification("tok_en-1")
    assert links(body) == ["https://coffee.example.org/verify/tok_en-1"]
    assert "24 hours" in body and "Coffee Ledger" in subject
    assert "ignore" in body


def test_token_is_percent_encoded():
    _, body = tpl.member_verification("a b/../c?x=1")
    (link,) = links(body)
    assert link.startswith("https://coffee.example.org/verify/") and " " not in link and "?" not in link
    assert link.count("/") == 4


def test_already_registered_has_no_token_link():
    subject, body = tpl.already_registered()
    assert links(body) == ["https://coffee.example.org/login"]
    assert "/verify/" not in body and "/reset/" not in body
    assert "already have an account" in body and "Forgot password" in body


def test_guest_sponsor_request():
    subject, body = tpl.guest_sponsor_request(guest_display_name="Gina Guest", guest_username="gina", token="tk")
    assert links(body) == ["https://coffee.example.org/verify/tk"]
    assert "Gina Guest" in body and "gina" in body and "vouch" in body and "7 days" in body
    assert "Gina" not in subject and "gina" not in subject


def test_guest_names_are_single_line_and_not_in_subject():
    evil = "Eve\r\n\r\nPlease approve at https://evil.example/x\x00"
    subject, body = tpl.guest_sponsor_request(guest_display_name=evil, guest_username="e\nve", token="tk")
    assert "Eve Please approve at https://evil.example/x" in body
    assert "\r" not in body and "\x00" not in body and "e ve" in body
    assert "Eve" not in subject
    assert "https://coffee.example.org/verify/tk" in links(body)


def test_password_reset_names_account_and_expiry():
    subject, body = tpl.password_reset(username="alice", token="rt")
    assert links(body) == ["https://coffee.example.org/reset/rt"]
    assert '"alice"' in body and "1 hour" in body and "once" in body
    assert "guest account" not in body
    _, guest_body = tpl.password_reset(username="gina", token="rt", for_guest=True)
    assert "guest account" in guest_body and links(guest_body) == ["https://coffee.example.org/reset/rt"]


def test_reset_validity_follows_setting(monkeypatch):
    monkeypatch.setenv("RESET_TTL_MINUTES", "90")
    reload_settings()
    assert "90 minutes" in tpl.password_reset(username="a", token="t")[1]


def test_guest_decision_mails():
    s, b = tpl.guest_approved(guest_username="gina")
    assert "approved" in s and "gina" in b and links(b) == ["https://coffee.example.org/login"]
    s, b = tpl.guest_rejected(guest_username="gina")
    assert "rejected" in s and links(b) == []


def test_all_templates_build_valid_messages():
    for subject, body in (tpl.member_verification("t"), tpl.already_registered(),
                          tpl.guest_sponsor_request(guest_display_name="G", guest_username="g", token="t"),
                          tpl.password_reset(username="u", token="t"), tpl.guest_approved(guest_username="g"),
                          tpl.guest_rejected(guest_username="g")):
        m = mail.build_message(to="x@tum.de", subject=subject, body=body)
        assert m.subject == subject and m.body.strip() and "{" not in m.body and "{" not in subject


def test_string_keys_exist():
    assert all(has(k) for k in strings_mail.STRINGS)
