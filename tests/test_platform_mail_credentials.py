"""Encrypted mail-login store (task 2.2): modes, atomic write, no password in file bytes / logs / repr /
exceptions, wrong SECRET_KEY, clear and status. Offline; the store lives in a temp directory."""
import logging
import os
import pickle
import stat

import pytest
from cryptography.fernet import Fernet

from app.config import get_settings
from app.services import keys, mail, mail_credentials
from app.services.errors import InvalidInput
from app.services.mail import MailError
from app.services.mail_credentials import MailLoginUnreadable
from tests.conftest import reload_settings

USER = "coffee@lrz.de"
PASSWORD = "Tr0ub4dor&3-unique-mail-pw"


@pytest.fixture
def secrets_dir(tmp_path, monkeypatch):
    path = tmp_path / "secrets"
    monkeypatch.setenv("SECRETS_DIR", str(path))
    reload_settings()
    return path


def mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_save_and_load_roundtrip(secrets_dir):
    mail_credentials.save_credentials(USER, PASSWORD)
    creds = mail_credentials.load_credentials()
    assert creds.username == USER and creds.password == PASSWORD


def test_modes_directory_0700_file_0600_even_with_open_umask(secrets_dir):
    old = os.umask(0)
    try:
        mail_credentials.save_credentials(USER, PASSWORD)
    finally:
        os.umask(old)
    assert mode(secrets_dir) == 0o700
    assert mode(mail_credentials.credentials_path()) == 0o600


def test_existing_directory_and_file_modes_are_fixed(secrets_dir):
    secrets_dir.mkdir(mode=0o755)
    os.chmod(secrets_dir, 0o777)
    target = secrets_dir / mail_credentials.FILE_NAME
    target.write_bytes(b"old")
    os.chmod(target, 0o644)
    mail_credentials.save_credentials(USER, PASSWORD)
    assert mode(secrets_dir) == 0o700 and mode(target) == 0o600
    assert [p.name for p in secrets_dir.iterdir()] == [mail_credentials.FILE_NAME]  # no temp leftovers


def test_password_and_username_are_not_in_the_file_bytes(secrets_dir):
    mail_credentials.save_credentials(USER, PASSWORD)
    raw = mail_credentials.credentials_path().read_bytes()
    assert PASSWORD.encode() not in raw and USER.encode() not in raw
    assert b"password" not in raw and b"username" not in raw
    # it is a Fernet token under the labelled HKDF key, and only under that key
    Fernet(keys.fernet_key("mail-credentials")).decrypt(raw)
    with pytest.raises(Exception):
        Fernet(keys.fernet_key("other-label")).decrypt(raw)


def test_overwrite_replaces_the_login(secrets_dir):
    mail_credentials.save_credentials(USER, PASSWORD)
    mail_credentials.save_credentials("other@lrz.de", "second-password-value")
    creds = mail_credentials.load_credentials()
    assert (creds.username, creds.password) == ("other@lrz.de", "second-password-value")


@pytest.mark.parametrize("failing", ["replace", "fsync"])
def test_atomic_write_leaves_no_partial_file_and_keeps_the_old_one(secrets_dir, monkeypatch, failing):
    mail_credentials.save_credentials(USER, PASSWORD)
    before = mail_credentials.credentials_path().read_bytes()

    def boom(*a, **k):
        raise OSError("simulated failure")

    with monkeypatch.context() as m:
        m.setattr(os, failing, boom)
        with pytest.raises(OSError):
            mail_credentials.save_credentials("new@lrz.de", "brand-new-password")
    assert mail_credentials.credentials_path().read_bytes() == before
    assert [p.name for p in secrets_dir.iterdir()] == [mail_credentials.FILE_NAME]  # temp file removed
    assert mail_credentials.load_credentials().username == USER


def test_failed_first_write_creates_no_file(secrets_dir, monkeypatch):
    with monkeypatch.context() as m:
        m.setattr(os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("simulated failure")))
        with pytest.raises(OSError):
            mail_credentials.save_credentials(USER, PASSWORD)
    assert list(secrets_dir.iterdir()) == []
    with pytest.raises(MailError) as exc:
        mail_credentials.load_credentials()
    assert exc.value.category == "not_configured"


def test_nothing_is_logged_and_password_not_in_any_log(secrets_dir, caplog):
    caplog.set_level(logging.DEBUG)
    mail_credentials.save_credentials(USER, PASSWORD)
    mail_credentials.load_credentials()
    mail_credentials.status()
    secrets_dir.joinpath(mail_credentials.FILE_NAME).write_bytes(b"garbage")
    with pytest.raises(MailLoginUnreadable):
        mail_credentials.load_credentials()
    mail_credentials.clear_credentials()
    assert PASSWORD not in caplog.text and PASSWORD not in "".join(r.getMessage() for r in caplog.records)


def test_password_not_in_repr_str_status_or_settings(secrets_dir):
    mail_credentials.save_credentials(USER, PASSWORD)
    creds = mail_credentials.load_credentials()
    texts = [repr(creds), str(creds), f"{creds}", f"{creds!r}", repr(mail_credentials.status()),
             str(mail_credentials.status()), repr(get_settings()), str(get_settings()), repr(vars(creds))]
    # vars() of the credentials does expose the value by design of a dataclass; the guarantee covers repr/str
    for text in texts[:-1]:
        assert PASSWORD not in text
    assert "<hidden>" in repr(creds)
    with pytest.raises(TypeError):
        pickle.dumps(creds)


def test_invalid_input_is_refused_without_echoing_the_password(secrets_dir):
    for user, pw in [("", PASSWORD), ("   ", PASSWORD), ("a\nb@lrz.de", PASSWORD), (USER, ""), (USER, "x" * 5000)]:
        with pytest.raises(InvalidInput) as exc:
            mail_credentials.save_credentials(user, pw)
        assert PASSWORD not in str(exc.value) and "xxxxx" not in str(exc.value)
    assert not mail_credentials.credentials_path().exists()


def test_wrong_secret_key_gives_the_clear_error(secrets_dir, monkeypatch):
    mail_credentials.save_credentials(USER, PASSWORD)
    monkeypatch.setenv("SECRET_KEY", "a-completely-different-secret-key-for-this-test-0123456789")
    reload_settings()
    with pytest.raises(MailLoginUnreadable) as exc:
        mail_credentials.load_credentials()
    assert isinstance(exc.value, MailError) and exc.value.category == "not_configured"
    assert str(exc.value) == "mail login unreadable: re-run setup-mail"
    assert "cryptography" not in repr(exc.value).lower() and "fernet" not in repr(exc.value).lower()
    assert exc.value.__cause__ is None and exc.value.__suppress_context__
    st = mail_credentials.status()
    assert st.configured is False and st.unreadable is True and st.masked_username is None
    # setup-mail again under the new key repairs it
    mail_credentials.save_credentials(USER, PASSWORD)
    assert mail_credentials.load_credentials().password == PASSWORD


@pytest.mark.parametrize("content", [b"", b"not a token", b"gAAAAA" + b"A" * 80])
def test_corrupt_file_gives_the_clear_error(secrets_dir, content):
    secrets_dir.mkdir()
    (secrets_dir / mail_credentials.FILE_NAME).write_bytes(content)
    with pytest.raises(MailLoginUnreadable) as exc:
        mail_credentials.load_credentials()
    assert str(exc.value) == mail_credentials.UNREADABLE_MESSAGE


@pytest.mark.parametrize("plain", [b"not json", b"[]", b'{"username": "a"}', b'{"username": 1, "password": 2}',
                                   b'{"username": "", "password": ""}'])
def test_valid_token_with_wrong_content_is_unreadable(secrets_dir, plain):
    secrets_dir.mkdir()
    (secrets_dir / mail_credentials.FILE_NAME).write_bytes(Fernet(keys.fernet_key("mail-credentials")).encrypt(plain))
    with pytest.raises(MailLoginUnreadable):
        mail_credentials.load_credentials()


def test_missing_file_is_not_configured(secrets_dir):
    with pytest.raises(MailError) as exc:
        mail_credentials.load_credentials()
    assert exc.value.category == "not_configured" and not isinstance(exc.value, MailLoginUnreadable)
    assert mail_credentials.status() == mail_credentials.MailLoginStatus(configured=False)


def test_clear_credentials_removes_the_file(secrets_dir):
    assert mail_credentials.clear_credentials() is False  # nothing to remove, no error
    mail_credentials.save_credentials(USER, PASSWORD)
    assert mail_credentials.clear_credentials() is True
    assert not mail_credentials.credentials_path().exists()
    assert mail_credentials.status().configured is False
    with pytest.raises(MailError):
        mail_credentials.load_credentials()


def test_status_masks_the_username_and_never_has_the_password(secrets_dir):
    mail_credentials.save_credentials(USER, PASSWORD)
    st = mail_credentials.status()
    assert st.configured is True and st.username == USER and st.masked_username == "c***@lrz.de"
    assert st.unreadable is False
    assert PASSWORD not in repr(st) and PASSWORD not in repr(st.username)
    assert not hasattr(st, "password")
    mail_credentials.save_credentials("Dr.Coffee@mail.lrz.de", PASSWORD)
    st = mail_credentials.status()
    assert st.username == "Dr.Coffee@mail.lrz.de" and st.masked_username == "D***@mail.lrz.de"
    mail_credentials.save_credentials("plainuser", PASSWORD)
    st = mail_credentials.status()
    assert st.username == "plainuser" and st.masked_username == "p***"


def test_smtp_backend_reports_unreadable_login_without_connecting(secrets_dir, monkeypatch):
    monkeypatch.setenv("MAIL_BACKEND", "smtp")
    monkeypatch.setenv("MAIL_FROM", "coffee@example.org")
    reload_settings()
    mail_credentials.save_credentials(USER, PASSWORD)
    monkeypatch.setenv("SECRET_KEY", "yet-another-secret-key-0123456789-abcdefghijklmnop")
    reload_settings()
    mail.reset_status()
    with pytest.raises(MailError) as exc:
        mail.get_mailer().send(mail.build_message(to="a@tum.de", subject="s", body="b"))
    assert str(exc.value) == "mail login unreadable: re-run setup-mail"
    # through the shared delivery path the failure is categorised and recorded once, outside the backend
    with pytest.raises(MailError) as exc2:
        mail._deliver(mail.get_mailer(), mail.build_message(to="a@tum.de", subject="s", body="b"))
    assert exc2.value.category == "not_configured"
    assert mail.get_status().last_failure_category == "not_configured"
    mail.reset_status()
