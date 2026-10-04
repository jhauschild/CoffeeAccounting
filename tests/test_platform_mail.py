"""Mail core (task 2.1): message shape, header safety, backends, caps, status, production refusal.
Memory/file/console backends only; no network."""
import logging
import os
import stat
from email import policy
from email.parser import BytesParser

import pytest
from sqlalchemy import select

from app import db as app_db
from app.config import Settings
from app.models import RateLimitEvent
from app.services import mail
from app.services.errors import InvalidInput
from app.services.mail import MailError, MailMessage
from tests.conftest import reload_settings


@pytest.fixture(autouse=True)
def _clean_mail_state(monkeypatch):
    monkeypatch.setenv("MAIL_FROM", "Coffee Ledger <coffee@example.org>")
    monkeypatch.setenv("MAIL_BACKEND", "memory")
    reload_settings()
    mail.clear_outbox()
    mail.reset_status()
    yield
    mail.clear_outbox()
    mail.reset_status()


def msg(to="alice@tum.de", subject="Hello", body="Body line\nhttps://example.org/x"):
    return mail.build_message(to=to, subject=subject, body=body)


# ----- message shape and headers ---------------------------------------------------------------------------------


def test_build_message_shape():
    m = msg()
    assert isinstance(m, MailMessage)
    assert m.to == "alice@tum.de" and m.subject == "Hello"
    assert m.headers["From"] == "coffee@example.org"  # address part of MAIL_FROM
    assert m.headers["Auto-Submitted"] == "auto-generated"
    parsed = mail.to_email_message(m)
    assert parsed["Auto-Submitted"] == "auto-generated"
    assert parsed["To"] == "alice@tum.de" and parsed["Subject"] == "Hello"
    assert parsed.get_content_type() == "text/plain" and not parsed.is_multipart()
    assert parsed["Date"] and parsed["Message-ID"]
    assert "https://example.org/x" in parsed.get_content()


def test_to_is_lowercased_and_dev_from_fallback(monkeypatch):
    monkeypatch.setenv("MAIL_FROM", "")
    reload_settings()
    m = msg(to="Alice@TUM.de")
    assert m.to == "alice@tum.de" and m.headers["From"] == "noreply@localhost"


@pytest.mark.parametrize("bad", [
    "alice@tum.de\r\nBcc: x@evil.org", "alice@tum.de\nBcc: x@evil.org", "a b@tum.de", "alice@tum.de,bob@tum.de",
    "<alice@tum.de>", "alice", "", "alice@", "@tum.de", "a..b@tum.de", "alice@tum.de\x00",
])
def test_bad_recipient_rejected(bad):
    with pytest.raises(InvalidInput):
        msg(to=bad)


@pytest.mark.parametrize("evil", [
    "Hi\r\nBcc: evil@example.org", "Hi\nBcc: evil@example.org", "Hi\rBcc: evil@example.org",
    "Hi\x00\x0b\x0c\x1b[31m\x7f\x85  Bcc: evil@example.org",
])
def test_subject_injection_blocked(evil):
    m = msg(subject=evil)
    assert not any(c in m.subject for c in "\r\n\x00\x0b\x0c\x1b\x7f\x85  ")
    raw = mail.to_email_message(m).as_bytes()
    parsed = BytesParser(policy=policy.default).parsebytes(raw)
    assert [k for k in parsed.keys() if k.lower() == "bcc"] == []
    assert parsed["Subject"].startswith("Hi")


def test_display_name_stripped_and_cannot_inject():
    m = mail.build_message(to="alice@tum.de", subject="s", body="b",
                           to_name='Eve"\r\nBcc: evil@example.org\n<x@y.z>\x00')
    assert "\r" not in m.headers["To"] and "\n" not in m.headers["To"] and "\x00" not in m.headers["To"]
    parsed = BytesParser(policy=policy.default).parsebytes(mail.to_email_message(m).as_bytes())
    assert parsed["Bcc"] is None
    assert [a.addr_spec for a in parsed["To"].addresses] == ["alice@tum.de"]


def test_hand_built_message_is_resanitised_at_serialisation():
    m = MailMessage(to="alice@tum.de", subject="ok\r\nBcc: evil@example.org", body="b",
                    headers={"From": "coffee@example.org\r\nBcc: evil@example.org", "X-Bad\r\nBcc": "x",
                             "Subject": "override", "Auto-Submitted": "auto-generated"})
    raw = mail.to_email_message(m).as_bytes()
    parsed = BytesParser(policy=policy.default).parsebytes(raw)
    assert parsed["Bcc"] is None and parsed["Subject"].startswith("ok")
    assert b"\r\nBcc:" not in raw


def test_body_is_plain_text_without_control_characters():
    m = msg(body="line1\r\nline2\x00\x1b‮ evil\nend")
    assert "\r" not in m.body and "\x00" not in m.body and "\x1b" not in m.body and "‮" not in m.body
    assert m.body.startswith("line1\nline2")


def test_non_ascii_subject_and_body_round_trip():
    m = msg(subject="Kaffee: Bestätigung", body="Grüße\nhttps://example.org/ä")
    parsed = BytesParser(policy=policy.default).parsebytes(mail.to_email_message(m).as_bytes())
    assert parsed["Subject"] == "Kaffee: Bestätigung" and "Grüße" in parsed.get_content()


def test_subject_length_is_limited():
    assert len(msg(subject="x" * 5000).subject) <= mail.MAX_SUBJECT_LENGTH


# ----- memory backend and extract_links --------------------------------------------------------------------------


def test_memory_outbox_and_extract_links():
    m = msg(body="Open https://coffee.example.org/verify/abc_DEF-1.\nOr (http://x.org/reset/zzz), thanks!")
    mail.get_mailer().send(m)
    assert mail.get_outbox() == [m]
    assert mail.extract_links(m) == ["https://coffee.example.org/verify/abc_DEF-1", "http://x.org/reset/zzz"]
    mail.get_outbox().clear()  # a copy: the real outbox is untouched
    assert len(mail.get_outbox()) == 1
    mail.clear_outbox()
    assert mail.get_outbox() == []
    assert mail.extract_links(msg(body="no links")) == []


# ----- console backend --------------------------------------------------------------------------------------------


def test_console_logs_recipient_and_subject_never_body(monkeypatch, caplog):
    monkeypatch.setenv("MAIL_BACKEND", "console")
    reload_settings()
    secret_link = "https://coffee.example.org/verify/SUPERSECRETTOKEN"
    with caplog.at_level(logging.DEBUG):
        mail.get_mailer().send(msg(subject="Subj", body=f"private text {secret_link}"))
    text = caplog.text
    assert "alice@tum.de" in text and "Subj" in text
    assert "SUPERSECRETTOKEN" not in text and "private text" not in text


# ----- file backend -----------------------------------------------------------------------------------------------


def test_file_backend_writes_private_eml(monkeypatch, tmp_path):
    target = tmp_path / "outbox"
    monkeypatch.setenv("MAIL_BACKEND", "file")
    monkeypatch.setenv("MAIL_FILE_DIR", str(target))
    reload_settings()
    mailer = mail.get_mailer()
    mailer.send(msg(body="https://coffee.example.org/verify/tok1"))
    mailer.send(msg(subject="Second"))
    files = sorted(target.glob("*.eml"))
    assert len(files) == 2
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o700
    for f in files:
        assert stat.S_IMODE(os.stat(f).st_mode) == 0o600
    parsed = BytesParser(policy=policy.default).parsebytes(
        next(f for f in files if b"tok1" in f.read_bytes()).read_bytes())
    assert parsed["To"] == "alice@tum.de" and parsed["Auto-Submitted"] == "auto-generated"
    assert "tok1" in parsed.get_content()


def test_file_backend_without_directory_is_not_configured():
    with pytest.raises(MailError) as exc:
        mail.FileMailer("").send(msg())
    assert exc.value.category == "not_configured"


def test_file_backend_os_error_is_other(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    with pytest.raises(MailError) as exc:
        mail.FileMailer(str(blocker / "sub")).send(msg())
    assert exc.value.category == "other"


# ----- smtp stub, errors, factory ---------------------------------------------------------------------------------


def test_smtp_backend_is_a_stub_until_task_2_2(monkeypatch):
    monkeypatch.setenv("MAIL_BACKEND", "smtp")
    reload_settings()
    mailer = mail.get_mailer()
    assert isinstance(mailer, mail.SmtpMailer)
    with pytest.raises(MailError) as exc:
        mailer.send(msg())
    assert exc.value.category == "not_configured"


def test_get_mailer_picks_by_setting(monkeypatch, tmp_path):
    assert isinstance(mail.get_mailer(), mail.MemoryMailer)
    monkeypatch.setenv("MAIL_BACKEND", "console")
    reload_settings()
    assert isinstance(mail.get_mailer(), mail.ConsoleMailer)
    monkeypatch.setenv("MAIL_BACKEND", "file")
    monkeypatch.setenv("MAIL_FILE_DIR", str(tmp_path))
    reload_settings()
    assert isinstance(mail.get_mailer(), mail.FileMailer)


def _get_with(monkeypatch, settings):
    monkeypatch.setattr(mail, "get_settings", lambda: settings)
    return mail.get_mailer()


@pytest.mark.parametrize("backend", ["memory", "console", "file"])
def test_production_refuses_non_smtp(monkeypatch, backend):
    s = Settings(_env_file=None, environment="production", public_base_url="https://coffee.example.org",
                 secret_key="Zq3v8K1mR7tXw2pL9sD4fG6hJ0kN5bVc", mail_from="coffee@example.org",
                 mail_file_dir="/tmp/x", mail_backend="smtp")
    assert s.mail_backend == "smtp" and isinstance(_get_with(monkeypatch, s), mail.SmtpMailer)
    s.mail_backend = backend  # bypass startup validation: get_mailer must refuse on its own
    with pytest.raises(MailError) as exc:
        _get_with(monkeypatch, s)
    assert exc.value.category == "not_configured"


def test_mail_error_categories_and_safe_keys():
    from app.strings import has
    for cat in mail.CATEGORIES:
        e = MailError(cat)
        assert e.category == cat and e.message_key == f"mail.error.{cat}" and str(e) == cat
        assert has(e.message_key)
    assert MailError("something odd").category == "other"
    assert MailError("auth", host="smtp.secret.example").context == {"host": "smtp.secret.example"}


def test_categorize_exception():
    import smtplib
    import socket
    import ssl
    cases = [
        (smtplib.SMTPAuthenticationError(535, b"bad"), "auth"),
        (smtplib.SMTPRecipientsRefused({"a@b.c": (550, b"no")}), "recipient_rejected"),
        (socket.timeout(), "timeout"), (ssl.SSLError("x"), "tls"), (ConnectionRefusedError(), "connect"),
        (smtplib.SMTPServerDisconnected(), "connect"), (RuntimeError("boom"), "other"),
    ]
    for exc, cat in cases:
        assert mail.categorize_exception(exc) == cat


# ----- caps -------------------------------------------------------------------------------------------------------


class CountingMailer:
    def __init__(self):
        self.sent = []

    def send(self, message):
        self.sent.append(message)


def test_send_mail_delivers_and_records_status(db):
    mailer = CountingMailer()
    mail.send_mail(db, mailer, msg(), per_recipient_key="alice@tum.de")
    assert len(mailer.sent) == 1
    st = mail.get_status()
    assert st.last_ok_at is not None and st.last_failure_category is None and not st.cap_reached


def test_per_recipient_cap_blocks_before_backend(db):
    mailer = CountingMailer()
    for _ in range(mail.MAIL_MAX_PER_RECIPIENT_PER_HOUR):
        mail.send_mail(db, mailer, msg(), per_recipient_key="alice@tum.de")
    with pytest.raises(MailError) as exc:
        mail.send_mail(db, mailer, msg(), per_recipient_key="Alice@TUM.de")  # case-insensitive
    assert exc.value.category == "cap_exceeded" and exc.value.context["scope"] == "recipient"
    assert len(mailer.sent) == mail.MAIL_MAX_PER_RECIPIENT_PER_HOUR
    mail.send_mail(db, mailer, msg(to="bob@tum.de"), per_recipient_key="bob@tum.de")  # others unaffected
    assert len(mailer.sent) == mail.MAIL_MAX_PER_RECIPIENT_PER_HOUR + 1
    assert mail.get_status().last_failure_category == "cap_exceeded"


def test_global_cap_blocks_before_backend(db, monkeypatch):
    monkeypatch.setenv("MAIL_MAX_PER_HOUR", "3")
    reload_settings()
    mailer = CountingMailer()
    for i in range(3):
        a = f"user{i}@tum.de"
        mail.send_mail(db, mailer, msg(to=a), per_recipient_key=a)
    with pytest.raises(MailError) as exc:
        mail.send_mail(db, mailer, msg(to="user9@tum.de"), per_recipient_key="user9@tum.de")
    assert exc.value.category == "cap_exceeded" and exc.value.context["scope"] == "global"
    assert len(mailer.sent) == 3
    assert mail.get_status().cap_reached


def test_cap_window_expires(db):
    from datetime import timedelta

    from app.timeutil import utcnow
    mailer = CountingMailer()
    old = utcnow() - timedelta(hours=2)
    for _ in range(mail.MAIL_MAX_PER_RECIPIENT_PER_HOUR):
        mail.reserve_send(db, msg(), per_recipient_key="alice@tum.de", now=old)
    mail.send_mail(db, mailer, msg(), per_recipient_key="alice@tum.de")
    assert len(mailer.sent) == 1


def test_rate_limit_rows_never_hold_the_address(db):
    mail.send_mail(db, CountingMailer(), msg(to="alice@tum.de"), per_recipient_key="alice@tum.de")
    db.flush()
    rows = db.scalars(select(RateLimitEvent)).all()
    assert {r.bucket for r in rows} == {mail.BUCKET_GLOBAL, mail.BUCKET_RECIPIENT}
    for r in rows:
        assert "alice" not in r.key and "tum.de" not in r.key
    rcpt = next(r for r in rows if r.bucket == mail.BUCKET_RECIPIENT)
    assert rcpt.key == mail.recipient_bucket_key("ALICE@tum.de") and len(rcpt.key) == 64


def test_per_recipient_key_defaults_to_message_recipient(db):
    for _ in range(mail.MAIL_MAX_PER_RECIPIENT_PER_HOUR):
        mail.send_mail(db, CountingMailer(), msg())
    with pytest.raises(MailError):
        mail.send_mail(db, CountingMailer(), msg())


def test_backend_failure_is_categorised_and_recorded(db):
    class Failing:
        def send(self, message):
            raise ConnectionRefusedError("smtp.internal.example:587 password=hunter2")

    with pytest.raises(MailError) as exc:
        mail.send_mail(db, Failing(), msg(), per_recipient_key="alice@tum.de")
    assert exc.value.category == "connect" and "hunter2" not in str(exc.value) and exc.value.__cause__ is None
    st = mail.get_status()
    assert st.last_failure_category == "connect" and st.last_failure_at is not None


# ----- background helper ------------------------------------------------------------------------------------------


def test_send_in_background_sends_and_counts_in_db(engine):
    assert mail.send_in_background(msg(), "alice@tum.de") is None
    assert len(mail.get_outbox()) == 1
    with app_db.read_session() as s:
        assert len(s.scalars(select(RateLimitEvent)).all()) == 2


def test_send_in_background_never_raises_and_logs_no_secrets(engine, caplog):
    class Failing:
        def send(self, message):
            raise RuntimeError("password=hunter2 body=https://x/verify/TOKEN")

    with caplog.at_level(logging.DEBUG):
        assert mail.send_in_background(msg(body="https://x/verify/TOKEN"), "alice@tum.de", mailer=Failing()) == "other"
    assert "hunter2" not in caplog.text and "TOKEN" not in caplog.text and "alice@tum.de" not in caplog.text
    assert mail.get_status().last_failure_category == "other"


def test_send_in_background_cap_and_smtp_stub(engine, monkeypatch):
    for _ in range(mail.MAIL_MAX_PER_RECIPIENT_PER_HOUR):
        assert mail.send_in_background(msg(), "alice@tum.de") is None
    assert mail.send_in_background(msg(), "alice@tum.de") == "cap_exceeded"
    assert len(mail.get_outbox()) == mail.MAIL_MAX_PER_RECIPIENT_PER_HOUR
    monkeypatch.setenv("MAIL_BACKEND", "smtp")
    reload_settings()
    assert mail.send_in_background(msg(to="bob@tum.de"), "bob@tum.de") == "not_configured"


def test_send_in_background_runs_as_fastapi_background_task(engine):
    from fastapi import BackgroundTasks, FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()

    @app.post("/go")
    def go(tasks: BackgroundTasks):
        tasks.add_task(mail.send_in_background, msg(to="carol@tum.de"), "carol@tum.de")
        return {"ok": True}

    assert TestClient(app).post("/go").status_code == 200
    assert [m.to for m in mail.get_outbox()] == ["carol@tum.de"]


def test_status_cap_reached_clears_after_next_success():
    mail.record_failure("cap_exceeded")
    assert mail.get_status().cap_reached
    mail.record_success()
    assert not mail.get_status().cap_reached
    mail.record_failure("auth")
    assert not mail.get_status().cap_reached and mail.get_status().last_failure_category == "auth"
