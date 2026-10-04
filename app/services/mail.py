"""Outgoing mail: the `Mailer` interface, backends, caps and the background-send helper.

Everything that sends mail goes through here (PLAN-v2 section 1 "Mail through the admin's account", 7b).

* `MailMessage` / `build_message`: plain text only. `From` is `MAIL_FROM`, `Auto-Submitted: auto-generated`.
  Header values are stripped of CR, LF and every other control character; no user-controlled text reaches a
  header except an optional recipient display name (stripped the same way). Subjects built by
  `mail_templates` are static anyway.
* Backends (`MAIL_BACKEND`): `memory` (tests; module-level outbox), `console` (logs recipient and subject
  only, never the body, because bodies contain one-time links), `file` (one `.eml` per message, dev/e2e only),
  `smtp` (task 2.2; here only a stub raising `MailError("not_configured")`). Production refuses all but smtp.
* Caps: `reserve_send` / `send_mail` enforce `MAIL_MAX_PER_HOUR` globally and 6 per hour per recipient with the
  DB-backed limiter, BEFORE the backend is reached. Addresses are never stored in `rate_limit_events`: the
  bucket key is an HMAC of the lower-cased address. A send that passed the caps counts even if the backend
  then fails (protects the mailbox from retry storms).
* `send_in_background(...)`: sync function for FastAPI `BackgroundTasks`, run after the request's commit. It
  opens its own short write session for the caps, closes it, and only then talks to the backend (a slow SMTP
  server must not hold the SQLite write lock). It never raises; failures are categorised and logged without
  credentials or bodies.
* `get_status()`: last send OK / last failure category and time, in memory (not persisted), for the admin page.

Services never commit: `send_mail` / `reserve_send` only add rate-limit rows to the caller's session.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import smtplib
import socket
import ssl
import threading
import time
import unicodedata
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from email.message import EmailMessage
from email.policy import SMTP as SMTP_POLICY
from email.utils import formataddr, formatdate, make_msgid, parseaddr
from pathlib import Path
from typing import Callable, Protocol

from sqlalchemy.orm import Session

from app.config import get_settings
from app.services import keys, ratelimit
from app.services.errors import InvalidInput, ServiceError
from app.timeutil import utcnow

log = logging.getLogger("app.mail")

CATEGORIES = ("connect", "tls", "auth", "recipient_rejected", "timeout", "not_configured", "cap_exceeded", "other")
MAIL_MAX_PER_RECIPIENT_PER_HOUR = 6
HOUR_SECONDS = 3600
BUCKET_GLOBAL = "mail_global"
BUCKET_RECIPIENT = "mail_rcpt"
MAX_SUBJECT_LENGTH = 200
MAX_NAME_LENGTH = 100
FALLBACK_FROM = "noreply@localhost"

_ADDRESS_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_LINK_RE = re.compile(r"https?://[^\s<>\"']+")
_WHITESPACE_CONTROLS = "\r\n\t\x0b\x0c\x85  "


# ----- errors ---------------------------------------------------------------------------------------------------


class MailError(ServiceError):
    """A mail could not be sent. `category` is one of `CATEGORIES`; `message_key` is a safe user-facing string
    key (`mail.error.<category>`). The exception text is the category only: never an address, host or secret."""

    code = "mail_error"

    def __init__(self, category: str = "other", **context):
        if category not in CATEGORIES:
            category = "other"
        super().__init__(category, **context)
        self.category = category

    @property
    def message_key(self) -> str:
        return f"mail.error.{self.category}"


# ----- message --------------------------------------------------------------------------------------------------


@dataclass
class MailMessage:
    to: str
    subject: str
    body: str
    headers: dict[str, str] = field(default_factory=dict)  # extra header lines (From, To, Auto-Submitted, ...)


class Mailer(Protocol):
    def send(self, message: MailMessage) -> None:
        """Deliver one message or raise `MailError`."""


def _is_control(ch: str) -> bool:
    return unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") or ch == "\x85"


def clean_header_text(text: str, max_length: int = MAX_SUBJECT_LENGTH) -> str:
    """Single-line, control-free text safe for a header value (also used for names shown inside bodies):
    line breaks and tabs become spaces, every other control/format character is dropped."""
    out = []
    for ch in str(text if text is not None else ""):
        if ch in _WHITESPACE_CONTROLS:
            out.append(" ")
        elif not _is_control(ch):
            out.append(ch)
    return " ".join("".join(out).split())[:max_length].strip()


def clean_body(text: str) -> str:
    """Body text: keep newlines and tabs, drop every other control/format character, normalise line ends."""
    text = str(text).replace("\r\n", "\n").replace("\r", "\n").replace(" ", "\n").replace(" ", "\n")
    return "".join(ch for ch in text if ch in "\n\t" or not _is_control(ch))


def normalize_address(address: str) -> str:
    """Validate a plain `local@domain` address and return it lower-cased; anything else raises InvalidInput."""
    address = (address or "").strip()
    if not _ADDRESS_RE.match(address) or ".." in address:
        raise InvalidInput("invalid mail address", field="to")
    return address.lower()


def sender_address() -> str:
    """The sender: MAIL_FROM's address part (a development fallback when unset or unusable)."""
    configured = parseaddr(get_settings().mail_from or "")[1]
    try:
        return normalize_address(configured) if configured else FALLBACK_FROM
    except InvalidInput:
        return FALLBACK_FROM


def build_message(*, to: str, subject: str, body: str, to_name: str | None = None) -> MailMessage:
    """Plain-text message with safe headers. Only `to_name` (stripped of control characters) may carry
    user-controlled text into a header; callers should normally leave it unset."""
    address = normalize_address(to)
    name = clean_header_text(to_name, MAX_NAME_LENGTH) if to_name else ""
    headers = {
        "From": sender_address(),
        "To": formataddr((name, address)) if name else address,
        "Auto-Submitted": "auto-generated",
    }
    return MailMessage(to=address, subject=clean_header_text(subject), body=clean_body(body), headers=headers)


_RESERVED_HEADERS = {"subject", "date", "message-id", "content-type", "mime-version", "content-transfer-encoding"}


def to_email_message(message: MailMessage) -> EmailMessage:
    """RFC 5322 representation (file backend; smtp in task 2.2). Header values are re-sanitised here, so a
    hand-built `MailMessage` cannot inject headers either."""
    msg = EmailMessage(policy=SMTP_POLICY)
    for name, value in message.headers.items():
        if name.lower() in _RESERVED_HEADERS or not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,40}", name):
            continue
        msg[name] = clean_header_text(value, 400)
    if "To" not in msg:
        msg["To"] = normalize_address(message.to)
    if "From" not in msg:
        msg["From"] = sender_address()
    msg["Subject"] = clean_header_text(message.subject)
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=sender_address().rpartition("@")[2] or "localhost")
    msg.set_content(clean_body(message.body), charset="utf-8")
    return msg


def extract_links(message: MailMessage) -> list[str]:
    """http(s) links in the body, in order (trailing sentence punctuation removed)."""
    return [m.rstrip(".,;:!?)") for m in _LINK_RE.findall(message.body)]


# ----- status (what the admin page shows) ----------------------------------------------------------------------


@dataclass(frozen=True)
class MailStatus:
    last_ok_at: datetime | None = None
    last_failure_category: str | None = None
    last_failure_at: datetime | None = None

    @property
    def cap_reached(self) -> bool:
        """True when the most recent failure was the hourly cap and no send succeeded after it (the page says
        "cap reached", not "mail broken")."""
        if self.last_failure_category != "cap_exceeded":
            return False
        return self.last_ok_at is None or self.last_failure_at >= self.last_ok_at


_status_lock = threading.Lock()
_status = MailStatus()


def get_status() -> MailStatus:
    with _status_lock:
        return _status


def record_success(now: datetime | None = None) -> None:
    global _status
    with _status_lock:
        _status = MailStatus(last_ok_at=now or utcnow(), last_failure_category=_status.last_failure_category,
                             last_failure_at=_status.last_failure_at)


def record_failure(category: str, now: datetime | None = None) -> None:
    global _status
    category = category if category in CATEGORIES else "other"
    with _status_lock:
        _status = MailStatus(last_ok_at=_status.last_ok_at, last_failure_category=category,
                             last_failure_at=now or utcnow())


def reset_status() -> None:
    global _status
    with _status_lock:
        _status = MailStatus()


# ----- backends -------------------------------------------------------------------------------------------------

_outbox: list[MailMessage] = []
_outbox_lock = threading.Lock()


def get_outbox() -> list[MailMessage]:
    with _outbox_lock:
        return list(_outbox)


def clear_outbox() -> None:
    with _outbox_lock:
        _outbox.clear()


class MemoryMailer:
    """Tests: appends to the module-level outbox."""

    def send(self, message: MailMessage) -> None:
        with _outbox_lock:
            _outbox.append(message)


class ConsoleMailer:
    """Development: logs recipient and subject only. Bodies carry one-time links and are never logged."""

    def send(self, message: MailMessage) -> None:
        log.info("mail (console backend) to=%s subject=%s", message.to, message.subject)


class FileMailer:
    """Development and e2e only: one `.eml` per message in MAIL_FILE_DIR (directory 0700, files 0600)."""

    def __init__(self, directory: str | None = None):
        self.directory = directory if directory is not None else get_settings().mail_file_dir

    def send(self, message: MailMessage) -> None:
        if not self.directory:
            raise MailError("not_configured")
        try:
            path = Path(self.directory)
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            name = f"{utcnow().strftime('%Y%m%dT%H%M%S%f')}-{uuid.uuid4().hex[:8]}.eml"
            fd = os.open(path / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(to_email_message(message).as_bytes())
        except OSError as exc:
            raise MailError("other") from exc


# ----- smtp backend (task 2.2) ----------------------------------------------------------------------------------

SMTP_CONNECT_TIMEOUT = 10.0  # seconds for connect (and the implicit-TLS handshake)
SMTP_TOTAL_TIMEOUT = 20.0  # seconds for the whole send, after which the connection is cut

ssl_context_factory: Callable[[], ssl.SSLContext] | None = None  # tests only: trust a generated test CA


def default_ssl_context() -> ssl.SSLContext:
    """Production TLS context: system CA store, certificate chain AND hostname verified, TLS 1.2 minimum."""
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _client_ssl_context() -> ssl.SSLContext:
    """The injectable factory's context (tests) or the default one. A context that does not verify the
    certificate and hostname is refused whatever its origin: there is no way to switch verification off."""
    context = (ssl_context_factory or default_ssl_context)()
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise MailError("tls")
    return context


def _ehlo_name() -> str:
    domain = sender_address().rpartition("@")[2]
    return domain if "." in domain else "localhost"


def _category_for(exc: BaseException, stage: str) -> str:
    """Category of a transport failure. Looks through the exception chain (smtplib wraps socket errors), so a
    socket timeout reads as `timeout` and a certificate problem as `tls` wherever it surfaced."""
    chain, seen = [], set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        chain.append(cur)
        cur = cur.__cause__ or cur.__context__
    if any(isinstance(e, (socket.timeout, TimeoutError)) for e in chain):
        return "timeout"
    if any(isinstance(e, (ssl.SSLError, ssl.CertificateError)) for e in chain):
        return "tls"
    if isinstance(exc, smtplib.SMTPNotSupportedError) and stage == "auth":
        return "auth"
    category = categorize_exception(exc)
    if category == "other":
        if stage == "starttls":
            return "tls"
        if stage == "connect" and isinstance(exc, OSError):
            return "connect"
    return category


class SmtpMailer:
    """Sends through the configured relay with the stored login (`mail_credentials`), read per send.

    * `starttls` (port 587): connect in clear, require the STARTTLS extension, upgrade with a verifying
      context, EHLO again. `ssl` (port 465): implicit TLS from the first byte.
    * AUTH is attempted only on an encrypted channel; a server that cannot encrypt gets no credentials and the
      send fails with category `tls` (no plaintext fallback, no way to turn verification off).
    * Timeouts: connect `SMTP_CONNECT_TIMEOUT`, whole send `SMTP_TOTAL_TIMEOUT` (a watchdog cuts the socket).
    * Failures raise `MailError(category)` only (`from None`: server text can echo addresses). The login is
      never logged and `smtplib` debug output (which would print AUTH data) is never enabled.
    * Success/failure status is recorded by the caller (`_deliver`), not here.
    """

    def send(self, message: MailMessage) -> None:
        from app.services import mail_credentials  # lazy: mail_credentials imports MailError from this module

        credentials = mail_credentials.load_credentials()  # not_configured / unreadable raise MailError
        email_message = to_email_message(message)
        settings = get_settings()
        context = _client_ssl_context()
        deadline = time.monotonic() + SMTP_TOTAL_TIMEOUT
        state: dict = {"client": None, "expired": False}

        def cut() -> None:
            state["expired"] = True
            sock = getattr(state["client"], "sock", None)
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    sock.close()
                except OSError:
                    pass

        watchdog = threading.Timer(SMTP_TOTAL_TIMEOUT, cut)
        watchdog.daemon = True
        watchdog.start()
        stage = "connect"
        try:
            host, port, name = settings.smtp_host, settings.smtp_port, _ehlo_name()
            if settings.smtp_security == "ssl":
                client = smtplib.SMTP_SSL(host, port, local_hostname=name, timeout=SMTP_CONNECT_TIMEOUT,
                                          context=context)
            else:
                client = smtplib.SMTP(host, port, local_hostname=name, timeout=SMTP_CONNECT_TIMEOUT)
            state["client"] = client
            try:

                def step_timeout() -> None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError
                    if client.sock is not None:
                        client.sock.settimeout(remaining)

                step_timeout()
                stage = "ehlo"
                client.ehlo()
                if settings.smtp_security != "ssl":
                    stage = "starttls"
                    if not client.has_extn("starttls"):
                        raise MailError("tls")
                    step_timeout()
                    client.starttls(context=context)
                    step_timeout()
                    client.ehlo()
                stage = "auth"
                if not isinstance(client.sock, ssl.SSLSocket):
                    raise MailError("tls")  # never send credentials over an unencrypted channel
                step_timeout()
                client.login(credentials.username, credentials.password)
                stage = "send"
                step_timeout()
                client.send_message(email_message, from_addr=sender_address(), to_addrs=[message.to])
                try:
                    client.quit()
                except (smtplib.SMTPException, OSError):
                    pass  # the message is accepted; a rough goodbye does not matter
            finally:
                try:
                    client.close()
                except Exception:
                    pass
        except MailError:
            raise
        except Exception as exc:
            category = "timeout" if state["expired"] else _category_for(exc, stage)
            log.debug("smtp send failed: %s (%s)", category, stage)
            raise MailError(category) from None
        finally:
            watchdog.cancel()


# Factory slot per backend name.
BACKENDS: dict[str, Callable[[], Mailer]] = {
    "smtp": SmtpMailer,
    "console": ConsoleMailer,
    "memory": MemoryMailer,
    "file": FileMailer,
}


def get_mailer() -> Mailer:
    """The backend named by MAIL_BACKEND; production only ever gets `smtp`."""
    settings = get_settings()
    name = settings.mail_backend or ("smtp" if settings.is_production else "console")
    if settings.is_production and name != "smtp":
        raise MailError("not_configured")
    factory = BACKENDS.get(name)
    if factory is None:
        raise MailError("not_configured")
    return factory()


def categorize_exception(exc: BaseException) -> str:
    """Map a transport exception to a safe category (the exception text is never kept). For the smtp backend."""
    if isinstance(exc, MailError):
        return exc.category
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "auth"
    if isinstance(exc, (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused)):
        return "recipient_rejected"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, (ssl.SSLError, ssl.CertificateError)):
        return "tls"
    if isinstance(exc, (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected, ConnectionError)):
        return "connect"
    return "other"


# ----- caps and sending -----------------------------------------------------------------------------------------


def recipient_bucket_key(address: str) -> str:
    """Rate-limit key for an address: HMAC of the lower-cased address, so rate_limit_events never holds it."""
    return hmac.new(keys.derive_key("mail-recipient-rate"), (address or "").strip().lower().encode("utf-8"),
                    hashlib.sha256).hexdigest()


def reserve_send(db: Session, message: MailMessage, *, per_recipient_key: str | None = None,
                 now: datetime | None = None) -> None:
    """Check both caps and, if both allow it, count this send. Raises `MailError("cap_exceeded")` (recording
    nothing) otherwise. Does not commit; the caller's transaction makes the counts durable."""
    settings = get_settings()
    recipient_key = recipient_bucket_key(per_recipient_key if per_recipient_key is not None else message.to)
    if ratelimit.is_limited(db, BUCKET_GLOBAL, "all", settings.mail_max_per_hour, HOUR_SECONDS, now):
        raise MailError("cap_exceeded", scope="global")
    if ratelimit.is_limited(db, BUCKET_RECIPIENT, recipient_key, MAIL_MAX_PER_RECIPIENT_PER_HOUR, HOUR_SECONDS, now):
        raise MailError("cap_exceeded", scope="recipient")
    ratelimit.record_hit(db, BUCKET_GLOBAL, "all", now)
    ratelimit.record_hit(db, BUCKET_RECIPIENT, recipient_key, now)


def _deliver(mailer: Mailer, message: MailMessage) -> None:
    try:
        mailer.send(message)
    except MailError as exc:
        record_failure(exc.category)
        raise
    except Exception as exc:  # backend bug or transport error: categorise and drop the text
        category = categorize_exception(exc)
        record_failure(category)
        raise MailError(category) from None
    record_success()


def send_mail(db: Session, mailer: Mailer, message: MailMessage, *, per_recipient_key: str | None = None) -> None:
    """Caps first (`cap_exceeded` never reaches the backend), then the backend. `per_recipient_key` is the
    address the per-recipient cap applies to (default: the message's recipient). Does not commit. The caller's
    transaction stays open during the send, so web code should use `send_in_background` instead."""
    try:
        reserve_send(db, message, per_recipient_key=per_recipient_key)
    except MailError as exc:
        record_failure(exc.category)
        raise
    _deliver(mailer, message)


def send_in_background(message: MailMessage, per_recipient_key: str | None = None, *,
                       mailer: Mailer | None = None) -> str | None:
    """For `BackgroundTasks.add_task(send_in_background, message, key)` after the request's commit. Never raises.
    Returns None on success or the failure category. Logs the category only (no address, body or credential)."""
    from app.db import write_session

    try:
        with write_session() as db:
            reserve_send(db, message, per_recipient_key=per_recipient_key)
    except MailError as exc:
        record_failure(exc.category)
        log.warning("mail not sent: %s", exc.category)
        return exc.category
    except Exception:
        record_failure("other")
        log.warning("mail not sent: other (cap bookkeeping failed)")
        return "other"
    try:
        _deliver(mailer if mailer is not None else get_mailer(), message)
    except MailError as exc:
        record_failure(exc.category)  # also covers get_mailer() refusing (e.g. non-smtp in production)
        log.warning("mail not sent: %s", exc.category)
        return exc.category
    except Exception:
        record_failure("other")
        log.warning("mail not sent: other")
        return "other"
    return None
