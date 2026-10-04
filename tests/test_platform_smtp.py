"""SMTP backend protocol tests (task 2.2, PLAN-v2 section 7b layer 2).

A real `smtplib` client talks to a local `aiosmtpd` relay on random localhost ports. The relay's certificate is
generated on the fly (SAN = localhost) by a throwaway CA; tests trust that CA through the injectable
`mail.ssl_context_factory`. Production code never uses the injection. No network beyond 127.0.0.1."""
import datetime
import email
import logging
import socket
import ssl
import threading
import time
from email import policy

import pytest
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.services import mail, mail_credentials
from app.services.mail import MailError
from tests.conftest import reload_settings

LOGIN = "coffee@lrz.test"
PASSWORD = "Sm7p-Relay-Passw0rd-unique"
SENDER = "coffee@example.org"


# ----- certificates ---------------------------------------------------------------------------------------------


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _make_ca(cn: str):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(cn)).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False, key_agreement=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_leaf(ca_key, ca_cert, names: list[str]):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(_name(names[0])).issuer_name(ca_cert.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def _pem_cert(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture(scope="session")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    ca_key, ca_cert = _make_ca("Test Mail CA")
    other_key, other_cert = _make_ca("Unrelated CA")
    leaf_key, leaf_cert = _make_leaf(ca_key, ca_cert, ["localhost"])
    certfile, keyfile = d / "server.pem", d / "server.key"
    certfile.write_bytes(_pem_cert(leaf_cert))
    keyfile.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
    return {"ca_pem": _pem_cert(ca_cert).decode(), "other_ca_pem": _pem_cert(other_cert).decode(),
            "certfile": str(certfile), "keyfile": str(keyfile)}


# ----- fake relay -----------------------------------------------------------------------------------------------


class Relay:
    """Recording handler plus authenticator."""

    def __init__(self, reject_rcpt: bool = False):
        self.reject_rcpt = reject_rcpt
        self.messages = []
        self.sessions = []  # per delivered message: (TLS session?, authenticated?)
        self.auth_attempts = []

    def authenticator(self, server, session, envelope, mechanism, auth_data):
        if isinstance(auth_data, LoginPassword):
            self.auth_attempts.append((auth_data.login.decode(), auth_data.password.decode()))
            ok = auth_data.login.decode() == LOGIN and auth_data.password.decode() == PASSWORD
        else:
            self.auth_attempts.append(("?", "?"))
            ok = False
        return AuthResult(success=ok, handled=False)

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if self.reject_rcpt:
            return "550 5.1.1 mailbox unavailable"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        self.messages.append(envelope)
        tls = server.transport.get_extra_info("ssl_object") is not None or session.ssl is not None
        self.sessions.append((tls, bool(session.authenticated)))
        return "250 Message accepted"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def server_ctx(pki):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pki["certfile"], pki["keyfile"])
    return ctx


@pytest.fixture
def start_relay(server_ctx):
    """start_relay(mode="starttls"|"ssl"|"clear", **relay_kwargs) -> (relay, port)."""
    controllers = []

    def _start(mode="starttls", **relay_kwargs):
        relay = Relay(**relay_kwargs)
        port = free_port()
        kwargs = dict(authenticator=relay.authenticator)
        if mode == "starttls":
            kwargs.update(tls_context=server_ctx, require_starttls=True)
        elif mode == "ssl":
            kwargs.update(ssl_context=server_ctx, auth_require_tls=False)  # aiosmtpd does not count implicit TLS
        elif mode == "clear":  # offers AUTH in clear and no STARTTLS at all
            kwargs.update(auth_require_tls=False)
        controller = Controller(relay, hostname="127.0.0.1", port=port, ready_timeout=10, **kwargs)
        controller.start()
        controllers.append(controller)
        return relay, port

    yield _start
    for controller in controllers:
        controller.stop()


@pytest.fixture
def hang_server():
    """hang(greeting: bool) -> port. Accepts connections and then says nothing (after an optional 220)."""
    socks, conns = [], []

    def _start(greeting: bool):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        socks.append(srv)

        def loop():
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                conns.append(conn)
                if greeting:
                    conn.sendall(b"220 hello ESMTP\r\n")

        threading.Thread(target=loop, daemon=True).start()
        return srv.getsockname()[1]

    yield _start
    for s in socks + conns:
        try:
            s.close()
        except OSError:
            pass


@pytest.fixture
def smtp_env(tmp_path, monkeypatch, pki):
    """Production-like smtp backend, test CA trusted via the injection point, login stored."""
    monkeypatch.setenv("MAIL_BACKEND", "smtp")
    monkeypatch.setenv("MAIL_FROM", f"Coffee Ledger <{SENDER}>")
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path / "secrets"))
    monkeypatch.setenv("SMTP_HOST", "localhost")
    reload_settings()
    mail_credentials.save_credentials(LOGIN, PASSWORD)
    monkeypatch.setattr(mail, "ssl_context_factory", lambda: ssl.create_default_context(cadata=pki["ca_pem"]))
    mail.clear_outbox()
    mail.reset_status()
    yield
    mail.reset_status()


def configure(monkeypatch, *, port: int, security: str, host: str = "localhost"):
    monkeypatch.setenv("SMTP_PORT", str(port))
    monkeypatch.setenv("SMTP_SECURITY", security)
    monkeypatch.setenv("SMTP_HOST", host)
    reload_settings()


def message(to="alice@tum.de", body="Open https://coffee.example.org/verify/abc123 to confirm.", **kw):
    return mail.build_message(to=to, subject="Confirm your address", body=body, **kw)


def send(msg=None):
    mail.get_mailer().send(msg or message())


def parse(envelope):
    return email.message_from_bytes(envelope.content, policy=policy.default)


TRANSPORTS = ["starttls", "ssl"]


# ----- delivery -------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("security", TRANSPORTS)
def test_delivers_after_auth(smtp_env, start_relay, monkeypatch, security):
    relay, port = start_relay(security)
    configure(monkeypatch, port=port, security=security)
    send()
    assert relay.auth_attempts == [(LOGIN, PASSWORD)]
    assert len(relay.messages) == 1
    env = relay.messages[0]
    assert env.mail_from == SENDER and env.rcpt_tos == ["alice@tum.de"]
    assert relay.sessions == [(True, True)]  # delivered over TLS, on an authenticated session


@pytest.mark.parametrize("security", TRANSPORTS)
def test_delivered_message_content(smtp_env, start_relay, monkeypatch, security):
    relay, port = start_relay(security)
    configure(monkeypatch, port=port, security=security)
    send(message(to="alice@tum.de"))
    parsed = parse(relay.messages[0])
    assert parsed.get_content_type() == "text/plain" and not parsed.is_multipart()
    assert parsed["Auto-Submitted"] == "auto-generated"
    assert parsed["From"] == SENDER and parsed["To"] == "alice@tum.de"
    assert parsed["Subject"] == "Confirm your address"
    assert "https://coffee.example.org/verify/abc123" in parsed.get_content()
    assert parsed["Date"] and parsed["Message-ID"]
    # the login never travels inside a message
    assert PASSWORD.encode() not in relay.messages[0].content and LOGIN.encode() not in relay.messages[0].content


@pytest.mark.parametrize("security", TRANSPORTS)
def test_display_name_with_crlf_cannot_inject_headers(smtp_env, start_relay, monkeypatch, security):
    relay, port = start_relay(security)
    configure(monkeypatch, port=port, security=security)
    evil = "Bob\r\nBcc: evil@attacker.example\r\nX-Injected: yes"
    send(mail.build_message(to="bob@tum.de", subject="Hi\r\nBcc: evil2@attacker.example", body="text", to_name=evil))
    env = relay.messages[0]
    assert env.rcpt_tos == ["bob@tum.de"]  # no extra envelope recipient
    parsed = parse(env)
    assert parsed["Bcc"] is None and parsed["X-Injected"] is None
    assert "attacker.example" not in (parsed["Subject"] or "").split("Bcc")[0]
    raw_headers = env.content.split(b"\r\n\r\n", 1)[0]
    assert b"\nBcc:" not in raw_headers and b"\nX-Injected:" not in raw_headers


def test_hand_built_message_cannot_inject_headers(smtp_env, start_relay, monkeypatch):
    relay, port = start_relay("starttls")
    configure(monkeypatch, port=port, security="starttls")
    nasty = mail.MailMessage(to="bob@tum.de", subject="s", body="b",
                             headers={"To": "bob@tum.de", "X-Evil": "a\r\nBcc: evil@attacker.example"})
    send(nasty)
    parsed = parse(relay.messages[0])
    assert parsed["Bcc"] is None and relay.messages[0].rcpt_tos == ["bob@tum.de"]


# ----- authentication -------------------------------------------------------------------------------------------


@pytest.mark.parametrize("security", TRANSPORTS)
def test_wrong_password_is_category_auth_and_nothing_delivered(smtp_env, start_relay, monkeypatch, security):
    relay, port = start_relay(security)
    configure(monkeypatch, port=port, security=security)
    mail_credentials.save_credentials(LOGIN, "definitely-the-wrong-password")
    with pytest.raises(MailError) as exc:
        send()
    assert exc.value.category == "auth"
    assert relay.messages == []
    assert "wrong-password" not in str(exc.value) and "wrong-password" not in repr(exc.value)


def test_not_configured_makes_no_connection(smtp_env, start_relay, monkeypatch):
    relay, port = start_relay("starttls")
    configure(monkeypatch, port=port, security="starttls")
    mail_credentials.clear_credentials()
    with pytest.raises(MailError) as exc:
        send()
    assert exc.value.category == "not_configured"
    assert relay.auth_attempts == [] and relay.messages == []


# ----- verified TLS, no fallback --------------------------------------------------------------------------------


@pytest.mark.parametrize("security", TRANSPORTS)
def test_untrusted_certificate_is_refused(smtp_env, start_relay, monkeypatch, pki, security):
    relay, port = start_relay(security)
    configure(monkeypatch, port=port, security=security)
    monkeypatch.setattr(mail, "ssl_context_factory", lambda: ssl.create_default_context(cadata=pki["other_ca_pem"]))
    with pytest.raises(MailError) as exc:
        send()
    assert exc.value.category == "tls"
    assert relay.auth_attempts == [] and relay.messages == []  # no credentials, no fallback to a laxer mode


@pytest.mark.parametrize("security", TRANSPORTS)
def test_default_context_does_not_trust_the_test_ca(smtp_env, start_relay, monkeypatch, security):
    """Without the injection, the production default (system CA store) refuses the generated certificate."""
    relay, port = start_relay(security)
    configure(monkeypatch, port=port, security=security)
    monkeypatch.setattr(mail, "ssl_context_factory", None)
    with pytest.raises(MailError) as exc:
        send()
    assert exc.value.category == "tls"
    assert relay.auth_attempts == [] and relay.messages == []


@pytest.mark.parametrize("security", TRANSPORTS)
def test_hostname_mismatch_is_refused(smtp_env, start_relay, monkeypatch, security):
    """The certificate is valid and trusted but names `localhost`; connecting to 127.0.0.1 must fail."""
    relay, port = start_relay(security)
    configure(monkeypatch, port=port, security=security, host="127.0.0.1")
    with pytest.raises(MailError) as exc:
        send()
    assert exc.value.category == "tls"
    assert relay.auth_attempts == [] and relay.messages == []


@pytest.mark.parametrize("security", TRANSPORTS)
def test_auth_offered_only_in_clear_is_refused_and_credentials_never_sent(smtp_env, start_relay, monkeypatch, security):
    relay, port = start_relay("clear")  # advertises AUTH on a plaintext channel, no STARTTLS, no TLS port
    configure(monkeypatch, port=port, security=security)
    with pytest.raises(MailError) as exc:
        send()
    assert exc.value.category == "tls"
    assert relay.auth_attempts == [] and relay.messages == []


def test_server_without_starttls_extension_is_refused(smtp_env, start_relay, monkeypatch):
    relay, port = start_relay("clear")
    configure(monkeypatch, port=port, security="starttls")
    with pytest.raises(MailError) as exc:
        send()
    assert exc.value.category == "tls" and relay.auth_attempts == []


def test_default_context_settings():
    ctx = mail.default_ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_default_factory_is_unset_in_production_code():
    assert mail.ssl_context_factory is None  # tests set it through monkeypatch only


@pytest.mark.parametrize("security", TRANSPORTS)
def test_context_without_verification_is_refused_even_if_injected(smtp_env, start_relay, monkeypatch, security):
    relay, port = start_relay(security)
    configure(monkeypatch, port=port, security=security)

    def lax():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    monkeypatch.setattr(mail, "ssl_context_factory", lax)
    with pytest.raises(MailError) as exc:
        send()
    assert exc.value.category == "tls"
    assert relay.auth_attempts == [] and relay.messages == []

    def no_hostname_check():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        return ctx

    monkeypatch.setattr(mail, "ssl_context_factory", no_hostname_check)
    with pytest.raises(MailError) as exc:
        send()
    assert exc.value.category == "tls" and relay.messages == []


# ----- recipients, connection problems, timeouts ----------------------------------------------------------------


@pytest.mark.parametrize("security", TRANSPORTS)
def test_recipient_rejection_550(smtp_env, start_relay, monkeypatch, security):
    relay, port = start_relay(security, reject_rcpt=True)
    configure(monkeypatch, port=port, security=security)
    with pytest.raises(MailError) as exc:
        send()
    assert exc.value.category == "recipient_rejected"
    assert relay.messages == []
    assert "alice@tum.de" not in str(exc.value) and "mailbox" not in str(exc.value)


@pytest.mark.parametrize("security", TRANSPORTS)
def test_connection_refused(smtp_env, monkeypatch, security):
    configure(monkeypatch, port=free_port(), security=security, host="127.0.0.1")
    with pytest.raises(MailError) as exc:
        send()
    assert exc.value.category == "connect"


@pytest.mark.parametrize("security", TRANSPORTS)
def test_silent_server_times_out_on_connect(smtp_env, hang_server, monkeypatch, security):
    monkeypatch.setattr(mail, "SMTP_CONNECT_TIMEOUT", 0.5)
    monkeypatch.setattr(mail, "SMTP_TOTAL_TIMEOUT", 2.0)
    configure(monkeypatch, port=hang_server(greeting=False), security=security, host="127.0.0.1")
    started = time.monotonic()
    with pytest.raises(MailError) as exc:
        send()
    assert exc.value.category == "timeout"
    assert time.monotonic() - started < 5


def test_server_that_stops_answering_after_the_greeting_times_out(smtp_env, hang_server, monkeypatch):
    monkeypatch.setattr(mail, "SMTP_CONNECT_TIMEOUT", 1.0)
    monkeypatch.setattr(mail, "SMTP_TOTAL_TIMEOUT", 1.0)
    configure(monkeypatch, port=hang_server(greeting=True), security="starttls", host="127.0.0.1")
    started = time.monotonic()
    with pytest.raises(MailError) as exc:
        send()
    assert exc.value.category == "timeout"
    assert time.monotonic() - started < 5


def test_default_timeouts_are_bounded():
    assert 0 < mail.SMTP_CONNECT_TIMEOUT <= 10 and 0 < mail.SMTP_TOTAL_TIMEOUT <= 20


# ----- status is recorded outside the backend; no secrets in logs -----------------------------------------------


def test_backend_does_not_record_status_but_the_delivery_path_does_once(smtp_env, start_relay, monkeypatch):
    relay, port = start_relay("starttls")
    configure(monkeypatch, port=port, security="starttls")
    send()
    assert mail.get_status().last_ok_at is None and mail.get_status().last_failure_category is None
    mail._deliver(mail.get_mailer(), message())
    assert mail.get_status().last_ok_at is not None and len(relay.messages) == 2
    mail_credentials.save_credentials(LOGIN, "wrong-again-wrong")
    with pytest.raises(MailError) as exc:
        mail._deliver(mail.get_mailer(), message())
    assert exc.value.category == "auth" and mail.get_status().last_failure_category == "auth"


def test_send_in_background_end_to_end_and_no_secret_in_logs(smtp_env, start_relay, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    relay, port = start_relay("ssl")
    configure(monkeypatch, port=port, security="ssl")
    assert mail.send_in_background(message()) is None
    assert len(relay.messages) == 1 and mail.get_status().last_ok_at is not None
    mail_credentials.save_credentials(LOGIN, PASSWORD + "-changed")
    assert mail.send_in_background(message(to="carol@tum.de")) == "auth"
    assert mail.get_status().last_failure_category == "auth"
    ours = "\n".join(r.getMessage() for r in caplog.records if r.name.startswith("app."))  # not the relay's own log
    assert "mail not sent: auth" in ours
    assert PASSWORD not in ours and LOGIN not in ours and "alice@tum.de" not in ours and "carol@tum.de" not in ours


def test_smtp_failures_do_not_leak_server_text_or_chain(smtp_env, start_relay, monkeypatch):
    relay, port = start_relay("starttls", reject_rcpt=True)
    configure(monkeypatch, port=port, security="starttls")
    with pytest.raises(MailError) as exc:
        send()
    assert exc.value.__cause__ is None and exc.value.__suppress_context__
    assert str(exc.value) == "recipient_rejected"
