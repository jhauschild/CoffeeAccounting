"""Local fake TLS SMTP relay for the acceptance run (same idea as tests/test_platform_smtp.py: aiosmtpd, STARTTLS,
AUTH only after TLS). It stands in for postout.lrz.de on loopback.

    python docs/status/repro/fake_relay.py --port 19587 --cert cert.pem --key key.pem --dir relay/ \
        --user svc-coffee@lrz.de --password 'the-mail-password'

Writes DIR/messages/NNNN.eml for every accepted message, DIR/logins.jsonl (one line per AUTH attempt: user,
whether the password matched, whether the channel was encrypted) and DIR/ready when listening. If DIR/mode
contains `reject-auth` every login is refused (535), so the application's failure category `auth` can be seen.
Runs until SIGTERM. The certificate is trusted by the application through SSL_CERT_FILE (the operating-system
trust-store mechanism of OpenSSL); no application code is changed or bypassed.
"""

from __future__ import annotations

import argparse
import json
import signal
import ssl
import threading
import time
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ns = ap.parse_args()

    from aiosmtpd.controller import Controller
    from aiosmtpd.smtp import AuthResult, LoginPassword

    d = Path(ns.dir)
    (d / "messages").mkdir(parents=True, exist_ok=True)
    lock = threading.Lock()
    counter = {"n": len(list((d / "messages").glob("*.eml")))}

    class Handler:
        async def handle_DATA(self, server, session, envelope):  # noqa: N802 (aiosmtpd API)
            with lock:
                counter["n"] += 1
                body = f"X-Envelope-From: {envelope.mail_from}\nX-Envelope-To: {', '.join(envelope.rcpt_tos)}\n"
                (d / "messages" / f"{counter['n']:04d}.eml").write_bytes(body.encode() + envelope.content)
            return "250 OK queued"

    def authenticator(server, session, envelope, mechanism, auth_data):
        if not isinstance(auth_data, LoginPassword):
            return AuthResult(success=False, handled=False)
        user, pw = auth_data.login.decode(), auth_data.password.decode()
        reject = (d / "mode").exists() and "reject-auth" in (d / "mode").read_text()
        ok = user == ns.user and pw == ns.password and not reject
        with lock, open(d / "logins.jsonl", "a") as fh:
            fh.write(json.dumps({"user": user, "password_ok": pw == ns.password, "accepted": ok,
                                 "tls": session.ssl is not None}) + "\n")
        return AuthResult(success=True) if ok else AuthResult(success=False, handled=False)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(ns.cert, ns.key)
    ctrl = Controller(Handler(), hostname="127.0.0.1", port=ns.port, tls_context=ctx, require_starttls=True,
                      authenticator=authenticator, auth_required=True, auth_require_tls=True)
    ctrl.start()
    (d / "ready").write_text("ok")
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    while not stop.is_set():
        time.sleep(0.2)
    ctrl.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
