"""Final audit (task 7.2): does a FAILING mail login (wrong password, refused TLS, refused recipient) leak the
stored mail password or SECRET_KEY into CLI output, `mail-status`, the application log or an HTTP response?

    python docs/status/repro/mail_failure_probe.py [WORKDIR]

Re-uses the planted secrets and the self-signed certificate set-up of prod_instance.py. Three failure modes:
(1) the SMTP server rejects the login, (2) the server certificate is not trusted (no SSL_CERT_FILE), (3) the
server is down. For each: `app.cli test-mail`, `app.cli mail-status`, and a registration over HTTPS whose mail
cannot be sent. Exit code 0 only when no output contains a planted secret and no HTTP answer is a 5xx.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

W = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(tempfile.mkdtemp(prefix="mail-fail-"))
sys.argv = [sys.argv[0], str(W)]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import prod_instance as P  # noqa: E402

failures = []


def leak_check(label, blob):
    bad = [n for n in (P.MAIL_PASSWORD, P.SECRET_KEY, P.USER_PASSWORD, P.HEAD_PASSWORD) if n in blob]
    print(("FAIL " if bad else "PASS ") + f"{label}: no planted secret in output" + (" (LEAK)" if bad else ""))
    if bad:
        failures.append(label)


def main():
    P.setup()
    P.run([P.PY, "-c", "from app.db import write_session; from app.models import Chair\n"
           "with write_session() as w:\n    w.add(Chair(short_name='ALPHA', full_name='Chair of Alpha', active=True))"])
    smtp, inbox = P.start_smtp()
    proc = P.start_app()
    try:
        c = P.Client("anon", "10.50.0.1")
        for mode in ("login rejected", "untrusted certificate", "server down"):
            env = dict(P.ENV)
            if mode == "login rejected":
                P.MAIL_PASSWORD_BACKUP = P.MAIL_PASSWORD
                # store a different password than the server accepts
                P.run([P.PY, "-m", "app.cli", "setup-mail", "--username", P.MAIL_USER, "--password-stdin"],
                      stdin="PLANTED-WRONG-MAIL-PASSWORD-zzz9\n")
                P.MAIL_PASSWORD_WRONG = "PLANTED-WRONG-MAIL-PASSWORD-zzz9"
            elif mode == "untrusted certificate":
                P.run([P.PY, "-m", "app.cli", "setup-mail", "--username", P.MAIL_USER, "--password-stdin"],
                      stdin=P.MAIL_PASSWORD + "\n")
                env.pop("SSL_CERT_FILE", None)
            else:
                smtp.stop()
            out = subprocess.run([P.PY, "-m", "app.cli", "test-mail", "someone@tum.de"], env=env, cwd=P.ROOT,
                                 capture_output=True, text=True)
            blob = out.stdout + out.stderr
            print(f"[{mode}] test-mail exit={out.returncode}: {re.sub(chr(10), ' | ', blob.strip())[:200]}")
            leak_check(f"{mode}: test-mail output", blob + P.__dict__.get("MAIL_PASSWORD_WRONG", ""))
            if P.__dict__.get("MAIL_PASSWORD_WRONG") and P.MAIL_PASSWORD_WRONG in blob:
                failures.append("wrong password echoed")
            out = subprocess.run([P.PY, "-m", "app.cli", "mail-status"], env=env, cwd=P.ROOT, capture_output=True, text=True)
            print(f"[{mode}] mail-status: {re.sub(chr(10), ' | ', (out.stdout + out.stderr).strip())[:240]}")
            leak_check(f"{mode}: mail-status output", out.stdout + out.stderr)
            if "PLANTED-WRONG" in (out.stdout + out.stderr):
                failures.append("wrong password in mail-status")
        # the running app still uses the credential it read (server is down now): a registration must answer without 5xx
        pg = c.get("/register")
        chairs = P.chairs_from(pg.text)
        r = None
        if chairs:
            r = c.post("/register", {"csrf_token": P.field(pg.text, "csrf_token"), "username": "failmail", "display_name": "Fail Mail",
                                     "chair_id": next(iter(chairs.values())), "email": "failmail@tum.de",
                                     "password": P.USER_PASSWORD, "password2": P.USER_PASSWORD, "privacy_ack": "1"})
        else:
            print("INFO no chairs yet: registration probe skipped")
        if r is not None:
            time.sleep(3)
            print(f"[server down] registration over HTTPS: {r.status_code}")
            leak_check("registration answer", r.text)
            if r.status_code >= 500:
                failures.append("5xx on mail failure")
    finally:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(5)
        try:
            smtp.stop()
        except Exception:  # noqa: BLE001
            pass
    log = P.LOG.read_text(errors="replace")
    leak_check("application log", log + "")
    for needle in ("PLANTED-WRONG-MAIL-PASSWORD-zzz9",):
        if needle in log:
            failures.append("wrong password in log")
            print("FAIL wrong mail password found in the application log")
    print("log lines mentioning mail:", [l[:160] for l in log.splitlines() if "mail" in l.lower()][:6])
    print("RESULT:", "OK" if not failures else f"FAILED {failures}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
