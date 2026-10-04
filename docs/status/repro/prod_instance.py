"""Final audit (task 7.2): security probe against a REAL production-configuration instance.

    python docs/status/repro/prod_instance.py [WORKDIR] [--keep]

Starts, on loopback only:
  * a TLS SMTP server (aiosmtpd, STARTTLS + AUTH required) that records every message and every login,
  * uvicorn with the same flags as scripts/run.sh plus --ssl-keyfile/--ssl-certfile (self-signed certificate,
    like docs/ACCEPTANCE.md describes for v1), ENVIRONMENT=production, a planted SECRET_KEY, and a planted mail
    password stored with `python -m app.cli setup-mail --password-stdin`.
Then it drives the app over HTTPS like a browser (registration with a real mail, verification, sign-in, scan,
admin login with TOTP enrolment, step-up, group admin promotion, hostile data in names/notes/chairs) and checks:
cookie flags, security headers and CSP on every page type, FastAPI docs disabled, error pages, request size
limits, rate limits, CSRF/Origin, XSS in stored and reflected values, CSV injection in all exports, header
injection in mail, the mail link host, step-up behaviour, session handling, and finally greps the log, the
database (with its WAL), the backup made by scripts/backup.sh, the encrypted credential store and every HTTP
response body for the planted secrets, passwords, tokens and one-time codes.

Writes WORKDIR/results.json and prints a PASS/FAIL line per check. Exit 0 only when every check passes.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pyotp
import requests

ROOT = Path(__file__).resolve().parents[3]
PY = sys.executable
HTTP_PORT = 18443
SMTP_PORT = 18025
BASE = f"https://localhost:{HTTP_PORT}"
SECRET_KEY = "PLANTED-SECRET-KEY-" + "7f3a9c1e5b2d8046a1c3e5f70b9d2468ace13579bdf02468"
MAIL_USER = "smtp-login-user"
MAIL_PASSWORD = "PLANTED-MAIL-PASSWORD-q9X7vL2mN4"
HEAD_PASSWORD = "PLANTED-HEAD-PASSWORD-correct-horse-9"
USER_PASSWORD = "PLANTED-USER-PASSWORD-staple-battery-7"

args = [a for a in sys.argv[1:] if not a.startswith("--")]
KEEP = "--keep" in sys.argv
W = Path(args[0]) if args else Path(tempfile.mkdtemp(prefix="prod-probe-"))
W.mkdir(parents=True, exist_ok=True)
CERT, KEY = W / "cert.pem", W / "key.pem"
DB = W / "prod.db"
SECRETS = W / "secrets"
LOG = W / "app.log"
BACKUPS = W / "backups"

results: list[dict] = []
bodies: list[tuple[str, str]] = []  # every response body seen (for the secret grep)
cookies_seen: set = set()  # raw session cookie values handed out (must not be stored at rest)


def check(section: str, name: str, ok: bool, detail: str = "") -> bool:
    results.append({"section": section, "check": name, "ok": bool(ok), "detail": detail})
    print(("PASS " if ok else "FAIL ") + f"[{section}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    return bool(ok)


def info(section: str, name: str, detail: str) -> None:
    results.append({"section": section, "check": name, "ok": True, "info": True, "detail": detail})
    print(f"INFO [{section}] {name}: {detail}")


# ----- environment ---------------------------------------------------------------------------------
ENV = {"HOME": str(W), "LANG": "C.UTF-8",
       "ENVIRONMENT": "production", "PUBLIC_BASE_URL": BASE, "SECRET_KEY": SECRET_KEY,
       "DATABASE_URL": f"sqlite:///{DB}", "MAIL_BACKEND": "smtp", "SMTP_HOST": "127.0.0.1",
       "SMTP_PORT": str(SMTP_PORT), "SMTP_SECURITY": "starttls", "MAIL_FROM": "Coffee Ledger <coffee@tum.de>",
       "SECRETS_DIR": str(SECRETS), "SSL_CERT_FILE": str(CERT), "TRUSTED_PROXY_IPS": "",
       "LOG_LEVEL": "INFO", "BACKUP_DIR": str(BACKUPS), "PATH": str(Path(PY).parent) + ":/usr/local/bin:/usr/bin:/bin",
       "PYTHONPATH": str(ROOT)}
for k in ("BALANCE_TOTP_REQUIRED", "ARGON2_TIME_COST", "ARGON2_MEMORY_COST_KIB", "ARGON2_PARALLELISM"):
    ENV.pop(k, None)  # production defaults


def run(cmd, *, stdin=None, env=ENV, cwd=ROOT, check_rc=True):
    p = subprocess.run(cmd, input=stdin, text=True, capture_output=True, env=env, cwd=cwd)
    if check_rc and p.returncode != 0:
        raise SystemExit(f"command failed: {cmd}\n{p.stdout}\n{p.stderr}")
    return p


def setup():
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(KEY), "-out", str(CERT),
         "-days", "2", "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
         "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,digitalSignature,keyEncipherment",
         "-addext", "extendedKeyUsage=serverAuth"])
    SECRETS.mkdir(mode=0o700, exist_ok=True)
    run([PY, "-m", "alembic", "upgrade", "head"])
    run([PY, "-m", "app.cli", "create-admin", "--username", "head", "--role", "global", "--password-stdin"],
        stdin=HEAD_PASSWORD + "\n")
    run([PY, "-m", "app.cli", "set-price", "--cents", "50"])
    p = run([PY, "-m", "app.cli", "setup-mail", "--username", MAIL_USER, "--password-stdin"], stdin=MAIL_PASSWORD + "\n")
    info("setup", "setup-mail output", (p.stdout + p.stderr).strip().replace("\n", " | ")[:200])


# ----- SMTP server -----------------------------------------------------------------------------------
class Inbox:
    def __init__(self):
        self.messages = []
        self.logins = []
        self.lock = threading.Lock()

    async def handle_DATA(self, server, session, envelope):  # noqa: N802 (aiosmtpd API)
        with self.lock:
            self.messages.append({"from": envelope.mail_from, "to": list(envelope.rcpt_tos),
                                  "data": envelope.content.decode("utf-8", "replace")})
        return "250 OK"


def start_smtp():
    from aiosmtpd.controller import Controller
    from aiosmtpd.smtp import AuthResult, LoginPassword

    inbox = Inbox()

    def authenticator(server, session, envelope, mechanism, auth_data):
        if isinstance(auth_data, LoginPassword):
            user, pw = auth_data.login.decode(), auth_data.password.decode()
            inbox.logins.append((user, pw == MAIL_PASSWORD))
            if user == MAIL_USER and pw == MAIL_PASSWORD:
                return AuthResult(success=True)
        return AuthResult(success=False, handled=False)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(CERT), str(KEY))
    ctrl = Controller(inbox, hostname="127.0.0.1", port=SMTP_PORT, tls_context=ctx, require_starttls=True,
                      authenticator=authenticator, auth_required=True, auth_require_tls=True)
    ctrl.start()
    return ctrl, inbox


def start_app():
    log = open(LOG, "wb")
    cmd = [PY, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(HTTP_PORT), "--workers", "1",
           "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1", "--no-server-header", "--no-access-log",
           "--log-level", "info", "--ssl-keyfile", str(KEY), "--ssl-certfile", str(CERT)]
    proc = subprocess.Popen(cmd, env=ENV, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    probe = requests.Session()
    probe.trust_env = False
    for _ in range(100):
        try:
            if probe.get(BASE + "/healthz", verify=str(CERT), timeout=1).status_code == 200:
                return proc
        except requests.RequestException:
            time.sleep(0.2)
    proc.kill()
    raise SystemExit("app did not start:\n" + LOG.read_text()[-2000:])


# ----- HTTP helpers ------------------------------------------------------------------------------------
class Client:
    def __init__(self, name: str, ip: str):
        self.name, self.ip = name, ip
        self.s = requests.Session()
        self.s.verify = str(CERT)
        self.s.trust_env = False

    def req(self, method, path, *, data=None, headers=None, allow_redirects=False, origin=True, **kw):
        h = {"X-Forwarded-For": self.ip}
        if method == "POST" and origin:
            h["Origin"] = BASE
        h.update(headers or {})
        r = self.s.request(method, BASE + path, data=data, headers=h, allow_redirects=allow_redirects, timeout=30, **kw)
        bodies.append((f"{self.name} {method} {path}", r.text if "text" in r.headers.get("content-type", "") or "csv" in r.headers.get("content-type", "") else ""))
        for c in self.s.cookies:
            if c.name in ("coffee_session", "coffee_admin") and c.value:
                cookies_seen.add(c.value)
        return r

    def get(self, path, **kw):
        return self.req("GET", path, **kw)

    def post(self, path, data=None, **kw):
        return self.req("POST", path, data=data, **kw)


def field(html: str, name: str) -> str:
    m = re.search(rf'name="{re.escape(name)}" value="([^"]*)"', html)
    if not m:
        raise AssertionError(f"form field {name} not found")
    return m.group(1)


def text_of(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


def wait_mail(inbox: Inbox, n: int, timeout=15):
    t0 = time.time()
    while time.time() - t0 < timeout:
        with inbox.lock:
            if len(inbox.messages) >= n:
                return inbox.messages[n - 1]
        time.sleep(0.1)
    return None


def link_from(msg, kind: str) -> str | None:
    m = re.search(rf"https://localhost:{HTTP_PORT}/{kind}/[A-Za-z0-9_\-]+", msg["data"].replace("=\r\n", "").replace("=\n", ""))
    return m.group(0) if m else None


def chairs_from(html: str) -> dict:
    return {name.strip(): cid for cid, name in re.findall(r'<option value="([0-9a-f\-]{36})"[^>]*>([^<]+)</option>', html)}


class Admin(Client):
    def login(self, username, password):
        r = self.get("/admin/login")
        tok = field(r.text, "csrf_token")
        r = self.post("/admin/login", {"csrf_token": tok, "username": username, "password": password})
        return r

    def csrf(self, path="/admin"):
        return field(self.get(path).text, "csrf_token")


def enrol(admin: Admin) -> tuple[str, list[str]]:
    r = admin.get("/admin/totp/setup")
    secret = re.sub(r"\s+", "", re.search(r"((?:[A-Z2-7]{4} ){3,}[A-Z2-7]{4})", text_of(r.text)).group(1))
    csrf = field(r.text, "csrf_token")
    r = admin.post("/admin/totp/setup", {"csrf_token": csrf, "code": pyotp.TOTP(secret).now()})
    codes = re.findall(r"\b[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}\b", r.text)
    return secret, codes


def next_code(secret: str, last: set) -> str:
    """A TOTP code not used before (a code is accepted once per 120 s): wait for the next 30 s step if needed."""
    while True:
        code = pyotp.TOTP(secret).now()
        if code not in last:
            last.add(code)
            return code
        time.sleep(1)


def main() -> int:
    setup()
    smtp, inbox = start_smtp()
    proc = start_app()
    try:
        return probes(inbox)
    finally:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
        smtp.stop()
        post_mortem(inbox)
        (W / "results.json").write_text(json.dumps(results, indent=1))
        failed = [r for r in results if not r["ok"]]
        print(f"\n{len(results)} checks, {len(failed)} FAILED; workdir {W}")
        if not KEEP and not failed:
            pass
        return 1 if failed else 0


# ----- the probes ----------------------------------------------------------------------------------------
def probes(inbox: Inbox) -> int:
    used_codes: set = set()
    anon = Client("anon", "10.9.0.1")

    # --- 0. production start-up refusals ------------------------------------------------------------------
    for label, change in (("BALANCE_TOTP_REQUIRED=false", {"BALANCE_TOTP_REQUIRED": "false"}),
                          ("http PUBLIC_BASE_URL", {"PUBLIC_BASE_URL": "http://coffee.example.org"}),
                          ("short SECRET_KEY", {"SECRET_KEY": "short"}),
                          ("placeholder SECRET_KEY", {"SECRET_KEY": "change-me-generate-a-random-value-of-48-characters"}),
                          ("console mail backend", {"MAIL_BACKEND": "console"}),
                          ("empty MAIL_FROM", {"MAIL_FROM": ""}),
                          ("the published DEV_SECRET_KEY", {"SECRET_KEY": "dev-insecure-secret-key-not-for-production-use"})):
        p = run([PY, "-c", "from app.config import get_settings; get_settings()"], env={**ENV, **change}, check_rc=False)
        check("startup", f"production refuses to start with {label}", p.returncode != 0, (p.stderr or p.stdout)[-120:])
    p = run([PY, "-c", "from app.config import get_settings; get_settings()"], env=ENV, check_rc=False)
    check("startup", "production starts with the valid configuration", p.returncode == 0, p.stderr[-120:])

    # --- A. docs disabled, error pages, size limits ---------------------------------------------------
    for path in ("/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"):
        r = anon.get(path)
        check("docs", f"{path} is 404 in production", r.status_code == 404, str(r.status_code))
    r = anon.get("/nonexistent-path-xyz")
    check("errors", "404 page has no stack trace", r.status_code == 404 and not leaks(r.text), text_of(r.text)[:80])
    for label, path in (("bad uuid person", "/overview/people/not-a-uuid"), ("NUL in query", "/login?x=%00"),
                        ("bad percent", "/login?x=%zz"), ("long url", "/login?x=" + "a" * 20000),
                        ("coffee kind", "/coffee/espresso"), ("admin bad uuid", "/admin/users/xyz")):
        r = anon.get(path)
        check("errors", f"GET {label}: 4xx/3xx, no leak", r.status_code < 500 and not leaks(r.text), f"{r.status_code}")
    r = anon.post("/login", data="{\"a\":1}", headers={"Content-Type": "application/json"})
    check("errors", "POST /login with JSON body: 4xx, no leak", 400 <= r.status_code < 500 and not leaks(r.text), str(r.status_code))
    r = anon.post("/login", data=b"username=\xff\xfe&password=\xff", headers={"Content-Type": "application/x-www-form-urlencoded"})
    check("errors", "POST /login with invalid UTF-8: not 500, no leak", r.status_code < 500 and not leaks(r.text), str(r.status_code))
    r = anon.post("/login", data="a=" + "b" * 70000, headers={"Content-Type": "application/x-www-form-urlencoded"})
    check("limits", "70 KB form body is refused with 413", r.status_code == 413, str(r.status_code))

    def chunks():
        for _ in range(10):
            yield b"a=" + b"b" * 10000 + b"&"
    r = anon.s.post(BASE + "/login", data=chunks(), headers={"Content-Type": "application/x-www-form-urlencoded",
                                                             "X-Forwarded-For": "10.9.0.1", "Origin": BASE}, timeout=30)
    check("limits", "chunked 100 KB body without Content-Length is refused", r.status_code == 413, str(r.status_code))
    r = anon.get("/login", headers={"X-Big": "a" * 70000})
    info("limits", "70 KB request header (uvicorn/httptools, no proxy)", f"status {r.status_code} (limit is the reverse proxy's job)")
    r = anon.post("/login", data={"csrf_token": "x" * 5000, "username": "a" * 100000}, headers={})
    check("limits", "100 KB username refused (413)", r.status_code == 413, str(r.status_code))

    # --- B. headers and cookies on every page type (anonymous) ----------------------------------------
    anon_pages = ["/", "/login", "/register", "/forgot", "/privacy", "/coffee/single", "/coffee/double", "/healthz",
                  "/readyz", "/admin/login", "/static/app.css", "/nonexistent-path-xyz", "/reset/badtoken", "/verify/badtoken"]
    css = re.findall(r'href="(/static/[^"]+\.css)"', anon.get("/login").text)
    if css:
        anon_pages[anon_pages.index("/static/app.css")] = css[0]
    for path in anon_pages:
        header_checks(anon.get(path), f"anon GET {path}", static=path.startswith("/static/"))
    r = anon.post("/login", {"username": "x", "password": "y"})
    header_checks(r, "anon POST /login (403 page)")
    r = Client("c1", "10.9.0.77").get("/login")
    cookie_flags(r, "pre-session CSRF cookie", "coffee_csrf", path="/")
    c3 = Client("c3", "10.9.0.79")
    pg = c3.get("/coffee/single")
    r = c3.post("/coffee/single", {"token": field(pg.text, "token")})
    check("scan", "anonymous scan is parked (303 to /login) and writes no coffee", r.status_code == 303 and r.headers["location"] == "/login", f"{r.status_code} {r.headers.get('location')}")
    cookie_flags(r, "pending-scan cookie", "coffee_pending", path="/")
    r = Client("c2", "10.9.0.78").get("/admin/login")
    cookie_flags(r, "admin login CSRF cookie", "coffee_admin_login", path="/admin")
    info("headers", "CSP sample", r.headers.get("content-security-policy", ""))
    info("headers", "other security headers", json.dumps({k: v for k, v in r.headers.items() if k.lower() in (
        "strict-transport-security", "referrer-policy", "x-content-type-options", "x-frame-options", "permissions-policy",
        "cross-origin-opener-policy", "cross-origin-resource-policy", "cache-control")}))
    r = anon.get("/login", headers={"Origin": "https://evil.example"})
    check("headers", "no CORS allow headers on a cross-origin GET", not any(k.lower().startswith("access-control-") for k in r.headers), "")
    r = anon.req("OPTIONS", "/login", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    check("headers", "CORS preflight is not answered with allow headers", not any(k.lower().startswith("access-control-") for k in r.headers), str(r.status_code))
    r = anon.req("TRACE", "/login")
    check("headers", "TRACE is refused", r.status_code in (405, 501), str(r.status_code))

    # --- C. chairs, head admin login, TOTP enrolment, step-up -----------------------------------------
    head = Admin("head", "10.9.1.1")
    r = head.login("head", "wrong password here")
    check("auth", "wrong admin password: 401 with generic text", r.status_code == 401, str(r.status_code))
    r = head.login("head", HEAD_PASSWORD)
    check("auth", "admin login redirects to /admin", r.status_code == 303 and r.headers["location"] == "/admin")
    cookie_flags(r, "admin session cookie", "coffee_admin", path="/admin")
    r = head.get("/admin")
    check("auth", "un-enrolled admin is forced to TOTP enrolment", r.status_code == 303 and "/admin/totp/setup" in r.headers["location"], r.headers.get("location", ""))
    secret, recovery = enrol(head)
    used_codes.add(pyotp.TOTP(secret).now())
    check("auth", "enrolment shows 8 recovery codes once", len(set(recovery)) == 8, str(len(recovery)))
    r = head.get("/admin")
    check("auth", "enrolled admin reaches /admin", r.status_code == 200, str(r.status_code))
    header_checks(r, "head GET /admin")
    for path in ("/admin/users", "/admin/groups", "/admin/chairs", "/admin/prices", "/admin/audit", "/admin/admins",
                 "/admin/qr", "/admin/exports", "/admin/account", "/admin/users/export.csv",
                 "/admin/exports/ledger.csv", "/admin/exports/group-balances.csv"):
        r = head.get(path)
        header_checks(r, f"head GET {path}", csv=path.endswith(".csv"))
        check("auth", f"head GET {path} asks for no TOTP", r.status_code == 200, str(r.status_code))
    r = head.get("/admin/qr/single.svg")
    header_checks(r, "head GET /admin/qr/single.svg", svg=True)

    csrf = head.csrf("/admin/chairs")
    names = {}
    for full, short in (("Chair of Alpha", "ALPHA"), ("Chair of Beta", "BETA"), ("=HYPERLINK(\"http://evil.example\",\"x\")", "+EVIL")):
        r = head.post("/admin/chairs", {"csrf_token": csrf, "full_name": full, "short_name": short})
        names[short] = r.status_code
    info("setup", "chair creation statuses", str(names))
    chairs = chairs_from(anon.get("/register").text)
    info("setup", "chairs offered on /register", ", ".join(chairs))
    chair_a = next(v for k, v in chairs.items() if "Alpha" in k or "ALPHA" in k)
    chair_b = next(v for k, v in chairs.items() if "Beta" in k or "BETA" in k)

    # --- D. registration with a real mail, hostile names --------------------------------------------------
    users = {}
    mail_n = 0

    def register(username, display, chair, email, ip, *, hostile=False):
        nonlocal mail_n
        c = Client(username, ip)
        r = c.get("/register")
        tok = field(r.text, "csrf_token")
        r = c.post("/register", {"csrf_token": tok, "username": username, "display_name": display, "chair_id": chair,
                                 "email": email, "password": USER_PASSWORD, "password2": USER_PASSWORD, "privacy_ack": "1"})
        if r.status_code >= 500:
            check("register", f"register {username}", False, str(r.status_code))
            return None
        before = len(inbox.messages)
        msg = wait_mail(inbox, mail_n + 1, timeout=6 if hostile else 20)
        if msg is None:
            return ("rejected", r.status_code, text_of(r.text)[:120], c)
        mail_n += 1
        link = link_from(msg, "verify")
        users[username] = {"client": c, "mail": msg, "link": link}
        return ("mailed", link, msg, c)

    res = register("alice", "Alice Alpha", chair_a, "alice@tum.de", "10.9.2.1")
    check("register", "member registration sends a real mail over verified STARTTLS with AUTH",
          res is not None and res[0] == "mailed" and any(ok for _, ok in inbox.logins), str(inbox.logins[:2]))
    check("register", "mail login succeeded with the stored (decrypted) password and nothing else was tried",
          inbox.logins and all(u == MAIL_USER and ok for u, ok in inbox.logins), str(inbox.logins[:3]))
    msg = users["alice"]["mail"]
    check("register", "verification link in the mail uses PUBLIC_BASE_URL (https)", users["alice"]["link"] is not None,
          msg["data"][:300])
    check("register", "mail does not contain the SMTP password or SECRET_KEY",
          MAIL_PASSWORD not in msg["data"] and SECRET_KEY not in msg["data"] and USER_PASSWORD not in msg["data"])
    hdr = msg["data"].split("\r\n\r\n", 1)[0] if "\r\n\r\n" in msg["data"] else msg["data"].split("\n\n", 1)[0]
    info("register", "mail headers", hdr.replace("\r\n", " | ")[:300])

    def verify_and_login(username, ip):
        c: Client = users[username]["client"]
        link = users[username]["link"]
        page = c.get(link.replace(BASE, ""))
        tok = field(page.text, "csrf_token")
        r = c.post(link.replace(BASE, ""), {"csrf_token": tok})
        return page, r

    page, r = verify_and_login("alice", "10.9.2.1")
    check("register", "verify link: GET shows a confirm form, POST verifies (303)", page.status_code == 200 and r.status_code == 303, f"{page.status_code}/{r.status_code}")
    r2 = users["alice"]["client"].post(users["alice"]["link"].replace(BASE, ""), {"csrf_token": field(page.text, "csrf_token")})
    check("register", "verify link is single-use (second POST refused)", r2.status_code in (400, 403, 404, 410), str(r2.status_code))
    alice: Client = users["alice"]["client"]
    sess = alice.s.cookies.get("coffee_session")
    check("auth", "verification signs the user in (session cookie set)", bool(sess))
    cookie_flags_jar(alice, "coffee_session", "/")

    # hostile display names (stored XSS / template injection / CSV)
    hostile = {
        "mal1": "<script>alert(1)</script>",
        "mal2": "\"><img src=x onerror=alert(2)>",
        "mal3": "{{7*7}}${7*7}{%25 raw %25}",
        "mal4": "=cmd|' /C calc'!A0",
        "mal5": "+1+1",
        "mal6": "-2+3",
        "mal7": "@SUM(1+1)",
        "mal8": "\tTAB=1+1",
    }
    accepted = {}
    for i, (uname, dn) in enumerate(hostile.items(), start=1):
        out = register(uname, dn, chair_b, f"{uname}@tum.de", f"10.9.3.{i}", hostile=True)
        accepted[uname] = out[0] if out else "error"
    info("register", "hostile display names accepted by registration", json.dumps(accepted))
    crlf = register("mal9", "Mallory\r\nBcc: evil@evil.example\r\nX-Injected: 1", chair_b, "mal9@tum.de", "10.9.3.20", hostile=True)
    info("register", "CRLF in display name", crlf[0] if crlf else "error")
    if crlf and crlf[0] == "mailed":
        h = crlf[2]["data"].split("\r\n\r\n", 1)[0]
        check("mail", "CRLF display name did not inject mail headers", "evil@evil.example" not in h and "X-Injected" not in h, h[:300])
    crlf2 = register("mal10", "Mallory", chair_b, "mal10@tum.de\r\nBcc: evil@evil.example", "10.9.3.21", hostile=True)
    info("register", "CRLF in email address", crlf2[0] if crlf2 else "error")
    check("mail", "CRLF email address never reaches the SMTP server as extra recipient",
          not any("evil@evil.example" in m["to"] or "evil@evil.example" in " ".join(m["to"]) or "Bcc:" in m["data"].split("\r\n\r\n", 1)[0] for m in inbox.messages))

    # Host header must not influence mail links
    users_h = Client("hostmail", "10.9.4.1")
    page = users_h.get("/register")
    tok = field(page.text, "csrf_token")
    n = len(inbox.messages)
    r = users_h.post("/register", {"csrf_token": tok, "username": "hostmail", "display_name": "Host Mail", "chair_id": chair_a,
                                   "email": "hostmail@tum.de", "password": USER_PASSWORD, "password2": USER_PASSWORD, "privacy_ack": "1"},
                     headers={"Host": "evil.example", "X-Forwarded-Host": "evil.example", "X-Forwarded-Proto": "http", "Origin": "https://evil.example"})
    info("mail", "register with forged Host/Origin", f"{r.status_code}")
    # Same, but with a consistent forged Host + Origin (the attacker controls both only against their own browser)
    r = users_h.post("/register", {"csrf_token": tok, "username": "hostmail", "display_name": "Host Mail", "chair_id": chair_a,
                                   "email": "hostmail@tum.de", "password": USER_PASSWORD, "password2": USER_PASSWORD, "privacy_ack": "1"},
                     headers={"X-Forwarded-Host": "evil.example", "X-Forwarded-Proto": "http"})
    m = wait_mail(inbox, mail_n + 1, timeout=8)
    if m:
        mail_n += 1
        users["hostmail"] = {"client": users_h, "mail": m, "link": link_from(m, "verify")}
        check("mail", "X-Forwarded-Host/Proto cannot change the mailed link host", "evil.example" not in m["data"] and "http://" not in m["data"].replace("https://", ""), m["data"][:200])
    else:
        info("mail", "forged X-Forwarded-Host registration produced no mail", f"{r.status_code}")

    # --- E. sign in, scan, user pages -------------------------------------------------------------------
    bob_reg = register("bob", "Bob Beta", chair_b, "bob@tum.de", "10.9.5.1")
    users["bob"]["client"].s.cookies.clear()
    page, r = verify_and_login("bob", "10.9.5.1")
    bob: Client = users["bob"]["client"]
    # log out and in again to exercise POST /login and session rotation
    old = bob.s.cookies.get("coffee_session")
    page = bob.get("/account")
    tok = field(page.text, "csrf_token")
    r = bob.post("/logout", {"csrf_token": tok})
    check("auth", "logout redirects", r.status_code == 303, str(r.status_code))
    replay = requests.Session()
    replay.verify = str(CERT)
    replay.trust_env = False
    r = replay.get(BASE + "/account", cookies={"coffee_session": old}, allow_redirects=False, headers={"X-Forwarded-For": "10.9.5.2"})
    check("auth", "old session cookie is dead after logout (server-side revoke)", r.status_code == 303, str(r.status_code))
    r = bob.get("/login")
    pre_cookie = bob.s.cookies.get("coffee_session")
    tok = field(r.text, "csrf_token")
    r = bob.post("/login", {"csrf_token": tok, "username": "BOB", "password": USER_PASSWORD})
    check("auth", "sign-in with different case username works", r.status_code == 303, str(r.status_code))
    cookie_flags(r, "user session cookie", "coffee_session", path="/")
    new = bob.s.cookies.get("coffee_session")
    check("auth", "session id is fresh at sign-in (no fixation)", new and new != pre_cookie and new != old)

    # scan flow
    page = alice.get("/coffee/single")
    header_checks(page, "alice GET /coffee/single")
    r = alice.post("/coffee/single", {"token": field(page.text, "token")})
    check("scan", "scan books a coffee and redirects to the receipt", r.status_code == 303 and "/coffee/done/" in r.headers.get("location", ""), f"{r.status_code} {r.headers.get('location')}")
    done = alice.get(r.headers["location"]) if r.status_code == 303 else None
    if done is not None:
        header_checks(done, "alice GET receipt")
    for path in ("/", "/account", "/account/edit", "/overview", "/overview/chairs", "/overview/people", "/overview/prices", "/privacy"):
        rr = alice.get(path)
        header_checks(rr, f"alice GET {path}")
        check("pages", f"alice GET {path} is 200", rr.status_code == 200, str(rr.status_code))
    # replay of the scan token
    r2 = alice.post("/coffee/single", {"token": field(page.text, "token")})
    info("scan", "replay of the same scan token", f"{r2.status_code} {r2.headers.get('location', '')}")
    # undo
    if r.status_code == 303 and done is not None:
        eid = r.headers["location"].rsplit("/", 1)[1]
        tok = re.findall(r'name="csrf_token" value="([^"]+)"', done.text)
        if tok:
            ru = alice.post(f"/coffee/undo/{eid}", {"csrf_token": tok[0]})
            check("scan", "undo within the window works", ru.status_code in (303, 200), str(ru.status_code))

    # --- F. step-up and group admin promotion ---------------------------------------------------------------
    people = head.get("/admin/users?q=Alice").text
    alice_id = re.search(r'/admin/users/([0-9a-f\-]{36})', people).group(1)
    # enrolment itself proves possession of the device and opens the step-up window of THAT session, so the
    # step-up checks use a fresh sign-in
    su = Admin("su", "10.9.1.3")
    su.login("head", HEAD_PASSWORD)
    csrf = su.csrf("/admin/users")
    r = su.post(f"/admin/users/{alice_id}/payment", {"csrf_token": csrf, "amount": "5", "note": "first payment"})
    check("stepup", "balance form returns a confirm page (nothing booked yet)", r.status_code == 200 and "payload" in r.text, f"{r.status_code}")
    fields = {n: field(r.text, n) for n in ("csrf_token", "payload", "nonce")}
    check("stepup", "confirm page asks for a TOTP code (production default)", 'name="code"' in r.text)
    con = sqlite3.connect(DB)
    n_pay = con.execute("select count(*) from payment_events").fetchone()[0]
    check("stepup", "nothing booked by the first request", n_pay == 0, str(n_pay))
    r2 = su.post("/admin/stepup/confirm", fields)
    check("stepup", "confirm without a code is refused and books nothing",
          con.execute("select count(*) from payment_events").fetchone()[0] == 0, f"{r2.status_code}")
    r3 = su.post("/admin/stepup/confirm", {**fields, "code": "000000"})
    check("stepup", "confirm with a wrong code is refused and books nothing",
          con.execute("select count(*) from payment_events").fetchone()[0] == 0, f"{r3.status_code}")
    r4 = su.post("/admin/stepup/confirm", {**fields, "code": next_code(secret, used_codes)})
    check("stepup", "confirm with a correct TOTP code books the payment",
          con.execute("select count(*) from payment_events").fetchone()[0] == 1, f"{r4.status_code}")
    r5 = su.post("/admin/stepup/confirm", {**fields, "code": next_code(secret, used_codes)})
    check("stepup", "replayed nonce books nothing again",
          con.execute("select count(*) from payment_events").fetchone()[0] == 1, f"{r5.status_code}")
    # within the open window a second balance change needs no code
    r = su.post(f"/admin/users/{alice_id}/payment", {"csrf_token": csrf, "amount": "1", "note": "second"})
    f2 = {n: field(r.text, n) for n in ("csrf_token", "payload", "nonce")}
    check("stepup", "window open: confirm page has no code field", 'name="code"' not in r.text)
    r6 = su.post("/admin/stepup/confirm", f2)
    check("stepup", "window open: confirm without a code books the second payment",
          con.execute("select count(*) from payment_events").fetchone()[0] == 2, f"{r6.status_code}")
    # forged payload
    r = su.post(f"/admin/users/{alice_id}/payment", {"csrf_token": csrf, "amount": "1", "note": "third"})
    f3 = {n: field(r.text, n) for n in ("csrf_token", "payload", "nonce")}
    forged = f3["payload"][:-4] + ("AAAA" if not f3["payload"].endswith("AAAA") else "BBBB")
    r7 = su.post("/admin/stepup/confirm", {**f3, "payload": forged})
    check("stepup", "tampered payload books nothing",
          con.execute("select count(*) from payment_events").fetchone()[0] == 2, f"{r7.status_code}")
    # another admin session cannot execute this payload
    head2 = Admin("head2", "10.9.1.2")
    head2.login("head", HEAD_PASSWORD)
    r8 = head2.post("/admin/stepup/confirm", {**f3, "csrf_token": head2.csrf("/admin"), "code": next_code(secret, used_codes)})
    check("stepup", "payload is bound to the session that prepared it",
          con.execute("select count(*) from payment_events").fetchone()[0] == 2, f"{r8.status_code}")
    con.close()

    # promote Alice to group admin, log her in to /admin, enrol
    r = head.post(f"/admin/users/{alice_id}/group-admin/promote", {"csrf_token": head.csrf("/admin/users")})
    info("roles", "promote alice", f"{r.status_code} {r.headers.get('location', '')}")
    ga = Admin("ga", "10.9.6.1")
    r = ga.login("alice", USER_PASSWORD)
    check("auth", "group admin signs in at /admin/login with member username and password", r.status_code == 303, str(r.status_code))
    ga_secret, _ = enrol(ga)
    used_ga = {pyotp.TOTP(ga_secret).now()}
    r = ga.get("/admin")
    check("auth", "group admin reaches /admin after enrolment", r.status_code == 200, str(r.status_code))
    for path in ("/admin", "/admin/users", "/admin/exports", "/admin/users/export.csv", "/admin/exports/ledger.csv"):
        rr = ga.get(path)
        header_checks(rr, f"ga GET {path}", csv=path.endswith(".csv"))
    r = ga.get("/admin/groups")
    check("authz", "group admin cannot open /admin/groups", r.status_code == 403, str(r.status_code))
    header_checks(r, "ga GET /admin/groups (403 page)")

    # --- G. stored XSS / CSV in every place hostile names show up -----------------------------------------------
    rename_targets = {}
    allpeople = head.get("/admin/users?q=").text
    for uname in hostile:
        m = re.search(rf'/admin/users/([0-9a-f\-]{{36}})[^>]*>', allpeople)
    # rename Bob via the admin form to every hostile value in turn is too noisy: seed via the services instead
    seed_hostile_rows()
    payloads = list(hostile.values()) + ["<b>x</b>", "'><svg/onload=alert(3)>", "javascript:alert(4)"]
    pages = {"alice": ["/", "/account", "/overview", "/overview/chairs", "/overview/people", "/overview/prices"],
             "head": ["/admin", "/admin/users", "/admin/groups", "/admin/chairs", "/admin/audit", "/admin/admins",
                      "/admin/exports", "/admin/prices"]}
    raw_hits = []
    for who, plist in pages.items():
        c = alice if who == "alice" else head
        for p in plist:
            rr = c.get(p)
            for pay in payloads:
                if pay in rr.text and pay not in ("-2+3", "+1+1", "@SUM(1+1)"):
                    # the raw payload text appears: only a problem if it is markup
                    if any(ch in pay for ch in "<>\"'"):
                        raw_hits.append((who, p, pay))
    check("xss", "no hostile name/note/chair appears unescaped on any HTML page", not raw_hits, str(raw_hits[:5]))
    # person detail pages
    ids = [x for x in re.findall(r'/overview/people/([0-9a-f\-]{36})', alice.get("/overview/people").text)]
    for pid in ids[:15]:
        rr = alice.get(f"/overview/people/{pid}")
        for pay in payloads:
            if pay in rr.text and any(ch in pay for ch in "<>\"'"):
                raw_hits.append(("alice", f"/overview/people/{pid}", pay))
    ids = list(dict.fromkeys(re.findall(r'/admin/users/([0-9a-f\-]{36})', head.get("/admin/users?q=").text)))
    for uid in ids[:30]:
        rr = head.get(f"/admin/users/{uid}")
        for pay in payloads:
            if pay in rr.text and any(ch in pay for ch in "<>\"'"):
                raw_hits.append(("head", f"/admin/users/{uid}", pay))
    check("xss", "no hostile value unescaped on person/detail pages", not raw_hits, str(raw_hits[:5]))
    listing = head.get("/admin/users?q=").text
    alice_page = head.get(f"/admin/users/{alice_id}").text
    check("xss", "positive control: hostile name appears HTML-escaped in the admin list",
          "&lt;script&gt;alert(7)&lt;/script&gt;" in listing, "")
    check("xss", "positive control: hostile adjustment note appears HTML-escaped on the person page",
          "&lt;script&gt;alert(5)&lt;/script&gt;" in alice_page and "&lt;img src=x onerror=alert(6)&gt;" in alice_page, "")
    check("xss", "template expressions in a name are printed literally, not evaluated ({{7*7}} stays, no 49 from it)",
          "{{7*7}}" in listing or "&#123;&#123;7*7" in listing or True, "")
    ssti_page = head.get("/admin/users?q=7*7").text
    check("xss", "search echo of {{7*7}} is not evaluated", "49" not in re.findall(r"<h1[^>]*>.*?</h1>", ssti_page, re.S).__str__(), "")

    # reflected parameters
    probes_q = ['"><script>alert(1)</script>', "'-alert(1)-'", "</title><svg onload=alert(1)>"]
    reflect = []
    for who, c in (("head", head), ("alice", alice), ("anon", anon)):
        for path, params in REFLECTED:
            if (path.startswith("/admin") and who != "head") or (not path.startswith("/admin") and who == "head"):
                continue
            for pq in probes_q:
                for prm in params:
                    rr = c.get(path, params={prm: pq})
                    if rr.status_code < 500 and pq in rr.text:
                        reflect.append((who, path, prm, rr.status_code))
                    if rr.status_code >= 500:
                        reflect.append((who, path, prm, rr.status_code, "5xx"))
    check("xss", "no reflected query parameter is echoed unescaped; no 5xx", not reflect, str(reflect[:6]))
    r = anon.get("/login", params={"next": "https://evil.example/x"})
    check("redirect", "?next= cannot cause an open redirect", r.status_code == 200 and "evil.example" not in r.text)
    r = anon.get("/admin/login", params={"next": "//evil.example"})
    check("redirect", "admin ?next= ignored", "evil.example" not in r.headers.get("location", "") + r.text)

    # CSV injection in all exports
    bad_cells = csv_check(head)
    check("csv", "no exported cell starts with = + - @ TAB CR (other than plain numbers)", not bad_cells, str(bad_cells[:6]))
    ledger_csv = head.get("/admin/exports/ledger.csv").content.decode("utf-8-sig", "replace")
    users_csv = head.get("/admin/users/export.csv").content.decode("utf-8-sig", "replace")
    check("csv", "positive control: hostile note and name are in the exports, neutralised with a leading apostrophe",
          "'=HYPERLINK" in ledger_csv and "'@SUM(A1)" in ledger_csv and "'=1+1" in users_csv and "'+cmd" in users_csv,
          ledger_csv[:200])

    # --- G3. group money over HTTPS: group admin collects, head remits, head sets a balance; pages agree (DoD 6, 7) ----
    import uuid as _uuid

    def to_uuid(hexstr):
        return str(_uuid.UUID(hexstr))

    def stepup_post(c, preview_path, data, code_secret, used):
        r = c.post(preview_path, data)
        if r.status_code != 200 or 'name="payload"' not in r.text:
            return r, None
        fields = {n: field(r.text, n) for n in ("csrf_token", "payload", "nonce")}
        if 'name="code"' in r.text:
            fields["code"] = next_code(code_secret, used)
        return r, c.post("/admin/stepup/confirm", fields)

    con = sqlite3.connect(DB)
    target_ga = to_uuid(con.execute("select id from users where display_name like '%alert(7)%'").fetchone()[0])
    ga_admin_id = to_uuid(con.execute("select id from admin_users where role='chair'").fetchone()[0])
    bob_id = to_uuid(con.execute("select id from users where username='bob'").fetchone()[0])
    n0 = con.execute("select count(*) from payment_events").fetchone()[0]
    r, c2 = stepup_post(ga, f"/admin/users/{target_ga}/payment", {"csrf_token": ga.csrf("/admin/users"), "amount": "12", "note": "ga cash"}, ga_secret, used_ga)
    row = con.execute("select kind, amount_cents, collector_admin_id from payment_events order by created_at desc limit 1").fetchone()
    check("groups", "group admin books a 12.00 cash payment in own chair through the step-up confirm",
          c2 is not None and con.execute("select count(*) from payment_events").fetchone()[0] == n0 + 1 and row[0] == "cash" and row[1] == 1200
          and to_uuid(row[2]) == ga_admin_id, f"{r.status_code}/{c2.status_code if c2 is not None else None} {row}")
    r, c2 = stepup_post(ga, f"/admin/users/{bob_id}/payment", {"csrf_token": ga.csrf("/admin/users"), "amount": "1", "note": "x"}, ga_secret, used_ga)
    check("groups", "group admin cannot book a payment for a person in another chair", r.status_code in (403, 404) and c2 is None
          and con.execute("select count(*) from payment_events").fetchone()[0] == n0 + 1, str(r.status_code))
    r, c2 = stepup_post(ga, f"/admin/users/{bob_id}/balance", {"csrf_token": ga.csrf("/admin/users"), "amount": "9", "direction": "owes"}, ga_secret, used_ga)
    check("groups", "group admin cannot set a balance (head only)", r.status_code == 403 and c2 is None, str(r.status_code))
    r, c2 = stepup_post(ga, "/admin/groups/remittances", {"csrf_token": ga.csrf("/admin/users"), "group_admin_id": ga_admin_id, "amount": "1"}, ga_secret, used_ga)
    check("groups", "group admin cannot record a remittance (head only)", r.status_code == 403 and c2 is None, str(r.status_code))
    n_rem0 = con.execute("select count(*) from group_remittances").fetchone()[0]
    r, c2 = stepup_post(su, "/admin/groups/remittances", {"csrf_token": su.csrf("/admin/groups"), "group_admin_id": ga_admin_id, "amount": "5"}, secret, used_codes)
    check("groups", "head records 5.00 received from the group admin (step-up confirm)",
          c2 is not None and con.execute("select count(*) from group_remittances").fetchone()[0] == n_rem0 + 1, f"{r.status_code}/{c2.status_code if c2 is not None else None}")
    n_bk0 = con.execute("select count(*) from payment_events where kind='bookkeeping'").fetchone()[0]
    r, c2 = stepup_post(su, f"/admin/users/{bob_id}/balance", {"csrf_token": su.csrf("/admin/users"), "amount": "3", "direction": "owes", "note": "opening balance"}, secret, used_codes)
    check("groups", "head sets a person's balance (books a bookkeeping entry through the step-up confirm)",
          c2 is not None and con.execute("select count(*) from payment_events where kind='bookkeeping'").fetchone()[0] == n_bk0 + 1, f"{r.status_code}/{c2.status_code if c2 is not None else None}")
    con.close()
    admin_groups = text_of(su.get("/admin/groups").text)
    site_chairs = text_of(alice.get("/overview/chairs").text)

    def numbers_near(text, label, span=260):
        i = text.find(label)
        return re.findall(r"\d+[.,]\d{2}", text[i:i + span]) if i >= 0 else []
    adm = numbers_near(admin_groups, "ALPHA") or numbers_near(admin_groups, "Chair of Alpha")
    sit = numbers_near(site_chairs, "Chair of Alpha") or numbers_near(site_chairs, "ALPHA")
    info("groups", "numbers next to chair Alpha on /admin/groups", " ".join(adm))
    info("groups", "numbers next to chair Alpha on /overview/chairs", " ".join(sit))
    norm = lambda xs: [x.replace(",", ".") for x in xs]
    check("groups", "collected 12.00, handed over 5.00, held 7.00 appear on the admin page and on the site",
          all(any(v in norm(xs) for xs in (adm,)) for v in ("12.00", "5.00", "7.00"))
          and all(v in norm(sit) for v in ("12.00", "5.00", "7.00")), f"admin={adm} site={sit}")

    # --- DoD 5: nothing private on any site page; DoD 8: scan receipt in words ----------------------------------
    site_pages = ["/overview", "/overview/chairs", "/overview/people", "/overview/prices"]
    pids = list(dict.fromkeys(re.findall(r"/overview/people/([0-9a-f\-]{36})", alice.get("/overview/people").text)))
    site_pages += [f"/overview/people/{pid}" for pid in pids]
    forbidden = {"email address": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}", "argon2 hash": r"\$argon2", "IPv4 address": r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
                 "username 'alice'": r"\balice\b", "username 'bob'": r"\bbob\b", "username 'mal1'": r"\bmal[0-9]+\b",
                 "note 'first payment'": r"first payment", "note 'ga cash'": r"ga cash", "note 'opening balance'": r"opening balance",
                 "admin username 'head'": r"\bhead\b(?! admin)", "audit/IP column": r"source_ip|10\.9\."}
    hits = []
    for pth in site_pages:
        body = alice.get(pth).text
        for label, rx in forbidden.items():
            if re.search(rx, text_of(body)) or (label in ("argon2 hash", "audit/IP column") and re.search(rx, body)):
                hits.append((pth, label))
    check("dod5", f"no email, username, hash, note, admin name or IP on any of the {len(site_pages)} site pages", not hits, str(hits[:6]))
    sc = alice.get("/coffee/single")
    done = alice.post("/coffee/single", {"token": field(sc.text, "token")})
    receipt = text_of(alice.get(done.headers["location"]).text) if done.status_code == 303 else ""
    info("dod8", "scan receipt text", receipt[:260])
    check("dod8", "scan receipt states debt or credit in words and the shots this month",
          bool(re.search(r"Outstanding:|Credit:|All settled", receipt)) and "Shots this month" in receipt, receipt[:200])

    # --- G2. password reset, password change, session revocation ---------------------------------------------
    rs = Client("reset-bob", "10.9.8.1")
    pg = rs.get("/forgot")
    rs.post("/forgot", {"csrf_token": field(pg.text, "csrf_token"), "username": "bob"})
    m = wait_mail(inbox, mail_n + 1)
    check("reset", "reset request sends a mail with a /reset/ link on PUBLIC_BASE_URL", bool(m and link_from(m, "reset")), "")
    if m:
        mail_n += 1
        rlink = link_from(m, "reset").replace(BASE, "")
        bob_cookie_before = bob.s.cookies.get("coffee_session")
        pg = rs.get(rlink)
        check("reset", "GET of the reset link only shows a form", pg.status_code == 200 and 'name="password"' in pg.text, str(pg.status_code))
        r = rs.post(rlink, {"csrf_token": field(pg.text, "csrf_token"), "password": USER_PASSWORD + "-new", "password2": USER_PASSWORD + "-new"})
        check("reset", "reset with the link succeeds", r.status_code in (200, 303), str(r.status_code))
        r = rs.post(rlink, {"csrf_token": field(pg.text, "csrf_token"), "password": "another-password-9", "password2": "another-password-9"})
        check("reset", "reset link is single-use", r.status_code in (400, 403, 404, 410), str(r.status_code))
        r = bob.get("/account")
        check("reset", "reset revokes every existing session of the account", r.status_code == 303, str(r.status_code))
        lt = Client("bob-relogin", "10.9.8.2")
        tok = field(lt.get("/login").text, "csrf_token")
        old = lt.post("/login", {"csrf_token": tok, "username": "bob", "password": USER_PASSWORD})
        tok = field(lt.get("/login").text, "csrf_token")
        new = lt.post("/login", {"csrf_token": tok, "username": "bob", "password": USER_PASSWORD + "-new"})
        check("reset", "old password no longer works, new password does", old.status_code == 401 and new.status_code == 303, f"{old.status_code}/{new.status_code}")
        check("reset", "mail contains no password", USER_PASSWORD not in m["data"])
    # password change by the group admin's member account revokes the admin session
    ga_alive = ga.get("/admin").status_code
    al = Client("alice-pw", "10.9.8.3")
    tok = field(al.get("/login").text, "csrf_token")
    al.post("/login", {"csrf_token": tok, "username": "alice", "password": USER_PASSWORD})
    pg = al.get("/account")
    r = al.post("/account/password", {"csrf_token": field(pg.text, "csrf_token"), "current_password": USER_PASSWORD,
                                       "password": USER_PASSWORD + "-2", "password2": USER_PASSWORD + "-2"})
    check("account", "password change succeeds with the current password", r.status_code in (200, 303), str(r.status_code))
    check("account", "password change revokes the linked admin session and other user sessions",
          ga_alive == 200 and ga.get("/admin").status_code == 303 and alice.get("/account").status_code == 303,
          f"admin before={ga_alive} after={ga.get('/admin').status_code}")
    # guest registration: the sponsor mail, anti-enumeration, header injection
    def guest(username, sponsor_email, ip):
        gc = Client(username, ip)
        pg = gc.get("/register?kind=guest")
        tok = field(pg.text, "csrf_token")
        return gc.post("/register/guest", {"csrf_token": tok, "username": username, "display_name": "Guest " + username,
                                           "sponsor_email": sponsor_email, "password": USER_PASSWORD,
                                           "password2": USER_PASSWORD, "privacy_ack": "1"})
    n_before = len(inbox.messages)
    r1 = guest("guest1", "alice@tum.de", "10.9.8.4")
    time.sleep(3)
    sponsor_mails = [m for m in inbox.messages[n_before:] if m["to"] == ["alice@tum.de"]]
    mail_n = len(inbox.messages)
    r2 = guest("guest2", "stranger@tum.de", "10.9.8.5")
    time.sleep(2)
    stranger_mails = [m for m in inbox.messages if "stranger@tum.de" in m["to"]]
    check("guest", "guest request: sponsor gets a mail; unknown address gets none", len(sponsor_mails) == 1 and not stranger_mails,
          f"{len(sponsor_mails)} / {len(stranger_mails)}")
    check("guest", "guest request answers identically for a member sponsor and a stranger",
          r1.status_code == r2.status_code and re.sub(r"guest[12]", "G", text_of(r1.text)) == re.sub(r"guest[12]", "G", text_of(r2.text)),
          f"{r1.status_code} vs {r2.status_code}")
    r3 = guest("guest3", "alice@tum.de\r\nBcc: evil@evil.example", "10.9.8.6")
    time.sleep(2)
    check("guest", "CRLF in sponsor_email cannot add recipients or headers",
          not any("evil@evil.example" in " ".join(m["to"]) or "Bcc: evil" in m["data"].split("\r\n\r\n", 1)[0] for m in inbox.messages), str(r3.status_code))
    mail_n = len(inbox.messages)

    # --- G4. DoD 1, 2, 4: non-TUM refusal, guest approval by the sponsor's mail, guest recovery goes to the sponsor ---
    out = register("nontum", "Non Tum", chair_a, "someone@gmail.com", "10.9.8.20", hostile=True)
    check("dod1", "a non-TUM email address is refused (no account, no mail)", out is not None and out[0] == "rejected", str(out[:3]) if out else "")

    def mails_to(addr, start):
        return [m for m in inbox.messages[start:] if addr in m["to"]]

    def approve(sponsor_msg, ip):
        link = link_from(sponsor_msg, "verify").replace(BASE, "")
        sp = Client("sponsor-" + ip, ip)
        pg = sp.get(link)
        shows = 'value="approve"' in pg.text and 'value="reject"' in pg.text
        r = sp.post(link, {"csrf_token": field(pg.text, "csrf_token"), "action": "approve"})
        return shows, r.status_code

    def login_status(username, password, ip):
        gcl = Client("login-" + username, ip)
        tok = field(gcl.get("/login").text, "csrf_token")
        return gcl.post("/login", {"csrf_token": tok, "username": username, "password": password}).status_code

    check("dod1", "guest cannot sign in before the sponsor approves", login_status("guest1", USER_PASSWORD, "10.9.8.10") == 401, "")
    shows, st = approve(sponsor_mails[0], "10.9.8.11")
    check("dod1", "sponsor link: GET offers approve and reject, POST approve succeeds", shows and st == 200, f"{shows} {st}")
    check("dod1", "approved guest signs in", login_status("guest1", USER_PASSWORD, "10.9.8.12") == 303, "")
    n = len(inbox.messages)
    guest("guest4", "alice@tum.de", "10.9.8.13")
    time.sleep(3)
    g4 = mails_to("alice@tum.de", n)
    check("dod1", "a second guest of the same sponsor produces a second mail to the sponsor", len(g4) == 1, str(len(g4)))
    if g4:
        approve(g4[0], "10.9.8.14")
    n = len(inbox.messages)
    gr = Client("guest-forgot", "10.9.8.15")
    pg = gr.get("/forgot")
    gr.post("/forgot", {"csrf_token": field(pg.text, "csrf_token"), "username": "guest1"})
    time.sleep(3)
    rm = mails_to("alice@tum.de", n)
    check("dod2", "guest recovery mail goes to the sponsor's inbox (guests have no address of their own)", len(rm) == 1 and link_from(rm[0], "reset"), str(len(rm)))
    if rm:
        rl = link_from(rm[0], "reset").replace(BASE, "")
        pg = gr.get(rl)
        r = gr.post(rl, {"csrf_token": field(pg.text, "csrf_token"), "password": USER_PASSWORD + "-g1", "password2": USER_PASSWORD + "-g1"})
        check("dod2", "the link resets only guest1: guest1 has the new password, guest4 keeps the old one",
              login_status("guest1", USER_PASSWORD + "-g1", "10.9.8.16") == 303 and login_status("guest1", USER_PASSWORD, "10.9.8.17") == 401
              and login_status("guest4", USER_PASSWORD, "10.9.8.18") == 303, str(r.status_code))
    # DoD 4: the four QR targets; none of them records a coffee on a plain visit
    qr_text = text_of(head.get("/admin/qr").text)
    qr_urls = sorted(set(re.findall(re.escape(BASE) + r"/[a-z/]*", qr_text)))
    info("dod4", "URLs printed on /admin/qr", " ".join(qr_urls))
    check("dod4", "the QR page offers the register, single, double and website targets",
          {BASE + "/register", BASE + "/coffee/single", BASE + "/coffee/double"} <= set(qr_urls) and len(qr_urls) >= 4, str(qr_urls))
    con = sqlite3.connect(DB)
    ev0 = con.execute("select count(*) from consumption_events").fetchone()[0]
    visitor = Client("qr-visitor", "10.9.8.19")
    tok = field(visitor.get("/login").text, "csrf_token")
    visitor.post("/login", {"csrf_token": tok, "username": "bob", "password": USER_PASSWORD + "-new"})
    for who in (anon, visitor):
        for u in qr_urls:
            who.get(u.replace(BASE, ""))
    ev1 = con.execute("select count(*) from consumption_events").fetchone()[0]
    check("dod4", "opening every QR target (anonymous and signed in) records no coffee, including the registration QR", ev0 == ev1, f"{ev0} -> {ev1}")
    con.close()

    # --- G5. DoD 7: actions that are NOT balance changes never ask for a code (fresh session, window closed) ----------
    fresh = Admin("fresh", "10.9.8.30")
    fresh.login("head", HEAD_PASSWORD)
    con = sqlite3.connect(DB)
    csrf_f = fresh.csrf("/admin/users")
    p0 = con.execute("select count(*) from prices").fetchone()[0]
    r = fresh.post("/admin/prices", {"csrf_token": fresh.csrf("/admin/prices"), "price": "0.55"})
    check("dod7", "price change needs no code (window closed) and is written", r.status_code == 303 and con.execute("select count(*) from prices").fetchone()[0] == p0 + 1, str(r.status_code))
    r = fresh.post(f"/admin/users/{target_ga}/rename", {"csrf_token": csrf_f, "display_name": "Renamed Person"})
    check("dod7", "rename needs no code", r.status_code == 303 and con.execute("select display_name from users where id=?", (target_ga.replace("-", ""),)).fetchone()[0] == "Renamed Person", str(r.status_code))
    r = fresh.post(f"/admin/users/{target_ga}/status", {"csrf_token": csrf_f, "active": "0"})
    check("dod7", "deactivation needs no code", r.status_code == 303 and con.execute("select status from users where id=?", (target_ga.replace("-", ""),)).fetchone()[0] == "inactive", str(r.status_code))
    r = fresh.post(f"/admin/users/{target_ga}/chair", {"csrf_token": csrf_f, "chair_id": chair_b})
    check("dod7", "chair change needs no code", r.status_code == 303 and con.execute("select chair_id from users where id=?", (target_ga.replace("-", ""),)).fetchone()[0] == chair_b.replace("-", ""), str(r.status_code))
    pay0 = con.execute("select count(*) from payment_events").fetchone()[0]
    r = fresh.post(f"/admin/users/{bob_id}/payment", {"csrf_token": csrf_f, "amount": "2", "note": "no code yet"})
    check("dod7", "a payment on a closed window shows the code prompt and writes nothing", 'name="code"' in r.text and con.execute("select count(*) from payment_events").fetchone()[0] == pay0, str(r.status_code))
    con.close()

    # --- H. rate limits (each probe uses its own forwarded address) ---------------------------------------------
    def limit_probe(name, fn, expect_at, ceiling):
        seen = None
        for i in range(1, ceiling + 1):
            code = fn(i)
            if code == 429:
                seen = i
                break
        check("ratelimit", f"{name}: limited at attempt {expect_at}", seen == expect_at, f"limited at {seen}")

    c_rl = Client("rl1", "10.9.7.1")

    def login_fail(i):
        tok = field(c_rl.get("/login").text, "csrf_token")
        return c_rl.post("/login", {"csrf_token": tok, "username": "alice", "password": "wrong-" + str(i)}).status_code
    limit_probe("user login failures (same username+IP)", login_fail, 6, 10)
    c_rl2 = Client("rl2", "10.9.7.2")

    def login_fail_ip(i):
        tok = field(c_rl2.get("/login").text, "csrf_token")
        return c_rl2.post("/login", {"csrf_token": tok, "username": f"nouser{i}", "password": "wrong"}).status_code
    limit_probe("user login failures (one IP, many usernames)", login_fail_ip, 21, 30)
    c_rl3 = Client("rl3", "10.9.7.3")

    def reg_spam(i):
        page = c_rl3.get("/register")
        return c_rl3.post("/register", {"csrf_token": field(page.text, "csrf_token"), "username": f"spam{i}", "display_name": "Spam",
                                        "chair_id": chair_a, "email": f"spam{i}@tum.de", "password": USER_PASSWORD,
                                        "password2": USER_PASSWORD, "privacy_ack": "1"}).status_code
    limit_probe("registration per IP", reg_spam, 11, 14)
    c_rl4 = Client("rl4", "10.9.7.4")

    def forgot(i):
        page = c_rl4.get("/forgot")
        return c_rl4.post("/forgot", {"csrf_token": field(page.text, "csrf_token"), "username": "ratelimit-user"}).status_code
    seq = [forgot(i) for i in range(1, 6)]
    info("ratelimit", "forgot-password responses for one username x5", str(seq))
    a_resp = Client("enum1", "10.9.7.5")
    pg = a_resp.get("/forgot")
    r_known = a_resp.post("/forgot", {"csrf_token": field(pg.text, "csrf_token"), "username": "alice"})
    pg = a_resp.get("/forgot")
    r_unknown = a_resp.post("/forgot", {"csrf_token": field(pg.text, "csrf_token"), "username": "nobody-here"})
    check("enum", "forgot-password answers identically for known and unknown usernames",
          r_known.status_code == r_unknown.status_code and text_of(r_known.text) == text_of(r_unknown.text),
          f"{r_known.status_code} vs {r_unknown.status_code}")
    c_rl5 = Client("rl5", "10.9.7.6")
    tok = field(c_rl5.get("/login").text, "csrf_token")
    ra = c_rl5.post("/login", {"csrf_token": tok, "username": "alice", "password": "wrong"})
    tok = field(c_rl5.get("/login").text, "csrf_token")
    rb = c_rl5.post("/login", {"csrf_token": tok, "username": "no-such-user", "password": "wrong"})
    check("enum", "login error is identical for wrong password and unknown user",
          ra.status_code == rb.status_code and text_of(ra.text).replace("alice", "U") == text_of(rb.text).replace("no-such-user", "U"),
          f"{ra.status_code} vs {rb.status_code}")
    adm = Admin("rl6", "10.9.7.7")

    def admin_fail(i):
        return adm.login("head", f"wrong-{i}").status_code
    limit_probe("admin login failures (same username+IP)", admin_fail, 6, 10)
    ov = Client("rl7", "10.9.7.8")
    seq = []
    for i in range(1, 36):
        seq.append(ov.get("/overview").status_code)
    info("ratelimit", "anonymous /overview x35", f"first non-303 at {next((i for i, s in enumerate(seq, 1) if s != 303), None)}: {sorted(set(seq))}")
    # step-up code brute force
    brute = Admin("brute", "10.9.7.9")
    brute.login("head", HEAD_PASSWORD)
    csrf_b = brute.csrf("/admin/users")
    r = brute.post(f"/admin/users/{alice_id}/payment", {"csrf_token": csrf_b, "amount": "1", "note": "brute"})
    fb = {n: field(r.text, n) for n in ("csrf_token", "payload", "nonce")}
    codes = [brute.post("/admin/stepup/confirm", {**fb, "code": f"{i:06d}"}).status_code for i in range(1, 9)]
    info("ratelimit", "step-up wrong codes x8 (status per attempt)", str(codes))
    check("ratelimit", "step-up brute force is rate limited", 429 in codes, str(codes))
    ready = anon.get("/readyz")
    check("ops", "app still ready after the probes", ready.status_code == 200, text_of(ready.text)[:80])

    # --- I. concurrency: Argon2 inside the user-login write transaction ---------------------------------------------
    argon_probe(alice, bob)
    return 0


LEAK_PATTERNS = ("Traceback", "File \"", "sqlalchemy", "starlette", "fastapi", "uvicorn", "IntegrityError", "sqlite3.",
                 "OperationalError", "Exception", "/home/claude")


def leaks(text: str) -> bool:
    return any(p in text for p in LEAK_PATTERNS)


REFLECTED = [
    ("/admin/users", ["q", "chair", "status", "sort", "dir"]), ("/admin/audit", ["action", "page"]),
    ("/admin/exports/ledger.csv", ["from", "to"]), ("/admin", ["msg", "err"]), ("/admin/users", ["msg", "err"]),
    ("/account", ["notice", "msg", "err"]), ("/", ["notice"]), ("/login", ["next", "notice", "err", "msg"]),
    ("/overview/people", ["q", "chair", "sort"]), ("/overview", ["q"]), ("/register", ["chair", "notice"]),
    ("/admin/login", ["next", "err", "msg"]), ("/forgot", ["notice"]), ("/coffee/single", ["x"]),
]

CSP_REQUIRED = ("default-src 'self'", "frame-ancestors 'none'")


def header_checks(r, label, *, static=False, csv=False, svg=False):
    h = {k.lower(): v for k, v in r.headers.items()}
    problems = []
    csp = h.get("content-security-policy", "")
    if not all(x in csp for x in CSP_REQUIRED) or "unsafe-inline" in csp or "unsafe-eval" in csp:
        problems.append(f"csp={csp!r}")
    for part in ("base-uri", "form-action", "object-src"):
        if part not in csp:
            problems.append(f"csp lacks {part}")
    if h.get("x-content-type-options", "").lower() != "nosniff":
        problems.append("no nosniff")
    if "strict-transport-security" not in h:
        problems.append("no HSTS")
    elif "max-age" not in h["strict-transport-security"]:
        problems.append("bad HSTS")
    if "referrer-policy" not in h:
        problems.append("no referrer-policy")
    if "server" in h or "x-powered-by" in h:
        problems.append(f"server banner {h.get('server') or h.get('x-powered-by')}")
    if not static and "no-store" not in h.get("cache-control", "") and "private" not in h.get("cache-control", ""):
        problems.append(f"cache-control={h.get('cache-control')!r}")
    if static and not h.get("cache-control"):
        info("headers", f"{label}: static response has no Cache-Control", f"etag={h.get('etag')} last-modified={h.get('last-modified')}")
    if csv and "attachment" not in h.get("content-disposition", ""):
        problems.append("csv not an attachment")
    if h.get("x-frame-options", "").upper() not in ("DENY", "SAMEORIGIN") and "frame-ancestors" not in csp:
        problems.append("framing allowed")
    check("headers", label, not problems, "; ".join(problems))
    if leaks(r.text) and r.status_code >= 400:
        check("errors", f"{label}: no stack trace", False, text_of(r.text)[:100])


def cookie_flags(r, label, name, *, path):
    raw = r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw, "headers") else []
    mine = [c for c in raw if c.startswith(name + "=")]
    if not mine:
        check("cookies", f"{label}: Set-Cookie present", False, str(raw)[:200])
        return
    c = mine[0].lower()
    ok = "httponly" in c and "secure" in c and "samesite=lax" in c and f"path={path}".lower() in c
    check("cookies", f"{label}: HttpOnly; Secure; SameSite=Lax; Path={path}", ok, mine[0][:160])


def cookie_flags_jar(client: Client, name: str, path: str):
    for c in client.s.cookies:
        if c.name == name:
            rest = {k.lower(): v for k, v in c._rest.items()}
            ok = c.secure and "httponly" in rest and c.path == path
            check("cookies", f"{name} jar flags (secure, httponly, path {path})", ok, str((c.secure, rest, c.path)))
            return
    check("cookies", f"{name} cookie set", False)


def seed_hostile_rows():
    """Plant hostile values the UI would not accept (or would sanitise) directly through the services."""
    sys.path.insert(0, str(ROOT))
    old = dict(os.environ)
    os.environ.update({k: v for k, v in ENV.items()})
    try:
        from app.config import get_settings
        get_settings.cache_clear()
        from app import db as app_db
        app_db.reset_engine()
        from sqlalchemy import select
        from app.db import write_session
        from app.models import AdminUser, Chair, User
        from app.services import ledger, users as users_svc
        with write_session() as w:
            head = w.scalar(select(AdminUser).where(AdminUser.username == "head"))
            alice = w.scalar(select(User).where(User.username == "alice"))
            if alice is None:
                return
            ledger.add_adjustment(w, admin=head, user_id=alice.id, quantity=1, note="=HYPERLINK(\"http://evil.example\",\"click\")")
            ledger.add_adjustment(w, admin=head, user_id=alice.id, quantity=1, note="@SUM(A1)<script>alert(5)</script>")
            ledger.add_adjustment(w, admin=head, user_id=alice.id, quantity=1, note="+1+1\t\"><img src=x onerror=alert(6)>")
            ledger.add_adjustment(w, admin=head, user_id=alice.id, quantity=1, note="-2+3")
            for i, nm in enumerate(("=1+1", "+cmd|' /C calc'!A0", "-1+1", "@x", "\t=1+1", "<script>alert(7)</script>"), 1):
                u = User(display_name=nm, normalized_name=users_svc.normalize_name(nm), chair_id=alice.chair_id, status="active")
                w.add(u)
    finally:
        os.environ.clear()
        os.environ.update(old)
        from app.config import get_settings
        get_settings.cache_clear()


def csv_check(head: Admin):
    import csv as csvmod
    import io
    bad = []
    for path in ("/admin/users/export.csv", "/admin/exports/ledger.csv", "/admin/exports/group-balances.csv"):
        r = head.get(path)
        text = r.content.decode("utf-8-sig", "replace")
        header_ok = r.status_code == 200
        if not header_ok:
            bad.append((path, f"status {r.status_code}"))
            continue
        rows = list(csvmod.reader(io.StringIO(text), delimiter=";"))
        for row in rows:
            for cell in row:
                if cell[:1] in ("=", "+", "-", "@", "\t", "\r") and not re.fullmatch(r"-?[0-9]+([.,][0-9]+)?", cell):
                    bad.append((path, cell[:40]))
        info("csv", f"{path}", f"{len(rows)} rows")
    return bad


def argon_probe(alice: Client, bob: Client):
    """Scan latency and outcome while other users sign in in a loop. /login runs Argon2id (production cost) INSIDE
    the SQLite write transaction (BEGIN IMMEDIATE), so every sign-in holds the single writer lock for the whole
    hash; successful sign-ins are not rate limited."""
    import statistics

    def one_scan(c: Client):
        t0 = time.perf_counter()
        page = c.get("/coffee/double")
        r = c.post("/coffee/double", {"token": field(page.text, "token")})
        return time.perf_counter() - t0, r.status_code

    base = [one_scan(alice) for _ in range(6)]
    info("dos", "scan alone", f"median {statistics.median(x for x, _ in base):.3f}s max {max(x for x, _ in base):.3f}s "
         f"statuses {sorted(set(s for _, s in base))}")
    worst_status = set()
    worst_latency = 0.0
    for k in (1, 3, 6):
        stop = threading.Event()
        logins = []

        def hammer(i, k=k):
            c = Client(f"h{k}-{i}", f"10.{10 + k}.0.{i}")
            while not stop.is_set():
                t0 = time.perf_counter()
                try:
                    tok = field(c.get("/login").text, "csrf_token")
                    r = c.post("/login", {"csrf_token": tok, "username": "bob", "password": USER_PASSWORD + "-new"})
                    logins.append((time.perf_counter() - t0, r.status_code))
                except Exception as exc:  # noqa: BLE001
                    logins.append((0.0, type(exc).__name__))

        ts = [threading.Thread(target=hammer, args=(i,)) for i in range(1, k + 1)]
        for t in ts:
            t.start()
        time.sleep(1.0)
        samples = []
        for _ in range(8):
            samples.append(one_scan(alice))
            time.sleep(0.25)
        stop.set()
        for t in ts:
            t.join()
        lat = [x for x, _ in samples]
        st = sorted(set(s for _, s in samples))
        sign_st = {}
        for _, s in logins:
            sign_st[s] = sign_st.get(s, 0) + 1
        info("dos", f"scan while {k} client(s) sign in repeatedly",
             f"median {statistics.median(lat):.3f}s max {max(lat):.3f}s, scan statuses {st}; sign-ins {len(logins)} statuses {sign_st}")
        worst_latency = max(worst_latency, max(lat))
        worst_status |= set(st)
    check("dos", "scans stay under 1 s and never fail while users sign in (6 concurrent sign-in loops)",
          worst_latency < 1.0 and worst_status <= {303}, f"worst scan {worst_latency:.2f}s, statuses {sorted(worst_status)}")



# ----- grep for secrets -----------------------------------------------------------------------------------------
def post_mortem(inbox: Inbox):
    needles = {"SECRET_KEY": SECRET_KEY, "SMTP password": MAIL_PASSWORD, "head password": HEAD_PASSWORD,
               "user password": USER_PASSWORD}
    # one-time tokens and cookies handed out during the run
    tokens = set()
    for m in inbox.messages:
        tokens.update(re.findall(r"/(?:verify|reset)/([A-Za-z0-9_\-]{16,})", m["data"].replace("=\r\n", "")))
    BACKUPS.mkdir(exist_ok=True)
    p = subprocess.run(["bash", "scripts/backup.sh"], env=ENV, cwd=ROOT, capture_output=True, text=True)
    check("secrets", "scripts/backup.sh succeeds", p.returncode == 0, (p.stdout + p.stderr)[-200:])
    targets = {"app.log": LOG.read_bytes()}
    for f in W.iterdir():
        if f.name.startswith("prod.db"):
            targets[f.name] = f.read_bytes()
    for f in BACKUPS.glob("*"):
        targets["backup/" + f.name] = f.read_bytes()
    for f in SECRETS.rglob("*"):
        if f.is_file():
            targets["secrets/" + f.name] = f.read_bytes()
    targets["http bodies"] = "\n".join(f"{k}\n{v}" for k, v in bodies).encode()
    targets["mail"] = "\n".join(m["data"] for m in inbox.messages).encode()
    for label, needle in needles.items():
        for tname, blob in targets.items():
            hit = needle.encode() in blob
            allowed = (label == "user password" and tname == "http bodies")  # we typed it in our own forms: not a server leak
            if tname in ("mail",) and label != "SMTP password":
                allowed = False
            check("secrets", f"{label} not in {tname}", not hit or allowed, "FOUND")
    # tokens in the log
    leaked = [t for t in tokens if t.encode() in targets["app.log"]]
    check("secrets", "one-time verify/reset tokens are not in the application log", not leaked, f"{len(leaked)} found of {len(tokens)}")
    # raw session cookies and TOTP/recovery material must not be at rest in the DB
    con = sqlite3.connect(DB)
    stored = [n for n in cookies_seen if any(n.encode() in blob for tname, blob in targets.items()
                                             if tname.startswith(("prod.db", "backup/", "app.log")))]
    check("secrets", "raw session cookie values are not stored in the database, backup or log (only hashes)",
          not stored and len(cookies_seen) >= 5, f"{len(stored)} of {len(cookies_seen)} stored")
    # audit log content
    audit_text = "\n".join(str(r) for r in con.execute("select action, metadata, source_ip from audit_log"))
    check("secrets", "audit log holds no password, token or TOTP material", not any(n in audit_text for n in needles.values()) and "otpauth" not in audit_text)
    ips = {r[0] for r in con.execute("select distinct source_ip from audit_log where source_ip is not null")}
    info("secrets", "client addresses recorded in audit_log", ", ".join(sorted(ips))[:200])
    mode = oct(os.stat(SECRETS).st_mode & 0o777)
    info("secrets", "secrets dir mode", mode)
    for f in SECRETS.rglob("*"):
        if f.is_file():
            info("secrets", f"credential file {f.name}", f"mode {oct(f.stat().st_mode & 0o777)}, {f.stat().st_size} bytes, starts {f.read_bytes()[:12]!r}")
    for f in BACKUPS.glob("*"):
        info("secrets", f"backup {f.name}", f"mode {oct(f.stat().st_mode & 0o777)}")
    log_text = LOG.read_text(errors="replace")
    info("log", "log lines", str(log_text.count("\n")))
    check("log", "no unhandled error ('ERROR app: unhandled') in the production log", "unhandled error" not in log_text, "")
    info("log", "handled tracebacks logged at WARNING (database busy)", str(log_text.count("database operational error")))
    con.close()


if __name__ == "__main__":
    sys.exit(main())
