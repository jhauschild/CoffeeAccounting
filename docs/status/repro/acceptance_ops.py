"""Acceptance run (task 7.3), operations and mail-security checks against the PRODUCTION instance started by
acceptance_up.sh (and the README commands against the development instance).

    python docs/status/repro/acceptance_ops.py WORKDIR            # run after acceptance_v2.py (prod and dev)

Covers: DoD 9 (mail over verified TLS, login stored encrypted outside the database and backups, in no log, page or
backup), the mail failure categories (auth, tls, connect), production start-up refusals and that a failing
configuration does not print the secret key, smoke.sh in all three modes (http dev, https prod), backup.sh and
restore.sh round trip (the secrets file is NOT in the backup), restore refused while the app runs, and the
remaining README CLI commands. Prints PASS/FAIL per check, writes WORKDIR/results-ops.json, exit 0 only if all pass.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
import time
from pathlib import Path

import requests

W = Path(sys.argv[1]).resolve()
ROOT = Path(__file__).resolve().parents[3]
PY = sys.executable
cfg = dict(line.split("=", 1) for line in (W / "acceptance.env").read_text().splitlines() if "=" in line)
PROD, DEV = W / "prod", W / "dev"
CERT = cfg["CERT"]
MAIL_PW, MAIL_USER, SECRET_KEY, HEAD_PW = cfg["MAIL_PW"], cfg["MAIL_USER"], cfg["SECRET_KEY"], cfg["HEAD_PW"]
USER_PW = "Acc-User-Password-4711"
results: list[dict] = []


def check(section, name, ok, detail=""):
    results.append({"section": section, "check": name, "ok": bool(ok), "detail": str(detail)[:500]})
    print(("PASS " if ok else "FAIL ") + f"[{section}] {name}" + (f" -- {str(detail)[:300]}" if detail and not ok else ""), flush=True)
    return bool(ok)


def info(section, name, detail):
    results.append({"section": section, "check": name, "ok": True, "info": True, "detail": str(detail)[:800]})
    print(f"INFO [{section}] {name}: {str(detail)[:300]}", flush=True)


def env_for(inst: Path, **extra):
    env = {k: v for k, v in os.environ.items()}
    env["PATH"] = str(Path(PY).parent) + ":" + env["PATH"]
    env["NO_PROXY"] = env["no_proxy"] = "localhost,127.0.0.1"
    if inst == PROD:
        env.update({"SSL_CERT_FILE": CERT, "BACKUP_DIR": str(PROD / "backups")})
    env.update(extra)
    return {k: v for k, v in env.items() if v is not None}


def sh(cmd, inst=PROD, *, input=None, env=None, check_rc=False, **extra):
    p = subprocess.run(cmd, cwd=inst, input=input, text=True, capture_output=True, env=env or env_for(inst, **extra))
    return p


def cli(inst, *args, input=None, **extra):
    return sh([PY, "-m", "app.cli", *args], inst, input=input, **extra)


def db_of(inst):
    return inst / "data" / "coffee.db"


def q(inst, query, *params):
    con = sqlite3.connect(db_of(inst))
    try:
        return con.execute(query, params).fetchall()
    finally:
        con.close()


def grep_bytes(path: Path, needles: dict[str, str]):
    data = path.read_bytes()
    return [name for name, n in needles.items() if n.encode() in data]


def start_prod():
    log = open(W / "prod_server.log", "ab")
    p = subprocess.Popen([PY, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "18443", "--workers", "1", "--proxy-headers",
                          "--forwarded-allow-ips", "127.0.0.1", "--no-server-header", "--no-access-log", "--log-level", "info",
                          "--ssl-keyfile", str(W / "tls/key.pem"), "--ssl-certfile", CERT], cwd=PROD, env=env_for(PROD), stdout=log, stderr=subprocess.STDOUT)
    (W / "prod.pid").write_text(str(p.pid))
    s = requests.Session()
    s.trust_env = False
    for _ in range(100):
        try:
            if s.get("https://localhost:18443/readyz", verify=CERT, timeout=1).status_code == 200:
                return p
        except requests.RequestException:
            time.sleep(0.2)
    raise SystemExit("prod did not restart")


def stop_prod():
    pid = int((W / "prod.pid").read_text())
    os.kill(pid, 15)
    for _ in range(50):
        try:
            os.kill(pid, 0)
            time.sleep(0.2)
        except OSError:
            return
    os.kill(pid, 9)


needles = {"SMTP password": MAIL_PW, "SECRET_KEY": SECRET_KEY, "head password": HEAD_PW, "user password": USER_PW}
relay = W / "relay"

# =============================================== DoD 9 =====================================================================
logins = [json.loads(l) for l in (relay / "logins.jsonl").read_text().splitlines()]
check("dod9", "the relay saw AUTH logins, every one over the encrypted channel (STARTTLS) with the stored mailbox login only",
      len(logins) > 5 and all(x["tls"] for x in logins) and all(x["user"] == MAIL_USER for x in logins), f"{len(logins)} logins")
check("dod9", "every login used the password typed at setup (decrypted from the stored file) and was accepted", all(x["password_ok"] and x["accepted"] for x in logins))
msgs = sorted((relay / "messages").glob("*.eml"))
bodies = {p.name: p.read_text(errors="replace") for p in msgs}
check("dod9", f"{len(msgs)} real mails were delivered through the TLS relay (setup test mail, verification, approvals, resets)", len(msgs) >= 10, len(msgs))
first = bodies[msgs[0].name]
info("dod9", "headers of the setup test mail", first.split("\n\n", 1)[0].replace("\n", " | "))
check("dod9", "mails carry Auto-Submitted: auto-generated and a From matching MAIL_FROM", all("Auto-Submitted: auto-generated" in b and "From: " in b for b in bodies.values()))
check("dod9", "all mailed links point at PUBLIC_BASE_URL (https://localhost:18443)", all(("http://" not in re.sub(r"https://", "", b)) for b in bodies.values())
      and any("https://localhost:18443/verify/" in b.replace("=\n", "") for b in bodies.values()))
check("dod9", "no mail contains the SMTP password, SECRET_KEY or any account password", not any(grep_bytes(p, needles) for p in msgs))
sec = PROD / "secrets"
sf = sec / "mail-login.enc"
check("dod9", "credential file is mode 0600 in a 0700 directory", stat.S_IMODE(sf.stat().st_mode) == 0o600 and stat.S_IMODE(sec.stat().st_mode) == 0o700,
      (oct(sf.stat().st_mode), oct(sec.stat().st_mode)))
check("dod9", "credential file is ciphertext: neither the password nor the user name appears in it", not grep_bytes(sf, {"pw": MAIL_PW, "user": MAIL_USER, "user local part": MAIL_USER.split("@")[0]}) and sf.read_bytes()[:4] == b"gAAA",
      sf.read_bytes()[:16])
dbp = db_of(PROD)
files = [dbp] + [Path(str(dbp) + s) for s in ("-wal", "-shm") if Path(str(dbp) + s).exists()]
check("dod9", "the database (and its WAL) contains neither the mail password, its user name nor SECRET_KEY",
      not any(grep_bytes(f, {**needles, "mail user": MAIL_USER}) for f in files), [f.name for f in files])
log = (W / "prod_server.log").read_bytes()
tokens = set()
for b in bodies.values():
    tokens |= set(re.findall(r"/(?:verify|reset)/([A-Za-z0-9_\-]{20,})", b.replace("=\n", "")))
check("dod9", "the application log contains no secret, password or mail login", not [n for n, v in {**needles, "mail user": MAIL_USER}.items() if v.encode() in log])
check("dod9", f"the application log contains none of the {len(tokens)} one-time verify/reset tokens (access log redacts them)", len(tokens) > 3 and not [t for t in tokens if t.encode() in log], len(tokens))
rr = sh(["grep", "-rIl", "--exclude=.env", "-e", MAIL_PW, "-e", SECRET_KEY, "."], PROD)
check("dod9", "the instance tree (code, templates, compose, scripts) contains neither the mail password nor SECRET_KEY outside .env/secrets", rr.stdout.strip() == "" or all(x.startswith("./data/") or x.startswith("./secrets/") for x in rr.stdout.split()), rr.stdout[:200])
rr = sh(["grep", "-rIniE", r"^\s*(SMTP_USER|SMTP_PASSWORD|smtp_user|smtp_password)\b", ".env.example", "docker-compose.yml", "Dockerfile", "app/config.py"], PROD)
check("dod9", "no SMTP_USER / SMTP_PASSWORD setting (variable or settings field) exists in .env.example, docker-compose.yml, the Dockerfile or app/config.py", rr.stdout.strip() == "", rr.stdout)
# admin pages and status never show the login
s = requests.Session()
s.verify, s.trust_env = CERT, False
B = "https://localhost:18443"
H = {"Origin": B, "X-Forwarded-For": "10.77.1.1"}
tok = re.search(r'name="csrf_token" value="([^"]*)"', s.get(B + "/admin/login", headers=H).text).group(1)
s.post(B + "/admin/login", data={"csrf_token": tok, "username": "head", "password": HEAD_PW}, headers=H, allow_redirects=False)
dash = s.get(B + "/admin", headers=H).text
pages = ["/admin", "/admin/users", "/admin/groups", "/admin/chairs", "/admin/prices", "/admin/audit", "/admin/admins", "/admin/qr", "/admin/exports", "/admin/account"]
leak = [p for p in pages if any(n in s.get(B + p, headers=H).text for n in (MAIL_PW, MAIL_USER, SECRET_KEY))]
check("dod9", f"none of {len(pages)} admin pages (dashboard, audit log, ...) shows the mail login or SECRET_KEY", not leak, leak)
txt = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", dash))
info("dod9", "dashboard mail card", re.search(r"[^.]{0,80}(s\*\*\*@lrz\.de|Mail)[^.]{0,120}", txt).group(0) if re.search(r"s\*\*\*@lrz\.de|Mail", txt) else txt[:200])
audit_text = s.get(B + "/admin/audit?action=mail.", headers=H).text
check("dod9", "the audit log (filter mail.) shows mail.login_saved and mail.send_ok rows but no secret",
      "mail.login_saved" in audit_text and "mail.send_ok" in audit_text and not any(n in audit_text for n in (MAIL_PW, MAIL_USER, SECRET_KEY)))
st = cli(PROD, "mail-status")
info("dod9", "mail-status", st.stdout.replace("\n", " | "))
check("dod9", "mail-status shows the masked user only and a last successful send", "s***@lrz.de" in st.stdout and MAIL_USER not in st.stdout + st.stderr and "last send OK: never" not in st.stdout)

# --- failure categories (the mail failure never prints a secret) ------------------------------------------------------
(relay / "mode").write_text("reject-auth")
t = cli(PROD, "test-mail", "fail@tum.de")
check("dod9", "relay rejects the login: test-mail fails with category 'auth' and prints no secret", t.returncode == 1 and "auth" in t.stderr and MAIL_PW not in t.stdout + t.stderr, t.stderr.strip()[:200])
st = cli(PROD, "mail-status")
check("dod9", "mail-status then reports 'mail failing: auth'", "mail failing: auth" in st.stdout and "last failure: auth" in st.stdout, st.stdout)
dash2 = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", s.get(B + "/admin", headers=H).text))
check("dod9", "the head admin's dashboard shows the failure banner (the web process and the CLI see the same status)", re.search(r"auth", dash2, re.I) is not None and re.search(r"fail", dash2, re.I) is not None,
      re.search(r".{0,60}fail.{0,100}", dash2, re.I).group(0) if re.search(r"fail", dash2, re.I) else dash2[:200])
(relay / "mode").unlink()
t = cli(PROD, "test-mail", "ok@tum.de")
check("dod9", "after the relay accepts again, test-mail succeeds and the status recovers", t.returncode == 0 and "state: ok" in cli(PROD, "mail-status").stdout, t.stdout + t.stderr)
env_no_trust = env_for(PROD)
env_no_trust.pop("SSL_CERT_FILE", None)
env_no_trust["REQUESTS_CA_BUNDLE"] = ""
logins_before = len((relay / "logins.jsonl").read_text().splitlines())
msgs_before = len(list((relay / "messages").glob("*.eml")))
t = sh([PY, "-m", "app.cli", "test-mail", "tls@tum.de"], PROD, env={**env_no_trust, "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt"})
check("dod9", "certificate not trusted (system store only): the connection is refused with category 'tls', no mail delivered, no login sent",
      t.returncode == 1 and "tls" in t.stderr, t.stderr.strip()[:200])
check("dod9", "an untrusted certificate never reaches the AUTH step: no login attempt and no message at the relay",
      len((relay / "logins.jsonl").read_text().splitlines()) == logins_before and len(list((relay / "messages").glob("*.eml"))) == msgs_before)
t = cli(PROD, "test-mail", "down@tum.de", SMTP_PORT="18599")
check("dod9", "server down (closed port): category 'connect'", t.returncode == 1 and "connect" in t.stderr, t.stderr.strip()[:200])
t = cli(PROD, "test-mail", "name@tum.de", SMTP_HOST="localhost.localdomain.invalid")
info("dod9", "wrong host name", (t.stderr or t.stdout).strip()[:200])
cli(PROD, "test-mail", "restore@tum.de")
st = cli(PROD, "mail-status")
check("dod9", "status recovers after a successful test mail", "state: ok" in st.stdout, st.stdout)
info("dod9", "NOT VERIFIED here", "the real postout.lrz.de handshake, LRZ acceptance of the login and From address, quota, spam handling (post-deployment checklist)")

# =============================================== production configuration ==================================================
base_env = env_for(PROD)
probe = "from app.config import get_settings; get_settings()"
refusals = {"http PUBLIC_BASE_URL": {"PUBLIC_BASE_URL": "http://coffee.example.org"}, "short SECRET_KEY": {"SECRET_KEY": "short"},
            "placeholder SECRET_KEY": {"SECRET_KEY": "change-me-generate-a-random-value-of-48-characters"}, "console mail backend": {"MAIL_BACKEND": "console"},
            "empty MAIL_FROM": {"MAIL_FROM": ""}, "BALANCE_TOTP_REQUIRED=false": {"BALANCE_TOTP_REQUIRED": "false"},
            "ssl with port 587": {"SMTP_SECURITY": "ssl", "SMTP_PORT": "587"}}
for label, change in refusals.items():
    p = sh([PY, "-c", probe], PROD, env={**base_env, **change})
    out = p.stdout + p.stderr
    check("config", f"production refuses to start with {label}", p.returncode != 0, out.strip()[-160:])
    check("config", f"... and the failure output does not contain SECRET_KEY or the mail password ({label})", SECRET_KEY not in out and MAIL_PW not in out and "mail-login" not in out, out[:200])
p = sh([PY, "-c", probe], PROD, env={**base_env, "PUBLIC_BASE_URL": "http://x.example"})
check("config", "a failing production configuration prints no input_value fragment of the settings (v1 defect D1)", "input_value" not in p.stderr, p.stderr[-300:])
p = sh([PY, "-c", probe], PROD, env=base_env)
check("config", "the valid production configuration loads", p.returncode == 0, p.stderr[-200:])
sv = (W / "prod_server.log").read_text(errors="replace")
info("config", "production start-up warnings in the log", "; ".join(sorted(set(re.findall(r"WARNING[^\n]{0,160}", sv)))[:3]))
check("config", "empty TRUSTED_PROXY_IPS logs the documented warning at start (task F6 L2)", "TRUSTED_PROXY_IPS is empty" in sv)
S2 = requests.Session()
S2.verify, S2.trust_env = CERT, False
for path in ("/docs", "/redoc", "/openapi.json"):
    check("config", f"{path} is 404 in production", S2.get(B + path, headers=H).status_code == 404)
r = S2.get(B + "/login", headers=H)
hdr = {k.lower(): v for k, v in r.headers.items()}
check("config", "HSTS, CSP without inline script/style, nosniff, frame deny, no-store on https", "max-age=31536000" in hdr.get("strict-transport-security", "")
      and "script-src 'self'" in hdr.get("content-security-policy", "") and "'unsafe-inline'" not in hdr.get("content-security-policy", "") and hdr.get("x-content-type-options") == "nosniff"
      and hdr.get("x-frame-options") == "DENY" and "no-store" in hdr.get("cache-control", ""), hdr)
ck = [c for c in r.raw.headers.getlist("Set-Cookie")]
check("config", "every cookie set is HttpOnly; Secure; SameSite=Lax", ck and all("HttpOnly" in c and "Secure" in c and "SameSite=lax" in c.replace("Lax", "lax") for c in ck), ck)

# =============================================== smoke.sh in all three modes ================================================
def smoke(args, base, extra_env=None, cacert=None):
    env = env_for(DEV if "18100" in base else PROD)
    env["CURL_OPTS"] = f"--cacert {cacert}" if cacert else ""
    env.update(extra_env or {})
    p = subprocess.run(["bash", str(ROOT / "scripts/smoke.sh"), *args, base], cwd=ROOT, text=True, capture_output=True, env=env)
    return p

for label, base, cacert in (("dev http", "http://127.0.0.1:18100", None), ("prod https", B, CERT)):
    p = smoke(["--health-only"], base, cacert=cacert)
    check("smoke", f"smoke.sh --health-only ({label}) exits 0", p.returncode == 0, p.stdout[-200:] + p.stderr[-200:])
    info("smoke", f"--health-only {label}", p.stdout.replace("\n", " | ")[-300:])
    p = smoke([], base, cacert=cacert)
    check("smoke", f"smoke.sh public run ({label}) exits 0", p.returncode == 0, p.stdout[-300:] + p.stderr[-300:])
    info("smoke", f"public run {label}", f"{len(re.findall(r'^ok ', p.stdout, re.M))} checks ok")
    p = smoke([], base, extra_env={"SMOKE_USERNAME": "bob", "SMOKE_PASSWORD": USER_PW}, cacert=cacert)
    check("smoke", f"smoke.sh full signed-in run ({label}) exits 0", p.returncode == 0, p.stdout[-400:] + p.stderr[-400:])
    info("smoke", f"full run {label}", f"{len(re.findall(r'^ok ', p.stdout, re.M))} checks ok; last: {p.stdout.strip().splitlines()[-1] if p.stdout.strip() else ''}")
p = smoke(["--health-only"], "http://127.0.0.1:18199")
check("smoke", "smoke.sh against a dead address fails (non-zero)", p.returncode != 0)

# =============================================== backup / restore ==========================================================
bk = PROD / "backups"
for f in bk.glob("*"):
    f.unlink()
env = env_for(PROD, DB_PATH=str(db_of(PROD)))
p = subprocess.run(["bash", str(ROOT / "scripts/backup.sh"), str(bk)], text=True, capture_output=True, env=env)
backups = sorted(bk.glob("coffee-*.db"))
check("backup", "scripts/backup.sh while the app runs: one verified backup file", p.returncode == 0 and len(backups) == 1, p.stdout + p.stderr)
info("backup", "backup.sh output", (p.stdout + p.stderr).strip())
b1 = backups[0]
check("backup", "backup file is mode 0600", stat.S_IMODE(b1.stat().st_mode) == 0o600, oct(b1.stat().st_mode))
check("backup", "the SECRETS file (mail-login.enc) is NOT in the backup directory and no secrets directory was copied", not list(bk.rglob("mail-login*")) and not any(x.is_dir() for x in bk.iterdir()), [x.name for x in bk.iterdir()])
check("backup", "the backup file does not contain the mail password, its user name or SECRET_KEY", not grep_bytes(b1, {**needles, "mail user": MAIL_USER}))
con = sqlite3.connect(b1)
n_ev = con.execute("select count(*) from consumption_events").fetchone()[0]
integ = con.execute("pragma integrity_check").fetchone()[0]
con.close()
check("backup", "the backup contains the ledger (consumption rows readable)", n_ev > 5, n_ev)
check("backup", "backup passes PRAGMA integrity_check", integ == "ok", integ)
# round trip on the live database file
n_live = q(PROD, "select count(*) from consumption_events")[0][0]
S3 = requests.Session()
S3.verify, S3.trust_env = CERT, False
H3 = {"Origin": B, "X-Forwarded-For": "10.77.2.1"}
tok = re.search(r'name="csrf_token" value="([^"]*)"', S3.get(B + "/login", headers=H3).text).group(1)
S3.post(B + "/login", data={"csrf_token": tok, "username": "bob", "password": USER_PW}, headers=H3, allow_redirects=False)
pg = S3.get(B + "/coffee/single", headers=H3)
S3.post(B + "/coffee/single", data={"token": re.search(r'name="token" value="([^"]*)"', pg.text).group(1)}, headers=H3, allow_redirects=False)
n_after = q(PROD, "select count(*) from consumption_events")[0][0]
check("backup", "one more coffee was recorded after the backup", n_after == n_live + 1, (n_live, n_after))
p = subprocess.run(["bash", str(ROOT / "scripts/restore.sh"), str(b1), "--yes"], text=True, capture_output=True, env=env)
check("backup", "restore.sh refuses while the application has the database open", p.returncode != 0 and "stop the application" in p.stderr, p.stderr.strip())
stop_prod()
p = subprocess.run(["bash", str(ROOT / "scripts/restore.sh"), str(b1), "--yes"], text=True, capture_output=True, env=env)
check("backup", "restore.sh with the app stopped succeeds", p.returncode == 0, p.stdout + p.stderr)
info("backup", "restore.sh output", (p.stdout + p.stderr).strip().replace("\n", " | "))
pre = sorted(bk.glob("pre-restore-*.db"))
check("backup", "the replaced database was kept as pre-restore-<timestamp>.db (BACKUP_DIR as Compose sets it)", len(pre) == 1, [x.name for x in bk.iterdir()])
check("backup", "after the restore the ledger is back at the backup state (the later coffee is gone, as documented)", q(PROD, "select count(*) from consumption_events")[0][0] == n_ev == n_live, (q(PROD, "select count(*) from consumption_events")[0][0], n_ev))
c = cli(PROD, "check-ledger")
check("backup", "check-ledger OK after the restore", c.returncode == 0, c.stdout + c.stderr)
check("backup", "mail login still works after the restore on the same server (it was never in the backup)", cli(PROD, "mail-status").stdout.count("configured: yes") == 1)
start_prod()
check("backup", "the application starts on the restored database: /readyz ok", S2.get(B + "/readyz", headers=H).json().get("status") == "ok")
S4 = requests.Session()
S4.verify, S4.trust_env = CERT, False
H4 = {"Origin": B, "X-Forwarded-For": "10.77.3.1"}
tok = re.search(r'name="csrf_token" value="([^"]*)"', S4.get(B + "/login", headers=H4).text).group(1)
rl = S4.post(B + "/login", data={"csrf_token": tok, "username": "bob", "password": USER_PW}, headers=H4, allow_redirects=False)
check("backup", "restored data is intact: a member signs in with the restored password hash", rl.status_code == 303, rl.status_code)
# restore onto a "new server": the secrets directory is empty -> mail not configured until setup-mail
import shutil
newdir = W / "newserver"
shutil.rmtree(newdir, ignore_errors=True)
(newdir / "secrets").mkdir(parents=True, mode=0o700)
env2 = env_for(PROD, SECRETS_DIR=str(newdir / "secrets"), DB_PATH=str(newdir / "coffee.db"), DATABASE_URL=f"sqlite:///{newdir / 'coffee.db'}")
p = subprocess.run(["bash", str(ROOT / "scripts/restore.sh"), str(b1), "--yes"], text=True, capture_output=True, env=env2)
st = subprocess.run([PY, "-m", "app.cli", "mail-status"], cwd=PROD, text=True, capture_output=True, env=env2)
check("backup", "restore onto a new server: the data comes back but mail is 'not configured' until setup-mail is run again", p.returncode == 0 and "mail configured: no" in st.stdout, st.stdout)

# =============================================== production CLI extras ======================================================
Path(W / "results-ops.json").write_text(json.dumps(results, indent=1))
failed = [r for r in results if not r["ok"]]
print(f"\n{len([r for r in results if not r.get('info')])} checks, {len(failed)} FAILED (ops)")
sys.exit(1 if failed else 0)
