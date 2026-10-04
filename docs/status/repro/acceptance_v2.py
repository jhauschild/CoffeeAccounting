"""Acceptance driver (task 7.3): drives a RUNNING instance over HTTP like a browser and checks the v2 Definition of Done.

    python docs/status/repro/acceptance_v2.py --name prod --base https://localhost:18443 --cert WORK/tls/cert.pem \
        --db WORK/prod/data/coffee.db --mail-dir WORK/relay/messages --head-password '...' --repo WORK/prod \
        --out WORK/results-prod.json [--cli-env KEY=VALUE ...]

Start the instances with docs/status/repro/acceptance_up.sh. The same script runs against the development instance
(file mail backend: --mail-dir WORK/dev/mails) and the production one (TLS SMTP relay: --mail-dir WORK/relay/messages).
Every check prints PASS/FAIL; money checks are cross-checked with direct SQLite queries (no application code).
Exit code 0 only when every check passed. Test-only shortcuts, each stated where used: a step-up window is "expired"
by writing admin_sessions.stepup_until in the past (waiting 5 real minutes per case would add nothing).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import email
import email.policy
import html as htmlmod
import json
import re
import sqlite3
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pyotp
import requests

ap = argparse.ArgumentParser()
ap.add_argument("--name", required=True)
ap.add_argument("--base", required=True)
ap.add_argument("--cert", default="")
ap.add_argument("--db", required=True)
ap.add_argument("--mail-dir", required=True)
ap.add_argument("--head-password", required=True)
ap.add_argument("--repo", required=True, help="the instance's git-archive copy (cwd for the CLI, holds .env)")
ap.add_argument("--out", required=True)
ap.add_argument("--cli-env", action="append", default=[])
ap.add_argument("--py", default=sys.executable)
ARGS = ap.parse_args()

BASE = ARGS.base.rstrip("/")
VERIFY = ARGS.cert or True
DB = ARGS.db
MAIL_DIR = Path(ARGS.mail_dir)
USER_PW = "Acc-User-Password-4711"
GUEST_NAMES = {"guest1": "Gerda Gast", "guest2": "Gustav Gast", "guestx": "Gisela Gast", "guest3": "Gunnar Gast"}
results: list[dict] = []
_ip = [0]


def check(section: str, name: str, ok: bool, detail: str = "") -> bool:
    results.append({"section": section, "check": name, "ok": bool(ok), "detail": str(detail)[:400]})
    print(("PASS " if ok else "FAIL ") + f"[{section}] {name}" + (f" -- {str(detail)[:300]}" if detail and not ok else ""), flush=True)
    return bool(ok)


def info(section: str, name: str, detail: str) -> None:
    results.append({"section": section, "check": name, "ok": True, "info": True, "detail": str(detail)[:600]})
    print(f"INFO [{section}] {name}: {detail}", flush=True)


def sql(query: str, *params):
    con = sqlite3.connect(DB, timeout=30)
    try:
        return con.execute(query, params).fetchall()
    finally:
        con.close()


def one(query: str, *params):
    rows = sql(query, *params)
    return rows[0][0] if rows else None


def hexid(u: str) -> str:
    return u.replace("-", "")


def dashed(h: str) -> str:
    return str(uuid.UUID(h))


def text_of(htmltext: str) -> str:
    return re.sub(r"\s+", " ", htmlmod.unescape(re.sub(r"<[^>]+>", " ", htmltext)))


def field(body: str, name: str) -> str:
    m = re.search(rf'name="{re.escape(name)}" value="([^"]*)"', body)
    if not m:
        raise AssertionError(f"form field {name} not found")
    return htmlmod.unescape(m.group(1))


def next_ip() -> str:
    _ip[0] += 1
    return f"10.33.{_ip[0] // 250}.{_ip[0] % 250 + 1}"


class Client:
    def __init__(self, label: str):
        self.label = label
        self.ip = next_ip()
        self.s = requests.Session()
        self.s.verify = VERIFY
        self.s.trust_env = False

    def req(self, method, path, data=None, headers=None, **kw):
        h = {"X-Forwarded-For": self.ip}
        if method == "POST":
            h["Origin"] = BASE
        h.update(headers or {})
        return self.s.request(method, BASE + path, data=data, headers=h, allow_redirects=False, timeout=60, **kw)

    def get(self, path, **kw):
        return self.req("GET", path, **kw)

    def post(self, path, data=None, **kw):
        return self.req("POST", path, data=data, **kw)

    def csrf(self, path):
        return field(self.get(path).text, "csrf_token")

    def login(self, username, password):
        tok = self.csrf("/login")
        return self.post("/login", {"csrf_token": tok, "username": username, "password": password})


class Admin(Client):
    secret: str | None = None

    def login(self, username, password):
        tok = field(self.get("/admin/login").text, "csrf_token")
        return self.post("/admin/login", {"csrf_token": tok, "username": username, "password": password})

    def csrf(self, path="/admin"):
        return field(self.get(path).text, "csrf_token")

    def enrol(self):
        r = self.get("/admin/totp/setup")
        sec = re.sub(r"\s+", "", re.search(r"((?:[A-Z2-7]{4} ){3,}[A-Z2-7]{4})", text_of(r.text)).group(1))
        r = self.post("/admin/totp/setup", {"csrf_token": field(r.text, "csrf_token"), "code": pyotp.TOTP(sec).now()})
        self.secret = sec
        return sec, re.findall(r"\b[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}\b", r.text)


USED_CODES: dict[str, set] = {}


def fresh_code(secret: str) -> str:
    """A TOTP code not used before for this secret (the server accepts a code once): wait for the next step."""
    used = USED_CODES.setdefault(secret, set())
    while True:
        code = pyotp.TOTP(secret).now()
        if code not in used:
            used.add(code)
            return code
        time.sleep(1)


# ---------- mail ---------------------------------------------------------------------------------------------------
def mails():
    out = []
    for p in sorted(MAIL_DIR.glob("*.eml")):
        msg = email.message_from_bytes(p.read_bytes(), policy=email.policy.default)
        body = msg.get_body(("plain",))
        out.append({"path": p, "to": [a.addr_spec for a in msg["To"].addresses] if msg["To"] else [], "subject": str(msg["Subject"] or ""),
                    "body": body.get_content() if body else "", "headers": msg})
    return out


def wait_mail(to: str, before: int, timeout=25):
    t0 = time.time()
    while time.time() - t0 < timeout:
        new = [m for m in mails()[before:] if to in m["to"]]
        if new:
            return new[0]
        time.sleep(0.2)
    return None


def link_of(msg, kind):
    m = re.search(rf"{re.escape(BASE)}/{kind}/[A-Za-z0-9_\-]+", msg["body"])
    return m.group(0).replace(BASE, "") if m else None


def post_stepup(c: Admin, preview_path: str, data: dict, *, use_code: bool = True):
    """Preview request -> (preview response, confirm response or None). Types a fresh code only when asked and needed."""
    data = {**data, "csrf_token": c.csrf("/admin")}
    r = c.post(preview_path, data)
    if r.status_code != 200 or 'name="payload"' not in r.text:
        return r, None
    fields = {n: field(r.text, n) for n in ("csrf_token", "payload", "nonce")}
    if 'name="code"' in r.text and use_code:
        fields["code"] = fresh_code(c.secret)
    return r, c.post("/admin/stepup/confirm", fields)


def stepup_prompt(c: Admin, preview_path: str, data: dict):
    r = c.post(preview_path, {**data, "csrf_token": c.csrf("/admin")})
    return r, ('name="code"' in r.text), (field(r.text, "payload") if 'name="payload"' in r.text else None), \
        ({n: field(r.text, n) for n in ("csrf_token", "payload", "nonce")} if 'name="payload"' in r.text else None)


def counts():
    return {t: one(f"select count(*) from {t}") for t in ("consumption_events", "payment_events", "group_remittances", "users")}


# =================================================================================================================
def main() -> int:
    anon = Client("anon")
    check("start", "readiness is ok", anon.get("/readyz").json().get("status") == "ok")

    # ---- setup: head admin, TOTP enrolment, chairs ---------------------------------------------------------------
    head = Admin("head")
    r = head.login("head", "wrong password!")
    check("admin", "wrong admin password: 401, no session", r.status_code == 401, r.status_code)
    r = head.login("head", ARGS.head_password)
    check("admin", "head login redirects to /admin", r.status_code == 303 and r.headers["location"] == "/admin", r.status_code)
    r = head.get("/admin")
    check("admin", "un-enrolled head admin is forced to TOTP enrolment", r.status_code == 303 and "/admin/totp/setup" in r.headers["location"])
    secret, recovery = head.enrol()
    USED_CODES.setdefault(secret, set()).add(pyotp.TOTP(secret).now())
    check("admin", "enrolment (wrong-code protected) shows 8 recovery codes once", len(set(recovery)) == 8, len(recovery))
    check("admin", "enrolled head admin reaches /admin", head.get("/admin").status_code == 200)
    csrf = head.csrf("/admin/chairs")
    for full, short in (("Chair of Alpha", "ALPHA"), ("Chair of Beta", "BETA")):
        head.post("/admin/chairs", {"csrf_token": csrf, "full_name": full, "short_name": short})
    chairs = {short: cid for cid, short in re.findall(r'<option value="([0-9a-f\-]{36})"[^>]*>(ALPHA|BETA) – ', anon.get("/register").text)}
    check("admin", "two chairs created and offered on /register", set(chairs) == {"ALPHA", "BETA"}, chairs)
    price = one("select price_per_shot_cents from prices order by effective_from desc limit 1")
    info("setup", "price per shot in effect (cents)", str(price))

    def register_member(username, display, chair, address, *, expect_mail=True):
        c = Client(username)
        before = len(mails())
        tok = c.csrf("/register")
        r = c.post("/register", {"csrf_token": tok, "username": username, "display_name": display, "chair_id": chairs[chair],
                                 "email": address, "password": USER_PW, "password2": USER_PW, "privacy_ack": "1"})
        msg = wait_mail(address, before, timeout=25 if expect_mail else 4)
        return c, r, msg

    # ===== DoD 1: members ================================================================================================
    n_users0 = one("select count(*) from users")
    alice, r, msg = register_member("alice", "Alice Alpha", "ALPHA", "alice@tum.de")
    check("dod1", "member registration answers 200/303 and mails the verification link to the TUM address",
          msg is not None and link_of(msg, "verify") is not None, (r.status_code, msg and msg["body"][:200]))
    check("dod1", "no user exists before the link is confirmed", one("select count(*) from users") == n_users0)
    vlink = link_of(msg, "verify")
    page = alice.get(vlink)
    check("dod1", "GET of the verification link shows a confirm form and writes nothing",
          page.status_code == 200 and one("select count(*) from users") == n_users0 and not alice.s.cookies.get("coffee_session"))
    r = alice.post(vlink, {"csrf_token": field(page.text, "csrf_token")})
    check("dod1", "POST creates the member, signs the browser in", r.status_code == 303 and bool(alice.s.cookies.get("coffee_session")), r.status_code)
    row = sql("select account_kind, email, verified_at is not null, chair_id from users where username='alice'")
    check("dod1", "stored as a verified member with the email and chair chosen", bool(row) and row[0][0] == "member" and row[0][1] == "alice@tum.de" and row[0][2] == 1
          and row[0][3] == hexid(chairs["ALPHA"]), row)
    r = Client("replay").post(vlink, {"csrf_token": field(page.text, "csrf_token")})
    check("dod1", "verification link is single-use", r.status_code >= 400, r.status_code)
    c_bad, r, msg = register_member("mallory", "Non Tum", "ALPHA", "someone@gmail.com", expect_mail=False)
    check("dod1", "a non-TUM address is refused: no mail, no pending row, no user", msg is None and one("select count(*) from users where username='mallory'") == 0
          and one("select count(*) from pending_registrations where username_normalized='mallory'") == 0, (r.status_code, text_of(r.text)[:160]))
    c_bad, r, msg = register_member("mallory2", "Sub Domain", "ALPHA", "x@evil-tum.de", expect_mail=False)
    check("dod1", "look-alike domain evil-tum.de is refused", msg is None and one("select count(*) from pending_registrations where username_normalized='mallory2'") == 0)
    c_ok, r, msg = register_member("sub", "Sub Domain Ok", "BETA", "sub@cs.tum.de")
    check("dod1", "a subdomain of tum.de (*.tum.de) is accepted", msg is not None, r.status_code)
    c_ok2, r, msg2 = register_member("student", "Student Mytum", "BETA", "student@mytum.de")
    check("dod1", "mytum.de is accepted", msg2 is not None, r.status_code)
    # same address twice: page identical, mail says "you already have an account"
    _, rd, mdup = register_member("alice2", "Alice Two", "ALPHA", "alice@tum.de")
    check("dod1", "an already-registered address gets a mail pointing to sign in / forgot password and no second account",
          mdup is not None and one("select count(*) from users where email='alice@tum.de'") == 1 and "alice2" not in (one("select group_concat(username) from users") or ""),
          mdup and mdup["body"][:200])
    bob_c, _, bmsg = register_member("bob", "Bob Beta", "BETA", "bob@tum.de")
    carol_c, _, cmsg = register_member("carol", "Carol Alpha", "ALPHA", "carol@tum.de")
    for c, m in ((bob_c, bmsg), (carol_c, cmsg), (c_ok, msg), (c_ok2, msg2)):
        lk = link_of(m, "verify")
        pg = c.get(lk)
        c.post(lk, {"csrf_token": field(pg.text, "csrf_token")})
    check("dod1", "members bob, carol, sub, student verified", one("select count(*) from users where account_kind='member'") == 5)

    # guests -------------------------------------------------------------------------------------------------------
    def guest_request(username, sponsor_email):
        c = Client(username)
        before = len(mails())
        tok = field(c.get("/register?kind=guest").text, "csrf_token")
        r = c.post("/register/guest", {"csrf_token": tok, "username": username, "display_name": GUEST_NAMES.get(username, "Gast Anonym"), "sponsor_email": sponsor_email,
                                       "password": USER_PW, "password2": USER_PW, "privacy_ack": "1"})
        return c, r, before

    g1, r1, b1 = guest_request("guest1", "alice@tum.de")
    m1 = wait_mail("alice@tum.de", b1)
    g2, r2, b2 = guest_request("guest2", "alice@tum.de")
    m2 = wait_mail("alice@tum.de", b2 + 0)
    gx, rx, bx = guest_request("guestx", "nobody-here@tum.de")
    time.sleep(2)
    check("dod1", "guest request: the sponsor's inbox gets a mail naming the guest; an unknown sponsor address gets none",
          m1 is not None and "guest1" in m1["body"] and not [m for m in mails()[bx:] if "nobody-here@tum.de" in m["to"]], m1 and m1["body"][:300])
    norm = lambda t: re.sub(r"guest\w+", "G", text_of(t))
    check("dod1", "guest request page is identical for a member sponsor and an unknown address (no member enumeration)",
          r1.status_code == rx.status_code and norm(r1.text) == norm(rx.text), (r1.status_code, rx.status_code))
    r = Client("g1login").login("guest1", USER_PW)
    check("dod1", "a guest cannot sign in before the sponsor approves", r.status_code == 401, r.status_code)
    sponsor_view = Client("sponsor")
    vg = link_of(m1, "verify")
    pg = sponsor_view.get(vg)
    check("dod1", "sponsor link (no sign-in needed): GET shows the guest's details with Approve and Reject and writes nothing",
          pg.status_code == 200 and 'value="approve"' in pg.text and 'value="reject"' in pg.text and one("select count(*) from users where username='guest1'") == 0)
    r = sponsor_view.post(vg, {"csrf_token": field(pg.text, "csrf_token"), "action": "approve"})
    check("dod1", "POST approve creates the guest with the sponsor recorded and the sponsor's chair",
          one("select account_kind from users where username='guest1'") == "guest"
          and one("select sponsor_id from users where username='guest1'") == one("select id from users where username='alice'")
          and one("select chair_id from users where username='guest1'") == hexid(chairs["ALPHA"]), r.status_code)
    r = g1.login("guest1", USER_PW)
    check("dod1", "the approved guest signs in", r.status_code == 303, r.status_code)
    vg2 = link_of(m2, "verify")
    pg2 = sponsor_view.get(vg2)
    sponsor_view.post(vg2, {"csrf_token": field(pg2.text, "csrf_token"), "action": "approve"})
    check("dod1", "second guest approved", one("select count(*) from users where account_kind='guest'") == 2)
    # reject path
    g3, r3, b3 = guest_request("guest3", "bob@tum.de")
    m3 = wait_mail("bob@tum.de", b3)
    pg3 = sponsor_view.get(link_of(m3, "verify"))
    sponsor_view.post(link_of(m3, "verify"), {"csrf_token": field(pg3.text, "csrf_token"), "action": "reject"})
    check("dod1", "reject deletes the request and creates no account", one("select count(*) from users where username='guest3'") == 0
          and one("select count(*) from pending_registrations where username_normalized='guest3' and consumed_at is null") == 0)
    # username rules
    cc, r, mcase = register_member("ALICE", "Case Clash", "ALPHA", "other@tum.de", expect_mail=True)
    if mcase:
        lk = link_of(mcase, "verify")
        pg = cc.get(lk)
        cc.post(lk, {"csrf_token": field(pg.text, "csrf_token")})
    check("dod1", "usernames are unique case-insensitively: ALICE cannot become a second account next to alice",
          one("select count(*) from users where username_normalized='alice'") == 1, (r.status_code, mcase is not None))
    r = subprocess.run([ARGS.py, "-m", "app.cli", "create-admin", "--username", "alice", "--role", "global", "--password-stdin"], input="Another-Long-Password-1\n",
                       text=True, capture_output=True, cwd=ARGS.repo, env=cli_env())
    check("dod1", "create-admin refuses a username that a user holds", r.returncode != 0, (r.stderr or r.stdout)[:120])

    # ===== DoD 2: recovery ==================================================================================================
    def forgot(username):
        c = Client("forgot-" + username)
        before = len(mails())
        r = c.post("/forgot", {"csrf_token": c.csrf("/forgot"), "username": username})
        return c, r, before

    cf, rf, bf = forgot("alice")
    mf = wait_mail("alice@tum.de", bf)
    check("dod2", "member: the reset mail reaches the member's own address with a /reset link", mf is not None and link_of(mf, "reset") is not None, mf and mf["body"][:120])
    cg, rg, bg = forgot("guest1")
    mg = wait_mail("alice@tum.de", bg)
    check("dod2", "guest: the reset mail goes to the SPONSOR's address and names the guest account", mg is not None and "guest1" in mg["body"] and link_of(mg, "reset") is not None,
          mg and mg["body"][:300])
    cu, ru, bu = forgot("no-such-user")
    time.sleep(1.5)
    check("dod2", "forgot-password answers identically for known and unknown usernames; unknown gets no mail",
          text_of(rg.text) == text_of(ru.text) and rg.status_code == ru.status_code, (rg.status_code, ru.status_code))
    check("dod2", "unknown username: no mail sent", not [m for m in mails()[bu:] if "no-such-user" in m["body"]])
    rl = link_of(mg, "reset")
    pg = cg.get(rl)
    check("dod2", "GET of the reset link only shows the form", pg.status_code == 200 and 'name="password"' in pg.text and
          g1.login("guest1", USER_PW).status_code == 303)
    r = cg.post(rl, {"csrf_token": field(pg.text, "csrf_token"), "password": USER_PW + "-new", "password2": USER_PW + "-new"})
    c_a, c_b, c_c = Client("a"), Client("b"), Client("c")
    check("dod2", "guest1 has the new password; the old one is refused", c_a.login("guest1", USER_PW + "-new").status_code == 303 and c_b.login("guest1", USER_PW).status_code == 401, r.status_code)
    check("dod2", "guest2 (same sponsor) keeps its own password: only the requested account was reset",
          c_c.login("guest2", USER_PW).status_code == 303 and Client("d").login("guest2", USER_PW + "-new").status_code == 401)
    r = cg.post(rl, {"csrf_token": field(pg.text, "csrf_token"), "password": "Second-Use-Password-5", "password2": "Second-Use-Password-5"})
    check("dod2", "the reset link is single-use", r.status_code >= 400 and Client("e").login("guest1", "Second-Use-Password-5").status_code == 401, r.status_code)
    check("dod2", "reset revoked the guest's earlier sessions", g1.get("/account").status_code == 303)
    # member reset
    rl_m = link_of(mf, "reset")
    pg = cf.get(rl_m)
    cf.post(rl_m, {"csrf_token": field(pg.text, "csrf_token"), "password": USER_PW + "-m", "password2": USER_PW + "-m"})
    check("dod2", "member reset works", Client("f").login("alice", USER_PW + "-m").status_code == 303)
    alice = Client("alice-in")
    alice.login("alice", USER_PW + "-m")
    ALICE_PW = USER_PW + "-m"
    guest1 = Client("guest1-in")
    guest1.login("guest1", USER_PW + "-new")
    guest2 = Client("guest2-in")
    guest2.login("guest2", USER_PW)
    bob = Client("bob-in")
    bob.login("bob", USER_PW)
    carol = Client("carol-in")
    carol.login("carol", USER_PW)

    # ===== DoD 3: one chair per person; group admin acts only in own chair ====================================================
    cols = [r[1] for r in sql("pragma table_info(users)")]
    tables = [r[0] for r in sql("select name from sqlite_master where type='table'")]
    check("dod3", "schema: exactly one chair_id column on users, no admin_chairs assignment table", cols.count("chair_id") == 1 and "admin_chairs" not in tables, tables)
    alice_uid = dashed(one("select id from users where username='alice'"))
    bob_uid = dashed(one("select id from users where username='bob'"))
    carol_uid = dashed(one("select id from users where username='carol'"))
    g1_uid = dashed(one("select id from users where username='guest1'"))
    r = head.post(f"/admin/users/{alice_uid}/group-admin/promote", {"csrf_token": head.csrf("/admin/users")})
    check("dod3", "head promotes alice to group admin (member only, no chair picker: scope = own chair)", r.status_code == 303 and one("select count(*) from admin_users where user_id=? and role='chair' and active=1", hexid(alice_uid)) == 1, r.status_code)
    pdet = head.get(f"/admin/users/{alice_uid}").text
    check("dod3", "the promote form has no chair field", 'action="/admin/users/%s/group-admin/demote"' % alice_uid in pdet or "demote" in pdet)
    ga = Admin("ga")
    r = ga.login("alice", ALICE_PW)
    check("dod3", "group admin signs in at /admin/login with the member's username and password", r.status_code == 303, r.status_code)
    r = ga.get("/admin")
    check("dod3", "group admin is forced to enrol TOTP first", r.status_code == 303 and "/admin/totp/setup" in r.headers.get("location", ""))
    ga_secret, _ = ga.enrol()
    USED_CODES.setdefault(ga_secret, set()).add(pyotp.TOTP(ga_secret).now())
    check("dod3", "group admin reaches /admin after enrolment", ga.get("/admin").status_code == 200)
    ulist = ga.get("/admin/users?q=").text
    check("dod3", "group admin's user list: own chair only (carol yes, bob (BETA) no)", carol_uid in ulist and bob_uid not in ulist)
    check("dod3", "group admin: own-chair person page 200, other chair 403",
          ga.get(f"/admin/users/{carol_uid}").status_code == 200 and ga.get(f"/admin/users/{bob_uid}").status_code == 403)
    n0 = counts()
    csrf = ga.csrf("/admin/users")
    forbidden = [(f"/admin/users/{bob_uid}/payment", {"amount": "1"}), (f"/admin/users/{bob_uid}/chair", {"chair_id": chairs["ALPHA"]}),
                 (f"/admin/users/{bob_uid}/status", {"active": "0"}), (f"/admin/users/{bob_uid}/rename", {"display_name": "Hacked"}),
                 (f"/admin/users/{carol_uid}/chair", {"chair_id": chairs["BETA"]}), (f"/admin/users/{alice_uid}/chair", {"chair_id": chairs["BETA"]}),
                 (f"/admin/users/{alice_uid}/balance", {"amount": "5", "direction": "credit"}), (f"/admin/users/{alice_uid}/payment", {"amount": "5"}),
                 ("/admin/prices", {"price": "0.01"}), ("/admin/chairs", {"full_name": "X", "short_name": "X"}),
                 ("/admin/groups/remittances", {"group_admin_id": "x", "amount": "1"})]
    codes = [ga.post(p, {"csrf_token": csrf, **d}).status_code for p, d in forbidden]
    check("dod3", "group admin: foreign chair, own chair change, own balance, prices, chairs, remittances all 403 and nothing written",
          all(c == 403 for c in codes) and counts() == n0 and one("select display_name from users where username='bob'") == "Bob Beta", codes)
    for path in ("/admin/groups", "/admin/audit", "/admin/admins", "/admin/prices", "/admin/chairs", "/admin/exports/group-balances.csv"):
        check("dod3", f"group admin GET {path} is 403 (head only)", ga.get(path).status_code == 403)
    pg = alice.get("/account/edit")
    check("dod3", "group admin's own profile form fixes the chair (no chair picker)", 'name="chair_id"' not in pg.text)
    r = alice.post("/account/edit", {"csrf_token": field(pg.text, "csrf_token"), "display_name": "Alice Alpha", "chair_id": chairs["BETA"]})
    check("dod3", "a submitted different chair is refused for a group admin (403)", r.status_code == 403 and one("select chair_id from users where username='alice'") == hexid(chairs["ALPHA"]), r.status_code)
    gpage = text_of(head.get(f"/admin/users/{g1_uid}").text)
    check("dod3", "a guest inherits the sponsor's chair (ALPHA) and the head admin's page names the sponsor", "ALPHA" in gpage and "Alice Alpha" in gpage)
    # members pick their own chair; a non-admin member may change it themselves
    pg = bob.get("/account/edit")
    check("dod3", "an ordinary member's profile form offers the chair (the person picks it, exactly one chair)", 'name="chair_id"' in pg.text)

    # ===== DoD 4: QR codes ==================================================================================================
    qr = head.get("/admin/qr")
    qtext = text_of(qr.text)
    urls = sorted(set(re.findall(re.escape(BASE) + r"/[a-z/]*[a-z]", qtext)))
    info("dod4", "targets printed on /admin/qr", " ".join(urls))
    want = {BASE + "/register", BASE + "/coffee/single", BASE + "/coffee/double", BASE + "/overview"}
    check("dod4", "the QR page lists the four targets: register, single, double, website", want <= set(urls), urls)
    kinds = re.findall(r"/admin/qr/([a-z]+)\.svg", qr.text)
    info("dod4", "SVG downloads linked", " ".join(sorted(set(kinds))))
    svgs = {}
    for k in sorted(set(kinds)):
        rr = head.get(f"/admin/qr/{k}.svg")
        svgs[k] = rr.text
        check("dod4", f"/admin/qr/{k}.svg is an SVG attachment", rr.status_code == 200 and "image/svg+xml" in rr.headers.get("content-type", "") and "<svg" in rr.text, rr.status_code)
    check("dod4", "four distinct SVG codes", len(svgs) == 4 and len(set(svgs.values())) == 4, list(svgs))
    Path(ARGS.out).with_suffix(".qr.json").write_text(json.dumps({"base": BASE, "svgs": svgs}))
    ev0 = counts()
    visitor = Client("visitor")
    visitor.login("bob", USER_PW)
    for who in (anon, visitor, alice):
        for u in want:
            who.get(u.replace(BASE, ""))
    check("dod4", "visiting every QR target (anonymous and signed in, incl. the registration QR) writes no coffee or payment", counts()["consumption_events"] == ev0["consumption_events"]
          and counts()["payment_events"] == ev0["payment_events"], (ev0, counts()))
    # ===== scan flow and ledger basics (single, double, idempotency, undo, price) ===========================================
    scan = Client("scanner")
    pg = scan.get("/coffee/single")
    ev_before = one("select count(*) from consumption_events")
    check("scan", "GET /coffee/single writes nothing and shows the confirm button", pg.status_code == 200 and 'name="token"' in pg.text and one("select count(*) from consumption_events") == ev_before)
    r = scan.post("/coffee/single", {"token": field(pg.text, "token")})
    check("scan", "an anonymous scan is parked: 303 to /login, no coffee", r.status_code == 303 and r.headers["location"] == "/login" and one("select count(*) from consumption_events") == ev_before, r.headers.get("location"))
    r = scan.login("bob", USER_PW)
    last = sql("select quantity, unit_price_cents, amount_cents, type from consumption_events order by created_at desc limit 1")[0]
    check("scan", "signing in records the parked single exactly once at the current price", one("select count(*) from consumption_events") == ev_before + 1 and last[0] == 1 and last[1] == price and last[2] == price, (r.status_code, last))
    # double + idempotency
    pg = bob.get("/coffee/double")
    tok = field(pg.text, "token")
    n1 = one("select count(*) from consumption_events")
    with concurrent.futures.ThreadPoolExecutor(8) as ex:
        rs = list(ex.map(lambda _: bob.post("/coffee/double", {"token": tok}), range(8)))
    locs = {x.headers.get("location") for x in rs}
    last = sql("select quantity, unit_price_cents, amount_cents from consumption_events where user_id=? order by created_at desc limit 1", hexid(bob_uid))[0]
    check("scan", "8 concurrent POSTs of one scan token: one coffee, one location", one("select count(*) from consumption_events") == n1 + 1 and len(locs) == 1 and all(x.status_code == 303 for x in rs), (locs, [x.status_code for x in rs]))
    check("scan", "double = 2 shots at 2 x price", last == (2, price, 2 * price), last)
    done = bob.get(rs[0].headers["location"])
    n2 = one("select count(*) from consumption_events")
    bob.get(rs[0].headers["location"])
    check("scan", "refreshing the success page records nothing", one("select count(*) from consumption_events") == n2)
    eid = rs[0].headers["location"].rsplit("/", 1)[1]
    tokc = field(done.text, "csrf_token")
    with concurrent.futures.ThreadPoolExecutor(8) as ex:
        us = list(ex.map(lambda _: bob.post(f"/coffee/undo/{eid}", {"csrf_token": tokc}), range(8)))
    rev = sql("select quantity, amount_cents, reversal_of_id from consumption_events where reversal_of_id=?", hexid(eid))
    check("scan", "8 concurrent undos: exactly one reversal row with the negated quantity and amount, the original untouched",
          len(rev) == 1 and rev[0][0] == -2 and rev[0][1] == -2 * price and one("select quantity from consumption_events where id=?", hexid(eid)) == 2, rev)
    # price change
    n_pr = one("select count(*) from prices")
    csrf = head.csrf("/admin/prices")
    r = head.post("/admin/prices", {"csrf_token": csrf, "price": "0.60"})
    new_price = 60
    check("price", "head adds price 0.60 (no TOTP asked)", r.status_code == 303 and one("select count(*) from prices") == n_pr + 1, r.status_code)
    r = head.post("/admin/prices", {"csrf_token": csrf, "price": "0.605"})
    check("price", "a price with 3 decimals is refused", one("select count(*) from prices") == n_pr + 1)
    pg = carol.get("/coffee/double")
    r = carol.post("/coffee/double", {"token": field(pg.text, "token")})
    last = sql("select quantity, unit_price_cents, amount_cents from consumption_events where user_id=? order by created_at desc limit 1", hexid(carol_uid))[0]
    check("price", "after the change a new double costs 2 x 60; earlier rows keep the old snapshot", last == (2, new_price, 120)
          and one("select count(*) from consumption_events where unit_price_cents=?", price) >= 2, last)
    pg = carol.get("/coffee/single")
    carol.post("/coffee/single", {"token": field(pg.text, "token")})
    # single by alice, group admin; alice also gets a coffee in order to get a balance
    for who in (alice, guest1, guest2):
        pg = who.get("/coffee/single")
        who.post("/coffee/single", {"token": field(pg.text, "token")})

    # ===== DoD 8: receipt =====================================================================================================
    pg = alice.get("/coffee/double")
    r = alice.post("/coffee/double", {"token": field(pg.text, "token")})
    receipt = text_of(alice.get(r.headers["location"]).text)
    info("dod8", "receipt text", receipt[:300])
    bal = one("select coalesce((select sum(amount_cents) from consumption_events where user_id=?),0) - coalesce((select sum(amount_cents) from payment_events where user_id=?),0)", hexid(alice_uid), hexid(alice_uid))
    month_shots = one("select coalesce(sum(quantity),0) from consumption_events where user_id=? and created_at >= ?", hexid(alice_uid), datetime.now(timezone.utc).strftime("%Y-%m-01"))
    check("dod8", "the receipt states the amount owed in words (Outstanding) and the shots this month", ("Outstanding:" in receipt) and "Shots this month" in receipt, receipt[:200])
    m = re.search(r"Outstanding: [^0-9]*([0-9]+[.,][0-9]{2})", receipt)
    check("dod8", "the amount on the receipt equals the SQL balance (consumed - paid)", bool(m) and int(m.group(1).replace(",", "").replace(".", "")) == bal, (m and m.group(1), bal))
    ms = re.search(r"Shots this month\D*(\d+)", receipt)
    check("dod8", "shots this month on the receipt equals the SQL sum for the month (UTC month, same here)", bool(ms) and int(ms.group(1)) == month_shots, (ms and ms.group(1), month_shots))

    # ===== DoD 6 + 7: money, step-up ==========================================================================================
    ga_id = dashed(one("select id from admin_users where user_id=? and role='chair'", hexid(alice_uid)))
    head_admin_id = dashed(one("select id from admin_users where username='head'"))
    # fresh head session: no window
    fresh = Admin("fresh")
    fresh.login("head", ARGS.head_password)
    fresh.secret = secret
    # (a) every balance-changing action asks for a code on a closed window and writes nothing without it
    carol_pay = (f"/admin/users/{carol_uid}/payment", {"amount": "2.00", "note": "n-pay"})
    # group admin cash for carol (ALPHA): window of ga is open from the enrolment, first book via ga
    # --- prepare targets: a payment made by head first to create something to correct/reverse
    ev_carol = one("select id from consumption_events where user_id=? and reversal_of_id is null order by created_at limit 1", hexid(carol_uid))
    actions = {
        "payment": (f"/admin/users/{carol_uid}/payment", {"amount": "2.00", "note": "n-pay"}),
        "adjustment": (f"/admin/users/{carol_uid}/adjustment", {"quantity": "1", "amount": "0.60", "note": "n-adj"}),
        "reversal": (f"/admin/users/{carol_uid}/events/{dashed(ev_carol)}/reverse", {"note": "n-rev"}),
        "set balance": (f"/admin/users/{bob_uid}/balance", {"amount": "3.00", "direction": "owes", "note": "n-bal"}),
        "remittance": ("/admin/groups/remittances", {"group_admin_id": ga_id, "amount": "1.00", "note": "n-rem"}),
        "merge": (f"/admin/users/{dashed(one('select id from users where username=?', 'student'))}/merge", {"target_id": dashed(one("select id from users where username='sub'"))}),
    }
    snapshot = counts()
    for name, (path, data) in actions.items():
        r, prompt, payload, _ = stepup_prompt(fresh, path, data)
        check("dod7", f"{name}: first request on a closed window shows the confirm page with a code field and books nothing",
              r.status_code == 200 and prompt and counts() == snapshot, (r.status_code, prompt))
    sess = one("select id from admin_sessions order by created_at desc limit 1")
    check("dod7", "fresh session has no open window (stepup_until NULL)", one("select stepup_until from admin_sessions where admin_id=(select id from admin_users where username='head') order by created_at desc limit 1") is None)
    # no code / wrong code / replay / tampering / foreign session
    r, prompt, payload, f = stepup_prompt(fresh, *actions["payment"])
    r1 = fresh.post("/admin/stepup/confirm", f)
    check("dod7", "confirm without a code writes nothing", counts() == snapshot, r1.status_code)
    r2 = fresh.post("/admin/stepup/confirm", {**f, "code": "000000"})
    check("dod7", "confirm with a wrong code writes nothing", counts() == snapshot, r2.status_code)
    r3 = fresh.post("/admin/stepup/confirm", {**f, "payload": f["payload"][:-4] + ("AAAA" if not f["payload"].endswith("AAAA") else "BBBB"), "code": fresh_code(secret)})
    check("dod7", "a tampered payload writes nothing (even with a valid code)", counts() == snapshot, r3.status_code)
    other = Admin("other")
    other.login("head", ARGS.head_password)
    r4 = other.post("/admin/stepup/confirm", {**f, "csrf_token": other.csrf("/admin"), "code": fresh_code(secret)})
    check("dod7", "a payload prepared by one session cannot be executed by another", counts() == snapshot, r4.status_code)
    # the correct code books, opens the window for this session only
    r5 = fresh.post("/admin/stepup/confirm", {**f, "code": fresh_code(secret)})
    pay_row = sql("select kind, amount_cents, collector_admin_id, admin_id from payment_events where note='n-pay'")
    check("dod7", "the correct code books the payment (kind cash, 2.00, collector = the head admin)", len(pay_row) == 1 and pay_row[0][:2] == ("cash", 200), (r5.status_code, pay_row))
    su = sql("select stepup_until, created_at from admin_sessions where admin_id=(select id from admin_users where username='head') order by last_seen_at desc")
    r6 = fresh.post("/admin/stepup/confirm", f)
    check("dod7", "the same nonce cannot book twice (replay)", one("select count(*) from payment_events where note='n-pay'") == 1, r6.status_code)
    # window length
    until = one("select stepup_until from admin_sessions where id=(select id from admin_sessions where stepup_until is not null order by stepup_until desc limit 1)")
    delta = (datetime.fromisoformat(until).replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).total_seconds()
    check("dod7", "the unlock window is fixed at about 300 s", 200 < delta <= 300, delta)
    # inside the window: no code needed for the other balance actions, each books exactly once
    for name in ("adjustment", "reversal", "set balance", "remittance"):
        path, data = actions[name]
        before = counts()
        r, prompt, payload, ff = stepup_prompt(fresh, path, data)
        check("dod7", f"{name}: inside the open window the confirm page has no code field", r.status_code == 200 and not prompt, r.status_code)
        rr = fresh.post("/admin/stepup/confirm", ff)
        after = counts()
        wrote = {k: after[k] - before[k] for k in after}
        info("dod7", f"{name}: rows written", json.dumps(wrote))
    check("dod7", "adjustment booked (1 shot at 0.60)", sql("select quantity, amount_cents, type from consumption_events where note='n-adj'") == [(1, 60, "adjustment")], sql("select quantity, amount_cents, type from consumption_events where note='n-adj'"))
    rev_row = sql("select quantity, amount_cents from consumption_events where reversal_of_id=? and note='n-rev'", ev_carol)
    orig = sql("select quantity, amount_cents from consumption_events where id=?", ev_carol)[0]
    check("dod7", "reversal booked as a negated copy of the original (original untouched)", rev_row == [(-orig[0], -orig[1])], (rev_row, orig))
    # set balance: bob balance = 3.00 owed after the change
    bob_bal = one("select coalesce((select sum(amount_cents) from consumption_events where user_id=?),0) - coalesce((select sum(amount_cents) from payment_events where user_id=?),0)", hexid(bob_uid), hexid(bob_uid))
    kind_bk = sql("select kind, amount_cents from payment_events where note='n-bal'")
    check("dod7", "set balance booked a bookkeeping entry and the balance equals the target (3.00 owed)", bob_bal == 300 and kind_bk and kind_bk[0][0] == "bookkeeping", (bob_bal, kind_bk))
    check("dod7", "remittance of 1.00 from the group admin recorded", one("select amount_cents from group_remittances where note='n-rem'") == 100)
    # merge, remittance correction (inside the open window)
    path, data = actions["merge"]
    before = counts()
    r, prompt, payload, ff = stepup_prompt(fresh, path, data)
    check("dod7", "merge: inside the window no code is asked", r.status_code == 200 and not prompt, r.status_code)
    fresh.post("/admin/stepup/confirm", ff)
    merged = one("select merged_into_id from users where username='student'")
    check("dod7", "merge booked: the source account points to the target, no ledger row moved or edited", merged == one("select id from users where username='sub'"), merged)
    rem_id = dashed(one("select id from group_remittances where note='n-rem'"))
    r, prompt, payload, ff = stepup_prompt(fresh, f"/admin/groups/remittances/{rem_id}/correct", {"corrected_to": "0.50", "note": "n-remc"})
    check("dod7", "remittance correction goes through the confirm page too", r.status_code == 200 and 'name="payload"' in r.text, r.status_code)
    fresh.post("/admin/stepup/confirm", ff)
    check("dod7", "remittance correction recorded as a correcting row (append-only; the original stays)", one("select count(*) from group_remittances where correction_of_id is not null") == 1 and one("select count(*) from group_remittances") == 2)
    # (b) the window expires: test-only shortcut, stepup_until is set into the past in the database
    con = sqlite3.connect(DB)
    con.execute("update admin_sessions set stepup_until=? where stepup_until is not null and admin_id=(select id from admin_users where username='head')", ((datetime.now(timezone.utc) - timedelta(seconds=5)).strftime("%Y-%m-%d %H:%M:%S.%f"),))
    con.commit()
    con.close()
    r, prompt, payload, ff = stepup_prompt(fresh, *actions["payment"])
    check("dod7", "after the window expires (stepup_until moved into the past, test-only shortcut) a code is asked again", prompt)
    # (c) concurrency: the same confirm 8 times books once
    n_pay = one("select count(*) from payment_events")
    ff2 = {**ff, "code": fresh_code(secret)}
    with concurrent.futures.ThreadPoolExecutor(8) as ex:
        list(ex.map(lambda _: fresh.post("/admin/stepup/confirm", ff2), range(8)))
    check("dod7", "8 concurrent confirms of one payload book exactly one payment", one("select count(*) from payment_events") == n_pay + 1)
    # (d) nothing else asks for a code: on a brand-new session everything non-balance works
    nb = Admin("nobal")
    nb.login("head", ARGS.head_password)
    csrf = nb.csrf("/admin/users")
    ok = []
    pages = ["/admin", "/admin/users", "/admin/groups", "/admin/chairs", "/admin/prices", "/admin/audit", "/admin/admins", "/admin/qr", "/admin/exports", "/admin/account",
             f"/admin/users/{carol_uid}", f"/admin/users/{carol_uid}/merge?q=bob", f"/admin/users/{g1_uid}/sponsor?q=carol"]
    bad = [(p, nb.get(p).status_code) for p in pages if nb.get(p).status_code != 200]
    check("dod7", "all admin pages open without a code on a fresh session", not bad, bad)
    for p in ("/admin/users/export.csv", "/admin/exports/ledger.csv", "/admin/exports/group-balances.csv"):
        ok.append(nb.get(p).status_code)
    check("dod7", "all three CSV exports download without a code", ok == [200, 200, 200], ok)
    p0 = counts()
    steps = []
    n_prices = one("select count(*) from prices")
    steps.append(("price change", nb.post("/admin/prices", {"csrf_token": csrf, "price": "0.55"}).status_code == 303 and one("select count(*) from prices") == n_prices + 1))
    steps.append(("rename", nb.post(f"/admin/users/{carol_uid}/rename", {"csrf_token": csrf, "display_name": "Carol Renamed"}).status_code == 303 and one("select display_name from users where username='carol'") == "Carol Renamed"))
    steps.append(("deactivate", nb.post(f"/admin/users/{carol_uid}/status", {"csrf_token": csrf, "active": "0"}).status_code == 303 and one("select status from users where username='carol'") != "active"))
    steps.append(("reactivate", nb.post(f"/admin/users/{carol_uid}/status", {"csrf_token": csrf, "active": "1"}).status_code == 303 and one("select status from users where username='carol'") == "active"))
    steps.append(("chair change", nb.post(f"/admin/users/{bob_uid}/chair", {"csrf_token": csrf, "chair_id": chairs["ALPHA"]}).status_code == 303 and one("select chair_id from users where username='bob'") == hexid(chairs["ALPHA"])))
    nb.post(f"/admin/users/{bob_uid}/chair", {"csrf_token": csrf, "chair_id": chairs["BETA"]})
    steps.append(("chair rename", nb.post(f"/admin/chairs/{chairs['BETA']}/rename", {"csrf_token": csrf, "full_name": "Chair of Beta", "short_name": "BETA"}).status_code == 303))
    steps.append(("session revoke", nb.post(f"/admin/users/{carol_uid}/sessions/revoke", {"csrf_token": csrf}).status_code == 303))
    steps.append(("sponsor reassign", nb.post(f"/admin/users/{g1_uid}/sponsor", {"csrf_token": csrf, "sponsor_id": carol_uid}).status_code == 303 and one("select sponsor_id from users where username='guest1'") == hexid(carol_uid)))
    nb.post(f"/admin/users/{g1_uid}/sponsor", {"csrf_token": csrf, "sponsor_id": alice_uid})
    steps.append(("promote", nb.post(f"/admin/users/{carol_uid}/group-admin/promote", {"csrf_token": csrf}).status_code == 303 and one("select count(*) from admin_users where user_id=? and role='chair' and active=1", hexid(carol_uid)) == 1))
    steps.append(("demote", nb.post(f"/admin/users/{carol_uid}/group-admin/demote", {"csrf_token": csrf}).status_code == 303 and one("select count(*) from admin_users where user_id=? and role='chair' and active=1", hexid(carol_uid)) == 0))
    for name, ok_ in steps:
        check("dod7", f"{name}: works on a fresh session without any TOTP prompt", ok_)
    check("dod7", "none of those wrote a payment, remittance or consumption row", {k: counts()[k] for k in ("consumption_events", "payment_events", "group_remittances")} ==
          {k: p0[k] for k in ("consumption_events", "payment_events", "group_remittances")})

    # ===== DoD 6: group money ================================================================================================
    # group admin books cash for a person of its own chair (ga's enrolment window is open, same session)
    carol_before = one("select count(*) from payment_events")
    r, c2 = post_stepup(ga, f"/admin/users/{carol_uid}/payment", {"amount": "12.00", "note": "ga-cash-1"})
    row = sql("select kind, amount_cents, collector_admin_id from payment_events where note='ga-cash-1'")
    check("dod6", "group admin books 12.00 cash for a person in the own chair (step-up window from enrolment)", c2 is not None and row and row[0][0] == "cash" and row[0][1] == 1200 and row[0][2] == hexid(ga_id), (r.status_code, row))
    # a second cash payment so that collected > the remittance; plus a head cash payment (not group money)
    post_stepup(ga, f"/admin/users/{carol_uid}/payment", {"amount": "3.00", "note": "ga-cash-2"})
    post_stepup(fresh, f"/admin/users/{carol_uid}/payment", {"amount": "4.00", "note": "head-cash"})  # head collected, not a group admin
    # remittance by head (1.00 -> corrected to 0.50 earlier, now add 5.00)
    r, c3 = post_stepup(fresh, "/admin/groups/remittances", {"group_admin_id": ga_id, "amount": "5.00", "note": "n-rem2"})
    collected = one("select coalesce(sum(amount_cents),0) from payment_events where collector_admin_id=? and kind='cash'", hexid(ga_id))
    remitted = one("select coalesce(sum(case when correction_of_id is null then amount_cents else 0 end),0) from group_remittances where group_admin_id=?", hexid(ga_id))
    corr = sql("select r.amount_cents, r.correction_of_id from group_remittances r where r.group_admin_id=? and r.correction_of_id is not null", hexid(ga_id))
    info("dod6", "SQL basis", f"collected={collected} remittance rows={sql('select amount_cents, correction_of_id from group_remittances order by created_at')}")
    adm = text_of(head.get("/admin/groups").text)
    site = text_of(alice.get("/overview/chairs").text)
    info("dod6", "admin groups page", adm[:700])
    info("dod6", "site chairs page", site[:700])
    # derive expected from SQL: handed over = sum of remittance rows treating a correction row as the new value
    rows = sql("select id, amount_cents, correction_of_id, created_at from group_remittances where group_admin_id=? order by created_at", hexid(ga_id))
    handed = sum(amt for _, amt, _, _ in rows)  # a correction row stores the DIFFERENCE (1.00 corrected to 0.50 = -0.50)
    held = collected - handed
    fmt = lambda c: f"{c // 100}.{c % 100:02d}"
    fmt_c = lambda c: f"{c // 100},{c % 100:02d}"
    info("dod6", "expected from SQL", f"collected {fmt(collected)} handed over {fmt(handed)} held {fmt(held)}")
    for label, text in (("/admin/groups", adm), ("/overview/chairs", site)):
        check("dod6", f"{label} shows collected {fmt(collected)}, handed over {fmt(handed)}, held {fmt(held)}",
              all(re.search(rf"\b{re.escape(v)}\b", text) or re.search(rf"\b{re.escape(w)}\b", text) for v, w in ((fmt(collected), fmt_c(collected)), (fmt(handed), fmt_c(handed)), (fmt(held), fmt_c(held)))), text[:300])
    check("dod6", "collected counts only the group admin's cash (12.00 + 3.00); the head admin's own cash payments (2.00, 4.00) are not group money", collected == 1500, collected)
    # set balance for every person: head can set; target reached exactly
    targets = {}
    for uname, amount, direction in (("carol", "7.00", "credit"), ("bob", "0.00", "owes"), ("alice", "2.50", "owes")):
        uid = dashed(one("select id from users where username=?", uname))
        rr, cc = post_stepup(fresh, f"/admin/users/{uid}/balance", {"amount": amount, "direction": direction, "note": "n-setbal"})
        targets[uname] = (uid, amount, direction)
    for uname, (uid, amount, direction) in targets.items():
        eff = one("select coalesce((select sum(amount_cents) from consumption_events where user_id=?),0) - coalesce((select sum(amount_cents) from payment_events where user_id=?),0)", hexid(uid), hexid(uid))
        want_bal = int(round(float(amount) * 100)) * (1 if direction == "owes" else -1)
        check("dod6", f"head set balance of {uname} to {amount} {direction}: SQL balance equals the target", eff == want_bal, (eff, want_bal))
    # every person page and account page agree with SQL
    mism = []
    for (uname,) in sql("select username from users where merged_into_id is null"):
        uid = dashed(one("select id from users where username=?", uname))
        bal = one("select coalesce((select sum(amount_cents) from consumption_events where user_id=?),0) - coalesce((select sum(amount_cents) from payment_events where user_id=?),0)", hexid(uid), hexid(uid))
        page = text_of(head.get(f"/admin/users/{uid}").text)
        shown = fmt(abs(bal)), fmt_c(abs(bal))
        if not any(s in page for s in shown):
            mism.append((uname, bal))
    check("dod6", "the head admin's person pages show the SQL balance of every person", not mism, mism)

    # ===== DoD 5: the open site ================================================================================================
    sentinel_ip = "10.33"
    pages = ["/overview", "/overview/chairs", "/overview/people", "/overview/prices"]
    pids = list(dict.fromkeys(re.findall(r"/overview/people/([0-9a-f\-]{36})", alice.get("/overview/people").text)))
    pages += [f"/overview/people/{p}" for p in pids]
    forb = {"an email address": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}", "tum.de": r"\btum\.de\b", "an argon2 hash": r"\$argon2", "an IP address": r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
            "a username (alice/bob/carol/guest1/guest2/sub/student)": r"(?<![A-Za-z])(?:alice|bob|carol|guest1|guest2|sub|student)(?![A-Za-z])", "a note (n-pay, n-adj, ga-cash, head-cash, n-bal...)": r"n-(?:pay|adj|rev|bal|rem|remc|setbal)|ga-cash|head-cash",
            "the head admin's username": r"(?<![A-Za-z])head(?![A-Za-z])(?! admin)"}
    hits = []
    for p in pages:
        body = alice.get(p)
        t = text_of(body.text)
        for label, rx in forb.items():
            if re.search(rx, t) or (label == "an argon2 hash" and re.search(rx, body.text)):
                hits.append((p, label, re.search(rx, t).group(0) if re.search(rx, t) else ""))
    check("dod5", f"none of {len(pages)} site pages shows an email, username, hash, note, admin username or IP", not hits, hits[:6])
    info("dod5", "pages checked", " ".join(pages[:4]) + f" + {len(pids)} person pages")
    check("dod5", "site shows names, chairs and the balance in words", any(w in text_of(alice.get("/overview/people").text) for w in ("owe", "Credit", "settled", "Outstanding")))
    csv_head = head.get("/admin/exports/ledger.csv").text
    r = anon.get("/overview")
    check("dod5", "an anonymous visitor is redirected to sign-in (no-store)", r.status_code == 303 and "/login" in r.headers["location"] and "no-store" in r.headers.get("cache-control", ""), r.status_code)
    check("dod5", "any verified signed-in user opens the site: a member, a guest and the group admin's member session",
          all(w.get("/overview").status_code == 200 for w in (bob, guest1, guest2, alice)), [w.get("/overview").status_code for w in (bob, guest1, guest2, alice)])
    check("dod5", "an admin cookie alone does not open the member site (admin session is not a user session)", head.get("/overview").status_code == 303)
    # who recorded: the site never names the recorder

    # ===== ledger integrity ================================================================================================
    r = subprocess.run([ARGS.py, "-m", "app.cli", "check-ledger"], capture_output=True, text=True, cwd=ARGS.repo, env=cli_env())
    check("ledger", "python -m app.cli check-ledger exits 0 after all of the above", r.returncode == 0, (r.stdout + r.stderr)[-300:])
    info("ledger", "check-ledger output", (r.stdout + r.stderr).strip().replace("\n", " | ")[:300])
    trig = []
    for tbl in ("consumption_events", "payment_events", "audit_log", "group_remittances", "prices"):
        try:
            con = sqlite3.connect(DB)
            con.execute(f"update {tbl} set note=note" if tbl != "audit_log" else "update audit_log set action=action")
            con.commit()
            trig.append((tbl, "UPDATE ALLOWED"))
        except sqlite3.Error as e:
            trig.append((tbl, "refused"))
        finally:
            con.close()
    check("ledger", "SQL UPDATE on the append-only tables is refused by triggers", all(s == "refused" for _, s in trig), trig)

    Path(ARGS.out).write_text(json.dumps(results, indent=1))
    failed = [r for r in results if not r["ok"]]
    print(f"\n{len([r for r in results if not r.get('info')])} checks, {len(failed)} FAILED ({ARGS.name})", flush=True)
    return 1 if failed else 0


def cli_env():
    import os
    env = dict(os.environ)
    for kv in ARGS.cli_env:
        k, v = kv.split("=", 1)
        env[k] = v
    env["PATH"] = str(Path(ARGS.py).parent) + ":" + env.get("PATH", "")
    return env


if __name__ == "__main__":
    raise SystemExit(main())
