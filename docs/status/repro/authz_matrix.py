"""Final audit (task 7.2): authorization and CSRF matrix, enumerated programmatically.

    python docs/status/repro/authz_matrix.py [--markdown]

Enumerates every route of the running app (OpenAPI paths PLUS the routes that are hidden from the schema:
/healthz, /readyz, /static) and probes each (method, path) as four principals:

    anon        no cookie
    user        ordinary signed-in member (user session cookie only)
    ga          group admin of chair A (admin cookie), probed with a target in chair A ("in scope")
                and a target in chair B ("out of scope")
    head        head (global) admin (admin cookie)

and, for every POST, in three variants: valid CSRF token + same-origin Origin, missing token, valid token +
cross-site Origin. The outcome is compared with an expected policy table written independently below (from
the plan, not from the code) and with the database: a rejected request must change nothing, and the
balance-changing routes must not change the ledger on the FIRST request (that is the step-up preview; only
/admin/stepup/confirm executes).

Exit code 0 only if every probe matches. Prints a JSON summary (and with --markdown the matrix).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

tmp = tempfile.mkdtemp(prefix="authz-matrix-")
DB = os.path.join(tmp, "m.db")
os.environ.update(ENVIRONMENT="development", PUBLIC_BASE_URL="http://testserver", MAIL_BACKEND="memory",
                  SECRET_KEY="audit-authz-matrix-secret-0123456789abcdef", DATABASE_URL=f"sqlite:///{DB}",
                  ARGON2_TIME_COST="1", ARGON2_MEMORY_COST_KIB="8", ARGON2_PARALLELISM="1",
                  TRUSTED_PROXY_IPS="")

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402

cfg = Config(str(ROOT / "alembic.ini"))
cfg.attributes["url"] = f"sqlite:///{DB}"
cfg.attributes["configure_logger"] = False
command.upgrade(cfg, "head")

from fastapi.testclient import TestClient  # noqa: E402

from app.db import write_session  # noqa: E402
from app.main import create_app  # noqa: E402
from app.services import admin_auth, groups, ledger  # noqa: E402
from app.services.admin_auth import ADMIN_COOKIE  # noqa: E402
from app.timeutil import utcnow  # noqa: E402
from app.web import tokens  # noqa: E402
from tests import factories  # noqa: E402

# ----------------------------------------------------------------------------------------------------
# Expected policy, per (method, path pattern). Written from the plan (docs/PLAN-v2-rev4.md section 4/5):
#   public   anyone
#   user     needs a member session
#   admin    any admin (group admin or head)
#   scoped   any admin, but the {user_id} must be in the admin's scope
#   head     head admin only
#   headuser head admin only (and the user must exist)
#   session  any live admin session (enrolment/logout)
POLICY = {
    ("GET", "/healthz"): "public", ("HEAD", "/healthz"): "public", ("GET", "/readyz"): "public",
    ("HEAD", "/readyz"): "public",
    ("GET", "/login"): "public", ("POST", "/login"): "public",
    ("GET", "/register"): "public", ("POST", "/register"): "public", ("POST", "/register/guest"): "public",
    ("GET", "/forgot"): "public", ("POST", "/forgot"): "public",
    ("GET", "/reset/{token}"): "public", ("POST", "/reset/{token}"): "public",
    ("GET", "/verify/{token}"): "public", ("POST", "/verify/{token}"): "public",  # bad token -> 400
    ("GET", "/privacy"): "public",
    ("GET", "/"): "public", ("HEAD", "/"): "public",
    ("GET", "/account"): "user", ("GET", "/account/edit"): "user", ("POST", "/account/edit"): "user",
    ("POST", "/account/password"): "user", ("POST", "/account/deactivate"): "user",
    ("POST", "/logout"): "user",
    ("GET", "/coffee/{kind}"): "public", ("POST", "/coffee/{kind}"): "scantoken",
    ("GET", "/coffee/done/{event_id}"): "user", ("POST", "/coffee/undo/{event_id}"): "user",
    ("GET", "/overview"): "user", ("GET", "/overview/chairs"): "user", ("GET", "/overview/people"): "user",
    ("GET", "/overview/people/{person_id}"): "user", ("GET", "/overview/prices"): "user",
    ("GET", "/admin/login"): "public", ("POST", "/admin/login"): "public",
    ("GET", "/admin"): "admin", ("GET", "/admin/users"): "admin", ("GET", "/admin/users/export.csv"): "admin",
    ("GET", "/admin/exports"): "admin", ("GET", "/admin/exports/ledger.csv"): "admin",
    ("GET", "/admin/qr"): "admin", ("POST", "/admin/qr"): "admin", ("GET", "/admin/qr/{kind}.svg"): "admin",
    ("GET", "/admin/account"): "admin", ("POST", "/admin/account/password"): "admin",
    ("POST", "/admin/account/sessions/revoke"): "admin",
    ("POST", "/admin/stepup/confirm"): "admin",
    ("GET", "/admin/totp/setup"): "session", ("POST", "/admin/totp/setup"): "session",
    ("POST", "/admin/logout"): "session",
    ("GET", "/admin/users/{user_id}"): "scoped", ("POST", "/admin/users/{user_id}/payment"): "scoped",
    ("POST", "/admin/users/{user_id}/adjustment"): "scoped",
    ("POST", "/admin/users/{user_id}/events/{event_id}/reverse"): "scoped",
    ("POST", "/admin/users/{user_id}/rename"): "scoped", ("POST", "/admin/users/{user_id}/status"): "scoped",
    ("POST", "/admin/users/{user_id}/sessions/revoke"): "scoped",
    ("POST", "/admin/users/{user_id}/balance"): "headuser",
    ("POST", "/admin/users/{user_id}/chair"): "headuser",
    ("GET", "/admin/users/{user_id}/merge"): "headuser", ("POST", "/admin/users/{user_id}/merge"): "headuser",
    ("GET", "/admin/users/{user_id}/sponsor"): "headuser", ("POST", "/admin/users/{user_id}/sponsor"): "headuser",
    ("POST", "/admin/users/{user_id}/group-admin/promote"): "headuser",
    ("POST", "/admin/users/{user_id}/group-admin/demote"): "headuser",
    ("GET", "/admin/admins"): "head", ("GET", "/admin/audit"): "head", ("GET", "/admin/chairs"): "head",
    ("POST", "/admin/chairs"): "head", ("POST", "/admin/chairs/{chair_id}/rename"): "head",
    ("POST", "/admin/chairs/{chair_id}/active"): "head", ("GET", "/admin/prices"): "head",
    ("POST", "/admin/prices"): "head", ("GET", "/admin/groups"): "head",
    ("POST", "/admin/groups/remittances"): "head",
    ("POST", "/admin/groups/remittances/{remittance_id}/correct"): "head",
    ("GET", "/admin/exports/group-balances.csv"): "head",
}
# POSTs of the head admin that must NOT touch the ledger on the first request (step-up preview only).
PREVIEW_ONLY = {
    "/admin/users/{user_id}/payment", "/admin/users/{user_id}/adjustment",
    "/admin/users/{user_id}/events/{event_id}/reverse", "/admin/users/{user_id}/balance",
    "/admin/users/{user_id}/merge", "/admin/groups/remittances",
    "/admin/groups/remittances/{remittance_id}/correct",
}
FORM = {
    "/login": {"username": "nobody", "password": "x" * 12},
    "/register": {"username": "mallory", "display_name": "Mallory", "chair_id": "{chair_a}",
                  "email": "mallory@tum.de", "password": "a-long-enough-password",
                  "password2": "a-long-enough-password", "privacy_ack": "1"},
    "/register/guest": {"username": "mallory2", "display_name": "Mallory", "sponsor_email": "alice@tum.de",
                        "password": "a-long-enough-password", "password2": "a-long-enough-password",
                        "privacy_ack": "1"},
    "/forgot": {"username": "alice"},
    "/reset/{token}": {"password": "a-long-enough-password", "password2": "a-long-enough-password"},
    "/verify/{token}": {},
    "/account/edit": {"display_name": "Pwned", "chair_id": "{chair_b}"},
    "/account/password": {"current_password": "x" * 12, "password": "a-long-enough-password",
                          "password2": "a-long-enough-password"},
    "/account/deactivate": {"confirm": "1"},
    "/logout": {}, "/coffee/{kind}": {"token": "forged"}, "/coffee/undo/{event_id}": {},
    "/admin/login": {"username": "nobody", "password": "x" * 12},
    "/admin/logout": {}, "/admin/totp/setup": {"code": "000000"},
    "/admin/account/password": {"current_password": "x" * 12, "new_password": "y" * 14, "new_password2": "y" * 14},
    "/admin/account/sessions/revoke": {}, "/admin/qr": {"line": "hello"},
    "/admin/stepup/confirm": {"payload": "not-a-payload", "nonce": "x"},
    "/admin/users/{user_id}/payment": {"amount": "5"}, "/admin/users/{user_id}/adjustment": {"quantity": "1"},
    "/admin/users/{user_id}/events/{event_id}/reverse": {},
    "/admin/users/{user_id}/rename": {"display_name": "Renamed"},
    "/admin/users/{user_id}/chair": {"chair_id": "{chair_b}"},
    "/admin/users/{user_id}/status": {"active": "0"}, "/admin/users/{user_id}/sessions/revoke": {},
    "/admin/users/{user_id}/merge": {"target_id": "{user2}"},
    "/admin/users/{user_id}/balance": {"amount": "5", "direction": "owes"},
    "/admin/users/{user_id}/group-admin/promote": {}, "/admin/users/{user_id}/group-admin/demote": {},
    "/admin/users/{user_id}/sponsor": {"sponsor_id": "{user2}"},
    "/admin/chairs": {"full_name": "New chair", "short_name": "NEW"},
    "/admin/chairs/{chair_id}/rename": {"full_name": "Renamed chair", "short_name": "REN"},
    "/admin/chairs/{chair_id}/active": {"active": "1"}, "/admin/prices": {"price": "0.60"},
    "/admin/groups/remittances": {"group_admin_id": "{ga_admin}", "amount": "5"},
    "/admin/groups/remittances/{remittance_id}/correct": {"corrected_to": "4"},
}


def enumerate_routes(app):
    found = set()
    for path, item in app.openapi()["paths"].items():
        for method in item:
            found.add((method.upper(), path))
    # routes that are not in the schema (health; HEAD / is registered with include_in_schema=False)
    found |= {("GET", "/healthz"), ("HEAD", "/healthz"), ("GET", "/readyz"), ("HEAD", "/readyz"),
              ("HEAD", "/")}
    return sorted(found)


def fingerprint(skip_audit: bool = False) -> str:
    con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    try:
        h = hashlib.sha256()
        for (t,) in con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall():
            if t in ("rate_limit_events", "alembic_version", "pending_actions") or (skip_audit and t == "audit_log"):
                continue  # bookkeeping written even by anonymous sign-in redirects (purged by purge-expired)
            cols = [c[1] for c in con.execute(f'PRAGMA table_info("{t}")') if c[1] not in ("last_seen_at",)]
            rows = sorted(map(repr, con.execute(f'SELECT {",".join(cols)} FROM "{t}"')))
            h.update(t.encode())
            h.update("\n".join(rows).encode())
        return h.hexdigest()
    finally:
        con.close()


def ledger_fingerprint() -> str:
    con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    try:
        h = hashlib.sha256()
        for t in ("consumption_events", "payment_events", "group_remittances", "prices", "users"):
            h.update(repr(sorted(map(repr, con.execute(f'SELECT * FROM "{t}"')))).encode())
        return h.hexdigest()
    finally:
        con.close()


def build_world():
    ids = {}
    with write_session() as w:
        ca = factories.make_chair(w, short_name="CHA", full_name="Chair A", commit=False)
        cb = factories.make_chair(w, short_name="CHB", full_name="Chair B", commit=False)
        factories.set_price(w, 50, commit=False)
        head = factories.make_admin(w, "global", username="head", commit=False)
        ga = factories.make_admin(w, "chair", [ca], username="ga", commit=False)
        in_user = factories.make_member(w, "Alice In", ca, username="alice", commit=False)
        in_user2 = factories.make_member(w, "Alice Two", ca, username="alice2", commit=False)
        out_user = factories.make_member(w, "Bob Out", cb, username="bob", commit=False)
        me = factories.make_member(w, "Me Myself", ca, username="me", commit=False)  # the "user" principal
        w.flush()
        ev_in = factories.add_events(w, in_user, "single", commit=False)[0]
        ev_out = factories.add_events(w, out_user, "single", commit=False)[0]
        ledger.add_payment(w, admin=ga, user_id=in_user.id, amount_cents=1000)
        rem = groups.record_remittance(w, head_admin=head, group_admin_id=ga.id, amount_cents=300,
                                       idempotency_key="matrix-remit")
        raw_user = "u" * 43
        factories.make_session(w, me, raw_token=raw_user, commit=False)
        ids = {"chair_a": ca.id, "chair_b": cb.id, "head": head.id, "ga": ga.id, "ga_admin": ga.id,
               "in_user": in_user.id, "me": me.id, "user2": in_user2.id, "out_user": out_user.id, "ev_in": ev_in.id,
               "ev_out": ev_out.id, "remittance_id": rem.id, "chair_id": ca.id}
        ids["_raw_user"] = raw_user
    return ids


def admin_cookie_for(admin_id):
    from app.models import AdminUser
    with write_session() as w:
        admin = w.get(AdminUser, admin_id)
        if not admin.totp_enabled:  # enrolled admins only: an un-enrolled admin is redirected to /admin/totp/setup
            admin_auth.begin_enrollment(w, admin)
            admin.totp_enabled = True
            w.flush()
        session, raw = admin_auth._new_session(w, admin, now=utcnow())
        return raw, tokens.csrf_token("admin", session.csrf_secret)


def user_csrf(raw_user):
    from app.models import UserSession
    from sqlalchemy import select
    from app.db import read_session
    with read_session() as r:
        sid = r.scalar(select(UserSession.id).where(UserSession.token_hash == hashlib.sha256(raw_user.encode()).hexdigest()))
    return tokens.csrf_token("user", str(sid))


def fill(s, ids, target):
    ids = {**ids, "user_id": target, "event_id": ids["ev_in"] if target == ids["in_user"] else ids["ev_out"],
           "kind": "single", "token": "sometoken", "person_id": target}
    for k, v in ids.items():
        s = s.replace("{" + k + "}", str(v))
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--markdown", action="store_true")
    args = ap.parse_args()

    ids = build_world()
    app = create_app()
    routes = enumerate_routes(app)
    unknown = [r for r in routes if (r[0], r[1]) not in POLICY and r[1] not in ("/openapi.json",)
               and not r[1].startswith(("/docs", "/redoc"))]
    covered_missing = [k for k in POLICY if k not in set(routes)]


    def client(who):
        """A fresh client per probe; admins get a fresh session each time (the logout probe kills one)."""
        c = TestClient(app, raise_server_exceptions=False, follow_redirects=False)
        csrf = None
        if who == "user":
            import secrets
            raw = secrets.token_urlsafe(32)
            with write_session() as w:
                from app.models import User
                factories.make_session(w, w.get(User, ids["me"]), raw_token=raw, commit=False)
            c.cookies.set("coffee_session", raw, path="/")
            csrf = user_csrf(raw)
        elif who in ("ga", "head"):
            raw, csrf = admin_cookie_for(ids[who])
            c.cookies.set(ADMIN_COOKIE, raw, path="/admin")
        return c, csrf

    failures, rows, probes = [], [], 0

    def verdict(r):
        loc = r.headers.get("location", "")
        if r.status_code == 303 and loc.startswith(("/login", "/admin/login")):
            return "redirect-login"
        if r.status_code == 303 and loc.startswith("/admin/totp/setup"):
            return "redirect-enrol"
        if r.status_code == 400:
            return "bad-request"
        if r.status_code in (401, 403):
            return "denied"
        if r.status_code == 404:
            return "not-found"
        if r.status_code in (200, 303):
            return "allowed"
        return f"status-{r.status_code}"

    for method, path in routes:
        if (method, path) not in POLICY:
            continue
        policy = POLICY[(method, path)]
        area = "admin" if path.startswith("/admin") else "user"
        for who in ("anon", "user", "ga", "head"):
            targets = [("in", ids["in_user"])]
            if policy in ("scoped", "headuser") or "{user_id}" in path:
                targets.append(("out", ids["out_user"]))
            for tname, target in targets:
                url = fill(path, ids, target)
                variants = ["get"] if method in ("GET", "HEAD") else ["csrf", "nocsrf", "xsite"]
                for variant in variants:
                    probes += 1
                    c, my_csrf = client(who)
                    before, ledger_before, noaudit_before = fingerprint(), ledger_fingerprint(), fingerprint(True)
                    if method in ("GET", "HEAD"):
                        r = c.request(method, url)
                    else:
                        data = {k: fill(v, ids, target) for k, v in FORM.get(path, {}).items()}
                        headers = {"Origin": "http://testserver"}
                        if variant == "csrf":
                            data["csrf_token"] = my_csrf or "x"
                            if who == "anon" and not area == "admin":
                                c.cookies.set("coffee_csrf", "anon-cookie")
                                data["csrf_token"] = tokens.csrf_token("anon", "anon-cookie")
                        elif variant == "xsite":
                            data["csrf_token"] = my_csrf or "x"
                            headers = {"Origin": "https://evil.example"}
                        r = c.post(url, data=data, headers=headers)
                    after, ledger_after, noaudit_after = fingerprint(), ledger_fingerprint(), fingerprint(True)
                    v = verdict(r)
                    changed = after != before
                    cfg_key = f"{method} {path} [{tname}]"
                    # ---- expectations
                    ok = True
                    why = ""
                    if method not in ("GET", "HEAD") and variant == "xsite":
                        ok = r.status_code == 403 and not changed
                        why = "cross-site POST must be 403 and change nothing"
                    elif method not in ("GET", "HEAD") and variant == "nocsrf":
                        cond = (r.status_code == 403 or v == "redirect-login")
                        # a few public POSTs are not CSRF-protected by token (scan token / login redirect)
                        ok = (cond or (policy == "scantoken" and r.status_code == 400)) and not changed
                        why = "POST without CSRF token must be 403 (or login redirect) and change nothing"
                    else:
                        authed_user = who == "user"
                        authed_admin = who in ("ga", "head")
                        if policy == "scantoken":
                            # forged scan token: refused (400) without a session, nothing booked
                            ok = r.status_code == 400 and not changed
                            why = "scan POST with a forged token is refused"
                        elif policy == "public":
                            ok = v in ("allowed", "denied", "not-found", "bad-request") and (r.status_code != 500)
                            # public pages never redirect to login
                            ok = ok and v != "redirect-login"
                            why = "public route must not require login"
                        elif policy == "user":
                            if authed_user:
                                ok = r.status_code not in (401, 403, 500) and v != "redirect-login"
                            else:
                                ok = (v == "redirect-login" or r.status_code in (401, 403)) and not changed
                            why = "user route: member session only"
                        elif policy in ("admin", "session"):
                            if authed_admin:
                                ok = r.status_code < 500 and v not in ("redirect-login",)
                                if path == "/admin/stepup/confirm":
                                    ok = r.status_code < 500
                            else:
                                ok = v == "redirect-login" and not changed
                            why = "admin route: admin cookie only"
                        elif policy == "scoped":
                            if who == "head" or (who == "ga" and tname == "in"):
                                ok = r.status_code < 500 and v != "redirect-login"
                            elif who == "ga":
                                ok = r.status_code in (403, 404) and not changed
                            else:
                                ok = v == "redirect-login" and not changed
                            why = "scoped route: head any, group admin only own chair"
                        elif policy in ("head", "headuser"):
                            if who == "head":
                                ok = r.status_code < 500 and v != "redirect-login"
                            elif who == "ga":
                                ok = r.status_code in (403, 404) and not changed
                            else:
                                ok = v == "redirect-login" and not changed
                            why = "head-only route"
                        # step-up: first request on a balance route never books anything
                        if (variant == "csrf" and who == "head" and path in PREVIEW_ONLY
                                and ledger_after != ledger_before):
                            ok = False
                            why = "balance route executed without step-up confirm"
                        # a request that is not allowed must never change state
                        if variant in ("get", "csrf", "nocsrf") and ok is True and who in ("anon", "user") \
                                and area == "admin" and changed:
                            ok = False
                            why = "state changed for a non-admin principal"
                    if method in ("GET", "HEAD") and noaudit_after != noaudit_before:
                        # only the audit_log row of an export download is allowed to change on a GET
                        ok = False
                        why = "a GET/HEAD request changed stored state other than the audit log (CSRF-able write)"
                    rows.append((method, path, tname, who, variant, r.status_code, v, "changed" if changed else "-", ok))
                    if path == "/admin/logout" and who in ("ga", "head") and variant == "csrf":
                        ok = v == "redirect-login"  # logout succeeds: session revoked, back to the login page
                    # Self-deactivate anonymizes `me` and kills sessions; put the principal back for later probes.
                    if path == "/account/deactivate" and who == "user" and variant == "csrf" and r.status_code == 303:
                        from app.models import User
                        from app.services import users as users_svc
                        with write_session() as w:
                            u = w.get(User, ids["me"])
                            if users_svc.get_identity_restore(w, u.id) is not None:
                                users_svc.restore_identity(w, user=u, actor_type="system")
                            elif u.status != "active":
                                u.status = "active"
                    if not ok:
                        failures.append({"probe": cfg_key, "who": who, "variant": variant, "status": r.status_code,
                                         "verdict": v, "db_changed": changed, "rule": why,
                                         "body": re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", r.text))[:160]})

    summary = {"routes_enumerated": len(routes), "routes_with_policy": len(POLICY), "probes": probes,
               "routes_without_policy": unknown, "policy_entries_without_route": covered_missing,
               "failures": failures}
    # Cookie scoping: the user cookie must not open /admin and the admin cookie must not open the user area.
    c, _ = client("user")
    r = c.get("/admin/users")
    summary["user_cookie_on_admin_users"] = r.status_code
    c, _ = client("head")
    r = c.get("/overview")
    summary["admin_cookie_on_overview"] = [r.status_code, r.headers.get("location")]
    # Positive controls on fresh users (the sweep above mutates the world): the allowed paths really work.
    with write_session() as w:
        fresh_in = factories.make_member(w, "Fresh In", w.get(__import__("app.models", fromlist=["Chair"]).Chair, ids["chair_a"]),
                                         username="fresh-in", commit=False)
        fresh_out = factories.make_member(w, "Fresh Out", w.get(__import__("app.models", fromlist=["Chair"]).Chair, ids["chair_b"]),
                                          username="fresh-out", commit=False)
        w.flush()
        fi, fo = fresh_in.id, fresh_out.id
    controls = {}
    for who, target, label in (("ga", fi, "ga renames in-scope"), ("ga", fo, "ga renames out-of-scope"),
                               ("head", fo, "head renames out-of-scope")):
        c, csrf = client(who)
        before = fingerprint()
        r = c.post(f"/admin/users/{target}/rename", data={"display_name": "Renamed " + label, "csrf_token": csrf},
                   headers={"Origin": "http://testserver"})
        controls[label] = [r.status_code, fingerprint() != before]
    summary["positive_controls"] = controls
    if controls["ga renames in-scope"] != [303, True] or controls["ga renames out-of-scope"][1] \
            or controls["ga renames out-of-scope"][0] not in (403, 404) or controls["head renames out-of-scope"] != [303, True]:
        failures.append({"probe": "positive controls", "detail": controls})
    if summary["user_cookie_on_admin_users"] != 303 or summary["admin_cookie_on_overview"][0] != 303:
        failures.append({"probe": "cookie scoping", "detail": summary})
    if args.markdown:
        print("| method | route | target | principal | variant | status | verdict | db | ok |")
        print("|---|---|---|---|---|---|---|---|---|")
        for row in rows:
            print("| " + " | ".join(str(x) for x in row) + " |")
    print(json.dumps(summary, indent=1, default=str))
    return 0 if not failures and not unknown and not covered_missing else 1


if __name__ == "__main__":
    sys.exit(main())
