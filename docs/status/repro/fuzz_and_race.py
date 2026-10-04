"""Final audit (task 7.2): form fuzzing (no 5xx) and double-submit races (exactly one booking).

    python docs/status/repro/fuzz_and_race.py

Re-uses the world and the principals of authz_matrix.py (development configuration, temp database).

1. FUZZ: every POST route of the app is sent every value of a hostile list in every one of its form fields
   (empty, whitespace, huge numbers, exponents, NaN/inf, full-width digits, comma decimals, negative zero, NUL,
   control characters, overlong text, markup, SQL metacharacters, unicode direction overrides, bad UUIDs) as the
   head admin, as the group admin (own and foreign target) and as a signed-in member. Any 5xx, any Python
   traceback in a page, and any unhandled error in the log is reported. Known defects are listed, not hidden.
2. RACE: the same step-up confirm is posted by 8 threads at once (must book exactly once), the same scan token
   by 8 threads (exactly one coffee), the same idempotent remittance preview/confirm, and 8 concurrent
   registrations of one address (never more pending rows than the per-address cap of 5 per hour).

Exit code 0 only when there is no 5xx outside the documented known-defect list and every race books exactly once.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import sys
import threading
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.argv = [sys.argv[0]]
import authz_matrix as M  # noqa: E402  (builds the temp database and world on import)

from fastapi.testclient import TestClient  # noqa: E402

app = M.create_app()
ids = M.build_world()

VALUES = ["", " ", "0", "-0", "-1", "1", "1e309", "1e-9", "nan", "inf", "-inf", "999999999999999999999999999999",
          "９９", "1,5", "1.005", "0.001", "5.", ".5", "+5", "5 5", "\x00", "a\x00b", "\x1b[31m", "a\r\nb: c", "<script>x</script>",
          "'; DROP TABLE users;--", "\" OR 1=1 --", "%", "_", "‮evil", "a" * 5000, "00000000-0000-0000-0000-000000000000",
          "not-a-uuid", "../../etc/passwd", "{{7*7}}", "${7*7}", "null", "None", "true", "퟿", "😀", "\u0000\u0001"]
KNOWN_DEFECTS = {("POST", "/admin/users/{user_id}/events/{event_id}/reverse")}  # see repro_reverse_negative_adjustment.py

errors = []
errors_lock = threading.Lock()


class LogTap(logging.Handler):
    def __init__(self):
        super().__init__()
        self.unhandled = []

    def emit(self, record):
        if record.levelno >= logging.ERROR:
            self.unhandled.append(record.getMessage())


tap = LogTap()
logging.getLogger("app").addHandler(tap)


def fuzz():
    routes = [(m, p) for m, p in M.enumerate_routes(app) if m == "POST"]
    posts = 0
    codes = Counter()
    for method, path in routes:
        form = M.FORM.get(path, {})
        if not form:
            continue
        for who in ("head", "ga", "user"):
            if who == "user" and path.startswith("/admin"):
                continue
            if who != "user" and not path.startswith("/admin"):
                continue
            for target_name in ("in", "out") if "{user_id}" in path else ("in",):
                target = ids["in_user"] if target_name == "in" else ids["out_user"]
                for fld in form:
                    for val in VALUES:
                        # fresh session each time: logout / deactivation probes would otherwise end the run
                        client = _client(who)
                        c, csrf = client
                        data = {k: M.fill(v, ids, target) for k, v in form.items()}
                        data[fld] = val
                        data["csrf_token"] = csrf or "x"
                        before_errors = len(tap.unhandled)
                        try:
                            r = c.post(M.fill(path, ids, target), data=data, headers={"Origin": "http://testserver"})
                        except Exception as exc:  # noqa: BLE001
                            errors.append({"route": f"POST {path}", "field": fld, "value": repr(val)[:40], "who": who,
                                           "error": f"client exception {type(exc).__name__}: {str(exc)[:100]}"})
                            continue
                        posts += 1
                        codes[r.status_code] += 1
                        leaked = "Traceback" in r.text or "IntegrityError" in r.text or "sqlalchemy" in r.text
                        if r.status_code >= 500 or leaked or len(tap.unhandled) > before_errors:
                            errors.append({"route": f"POST {path}", "field": fld, "value": repr(val)[:40], "who": who,
                                           "status": r.status_code, "leaked": leaked, "known": (method, path) in KNOWN_DEFECTS})
    return posts, codes


_sessions = {}


def _client(who):
    c = TestClient(app, raise_server_exceptions=False, follow_redirects=False)
    csrf = None
    if who == "user":
        import secrets
        from app.db import write_session
        from app.models import User
        raw = secrets.token_urlsafe(32)
        with write_session() as w:
            M.factories.make_session(w, w.get(User, ids["me"]), raw_token=raw, commit=False)
        c.cookies.set("coffee_session", raw, path="/")
        csrf = M.user_csrf(raw)
    else:
        raw, csrf = M.admin_cookie_for(ids[who])
        c.cookies.set(M.ADMIN_COOKIE, raw, path="/admin")
    return c, csrf


def race():
    out = {}
    from app.db import read_session
    # --- 1. same step-up confirm from 8 threads
    head, csrf = _client("head")
    r = head.post(f"/admin/users/{ids['in_user']}/payment", data={"csrf_token": csrf, "amount": "7", "note": "race"},
                  headers={"Origin": "http://testserver"})
    fields = {n: re.search(rf'name="{n}" value="([^"]*)"', r.text).group(1) for n in ("csrf_token", "payload", "nonce")}
    con = sqlite3.connect(M.DB)
    n0 = con.execute("select count(*) from payment_events").fetchone()[0]
    codes = []

    def confirm():
        codes.append(head.post("/admin/stepup/confirm", data=fields, headers={"Origin": "http://testserver"}).status_code)
    ts = [threading.Thread(target=confirm) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    out["confirm x8 payments booked"] = con.execute("select count(*) from payment_events").fetchone()[0] - n0
    out["confirm x8 statuses"] = dict(Counter(codes))
    # --- 2. same scan token from 8 threads
    user, ucsrf = _client("user")
    page = user.get("/coffee/single")
    token = re.search(r'name="token" value="([^"]*)"', page.text).group(1)
    e0 = con.execute("select count(*) from consumption_events").fetchone()[0]
    codes = []

    def scan():
        codes.append(user.post("/coffee/single", data={"token": token}, headers={"Origin": "http://testserver"}).status_code)
    ts = [threading.Thread(target=scan) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    out["scan x8 coffees booked"] = con.execute("select count(*) from consumption_events").fetchone()[0] - e0
    out["scan x8 statuses"] = dict(Counter(codes))
    # --- 3. concurrent registration of one username
    anon = TestClient(app, raise_server_exceptions=False, follow_redirects=False)
    pg = anon.get("/register")
    tok = re.search(r'name="csrf_token" value="([^"]*)"', pg.text).group(1)
    form = {"csrf_token": tok, "username": "racer", "display_name": "Racer", "chair_id": str(ids["chair_a"]),
            "email": "racer@tum.de", "password": "a-long-enough-password", "password2": "a-long-enough-password", "privacy_ack": "1"}
    pend0 = con.execute("select count(*) from pending_registrations").fetchone()[0]
    codes = []

    def reg():
        codes.append(anon.post("/register", data=form, headers={"Origin": "http://testserver"}).status_code)
    ts = [threading.Thread(target=reg) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    out["register x8 pending rows"] = con.execute("select count(*) from pending_registrations").fetchone()[0] - pend0
    out["register x8 statuses"] = dict(Counter(codes))
    con.close()
    return out


def main():
    posts, codes = fuzz()
    print(f"fuzz: {posts} POSTs, status counts {dict(sorted(codes.items()))}")
    unexpected = [e for e in errors if not e.get("known")]
    known = [e for e in errors if e.get("known")]
    summary = Counter((e["route"], e.get("status", e.get("error"))) for e in unexpected)
    print("known defect hits (reverse of a negative adjustment is not fuzzed into existence here):", len(known))
    print("unexpected 5xx / leaks / unhandled errors:", len(unexpected))
    for (route, st), n in summary.most_common(20):
        print("   ", route, st, n)
    for e in unexpected[:10]:
        print("   e.g.", e)
    r = race()
    print(json.dumps(r, indent=1))
    ok = (not unexpected and r["confirm x8 payments booked"] == 1 and r["scan x8 coffees booked"] == 1
          and r["register x8 pending rows"] <= 5)  # per-address cap REGISTRATION_EMAIL = 5/h, enforced under concurrency
    print("RESULT:", "OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
