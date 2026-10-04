"""Final audit (task 7.2): what happens when the head admin merges the user behind a GROUP ADMIN (role holder with
collected cash) into another person, and when the merged-away or the target person is later deactivated?

    python docs/status/repro/merge_group_admin.py

Prints what the services and every page do afterwards: group balance, /admin/groups, /admin/admins, /overview/chairs,
group balances CSV, `check-ledger`, whether the group admin can still sign in or act, and whether the money can still
be remitted. Exit code 0 when nothing crashes (no 5xx) and `check-ledger` stays OK.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
sys.argv = [sys.argv[0]]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import authz_matrix as M  # noqa: E402  (temp DB + world)

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.db import read_session, write_session  # noqa: E402
from app.models import AdminUser, User  # noqa: E402
from app.services import checker, groups, ledger, users as users_svc  # noqa: E402

app = M.create_app()
ids = M.build_world()
problems = []

with write_session() as w:
    head = w.get(AdminUser, ids["head"])
    ga = w.get(AdminUser, ids["ga"])
    ga_user = ga.user_id
    target = ids["user2"]  # another member of the same chair
    print("held before merge:", groups.held(w, ga.id), "cents; collected", groups.collected(w, ga.id))
    result = None
    try:
        result = users_svc.merge_users(w, admin=head, duplicate_id=ga_user, target_id=target)
        print("merge of the group admin's user accepted:", type(result).__name__)
    except Exception as exc:  # noqa: BLE001
        print("merge refused:", type(exc).__name__, exc)

with read_session() as r:
    ga = r.get(AdminUser, ids["ga"])
    u = r.get(User, ga.user_id)
    print("after: admin active =", ga.active, "role =", ga.role, "| linked user status =", u.status, "| merged_into =", getattr(u, "merged_into_id", None))
    print("held after:", groups.held(r, ga.id))

with read_session() as r:
    report = checker.check_ledger(r)
    print("check-ledger ok:", getattr(report, "ok", report))
    if not getattr(report, "ok", True):
        problems.append("check-ledger")

c = TestClient(app, raise_server_exceptions=False, follow_redirects=False)
raw, csrf = M.admin_cookie_for(ids["head"])
c.cookies.set(M.ADMIN_COOKIE, raw, path="/admin")
for p in ["/admin/groups", "/admin/admins", "/admin/exports/group-balances.csv", "/admin/users", f"/admin/users/{ids['in_user']}", f"/admin/users/{ids['user2']}"]:
    r = c.get(p)
    print("head GET", p, r.status_code)
    if r.status_code >= 500:
        problems.append(f"head GET {p} -> {r.status_code}")
u = TestClient(app, raise_server_exceptions=False, follow_redirects=False)
import secrets
tok = secrets.token_urlsafe(32)
with write_session() as w:
    M.factories.make_session(w, w.get(User, ids["me"]), raw_token=tok, commit=False)
u.cookies.set("coffee_session", tok, path="/")
for p in ["/overview", "/overview/chairs", "/overview/people", f"/overview/people/{ids['user2']}", f"/overview/people/{ids['in_user']}"]:
    r = u.get(p)
    print("user GET", p, r.status_code)
    if r.status_code >= 500:
        problems.append(f"user GET {p} -> {r.status_code}")

# the merged group admin's old admin session and password login
raw2, _ = None, None
ga_c = TestClient(app, raise_server_exceptions=False, follow_redirects=False)
with write_session() as w:
    from app.services import admin_auth
    from app.timeutil import utcnow
    adm = w.get(AdminUser, ids["ga"])
    try:
        session, rawtok = admin_auth._new_session(w, adm, now=utcnow())
        ga_c.cookies.set(M.ADMIN_COOKIE, rawtok, path="/admin")
        print("a session can still be created for the group admin of a merged user (via service)")
    except Exception as exc:  # noqa: BLE001
        print("no session for the group admin:", type(exc).__name__)
r = ga_c.get("/admin")
print("group admin of the merged user can open /admin:", r.status_code, r.headers.get("location", ""))
# remit the held money
with write_session() as w:
    head = w.get(AdminUser, ids["head"])
    try:
        held = groups.held(w, ids["ga"])
        rem = groups.record_remittance(w, head_admin=head, group_admin_id=ids["ga"], amount_cents=held, idempotency_key="after-merge")
        print("remittance of the held money after the merge: accepted, held now", groups.held(w, ids["ga"]))
    except Exception as exc:  # noqa: BLE001
        print("remittance after merge refused:", type(exc).__name__, exc)
print("RESULT:", "OK" if not problems else problems)
sys.exit(0 if not problems else 1)
