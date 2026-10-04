"""Final audit (task 7.2): independent recomputation of totals, group balances and chair roll-ups.

    python docs/status/repro/verify_scenario.py DB_PATH

Opens DB_PATH (built by long_scenario.py) READ-ONLY with plain sqlite3, recomputes from the raw rows, with its own
merge-chain walk (not the `effective_users` view), and compares the result with
  * the service layer (`ledger.get_totals`, `groups.*`, `overview.*`),
  * the HTTP pages `/admin/groups`, `/admin/` (held tile), `/overview`, `/overview/chairs`,
  * the CSV exports (users, ledger, group balances),
  * and a group admin's own scoped users export.
Exit code 0 only when every comparison matches. The definitions come from docs/V2-CONTRACT.md, not from the code.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import sqlite3
import sys
import uuid
from collections import defaultdict
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

FAILS: list[str] = []
CHECKS = 0


def check(label: str, got, want) -> None:
    global CHECKS
    CHECKS += 1
    if got != want:
        FAILS.append(f"{label}: got {got!r}, want {want!r}")


# ----- raw SQL model -----------------------------------------------------------------------------
class Raw:
    def __init__(self, path: str):
        self.c = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        self.c.row_factory = sqlite3.Row
        def fix(v):  # sqlite stores uuids as 32 hex characters
            if isinstance(v, str) and len(v) == 32 and all(ch in "0123456789abcdef" for ch in v):
                return uuid.UUID(v)
            return v

        q = lambda sql, *a: [{k: fix(v) for k, v in dict(r).items()} for r in self.c.execute(sql, a)]  # noqa: E731
        self.users = {r["id"]: r for r in q("SELECT * FROM users")}
        self.admins = {r["id"]: r for r in q("SELECT * FROM admin_users")}
        self.chairs = {r["id"]: r for r in q("SELECT * FROM chairs")}
        self.ce = q("SELECT * FROM consumption_events")
        self.pe = q("SELECT * FROM payment_events")
        self.rem = q("SELECT * FROM group_remittances")

    def eff(self, uid):
        seen = set()
        while self.users[uid]["merged_into_id"] and uid not in seen:
            seen.add(uid)
            uid = self.users[uid]["merged_into_id"]
        return uid

    def totals(self):
        t = defaultdict(lambda: {"shots": 0, "consumed": 0, "paid": 0})
        for e in self.ce:
            x = t[self.eff(e["user_id"])]
            x["shots"] += e["quantity"]
            x["consumed"] += e["amount_cents"]
        for p in self.pe:
            t[self.eff(p["user_id"])]["paid"] += p["amount_cents"]
        return t

    def collected(self, admin_id):
        return sum(p["amount_cents"] for p in self.pe if p["kind"] == "cash" and p["collector_admin_id"] == admin_id)

    def remitted(self, admin_id):
        return sum(r["amount_cents"] for r in self.rem if r["group_admin_id"] == admin_id)

    def chair_rollup(self):
        coll, rem = defaultdict(int), defaultdict(int)
        for p in self.pe:
            if p["kind"] == "cash" and p["collector_admin_id"] and self.admins[p["collector_admin_id"]]["role"] == "chair":
                coll[p["chair_id"]] += p["amount_cents"]
        for r in self.rem:
            if self.admins[r["group_admin_id"]]["role"] == "chair":
                rem[r["chair_id"]] += r["amount_cents"]
        return {cid: (coll[cid], rem[cid], coll[cid] - rem[cid]) for cid in set(coll) | set(rem)}


# ----- html helpers ------------------------------------------------------------------------------
class Tables(HTMLParser):
    """Collects every <table> as {'head': [...], 'rows': [[cell text...]]} (td and th text, whitespace folded)."""

    def __init__(self):
        super().__init__()
        self.tables, self._row, self._cell, self._in_head = [], None, None, False

    def handle_starttag(self, tag, attrs):
        if tag == "table":
            self.tables.append({"head": [], "rows": []})
        elif tag == "thead":
            self._in_head = True
        elif tag == "tr":
            self._row = []
        elif tag in ("td", "th"):
            self._cell = []

    def handle_endtag(self, tag):
        if tag == "thead":
            self._in_head = False
        elif tag in ("td", "th") and self._cell is not None:
            text = " ".join("".join(self._cell).split())
            self._row.append(text)
            self._cell = None
        elif tag == "tr" and self._row is not None and self.tables:
            (self.tables[-1]["head"] if self._in_head else self.tables[-1]["rows"]).extend(
                [self._row] if not self._in_head else self._row)
            self._row = None

    def handle_data(self, data):
        if self._cell is not None:
            self._cell.append(data)


def tables(html: str):
    p = Tables()
    p.feed(html)
    return p.tables


def money(text: str) -> int:
    """'€12.50', '−€3.00', '12,50 EUR' -> cents (sign by minus sign or U+2212)."""
    m = re.search(r"([−-]?)\s*€?\s*([0-9]+)[.,]([0-9]{2})", text)
    assert m, f"no amount in {text!r}"
    cents = int(m.group(2)) * 100 + int(m.group(3))
    return -cents if m.group(1) else cents


def abs_and_negative(text: str, badge_words=("More handed over than collected",)) -> tuple[int, bool]:
    return abs(money(text)), any(w in text for w in badge_words)


# ----- main --------------------------------------------------------------------------------------
def main() -> int:
    db_path = sys.argv[1]
    os.environ.setdefault("ENVIRONMENT", "development")
    os.environ.setdefault("PUBLIC_BASE_URL", "http://testserver")
    os.environ.setdefault("SECRET_KEY", "audit-scenario-secret-key-0123456789abcdef-xyz")
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    os.environ.setdefault("ARGON2_TIME_COST", "1")
    os.environ.setdefault("ARGON2_MEMORY_COST_KIB", "8")
    os.environ.setdefault("ARGON2_PARALLELISM", "1")
    os.environ.setdefault("MAIL_BACKEND", "memory")

    raw = Raw(db_path)
    totals = raw.totals()

    from fastapi.testclient import TestClient

    from app.db import read_session, write_session
    from app.main import create_app
    from app.models import AdminUser, User
    from app.services import admin_auth, groups, ledger, overview, sessions
    from app.timeutil import utcnow
    from app.web import tokens

    # 1. services vs raw SQL, every user (merged ones count for their effective user)
    with read_session() as db:
        for uid, u in raw.users.items():
            t = ledger.get_totals(db, uid)
            want = totals[raw.eff(uid)]
            check(f"get_totals({u['display_name']})", (t.consumed_shots, t.consumed_amount_cents, t.paid_amount_cents,
                                                       t.balance_cents),
                  (want["shots"], want["consumed"], want["paid"], want["consumed"] - want["paid"]))
        # 2. groups: collected / remitted / held for every group admin row
        for aid, a in raw.admins.items():
            if a["role"] != "chair":
                continue
            check(f"collected({a['username']})", groups.collected(db, aid), raw.collected(aid))
            check(f"held({a['username']})", groups.held(db, aid), raw.collected(aid) - raw.remitted(aid))
        rows = {r.admin_id: r for r in groups.list_group_balances(db)}
        for aid, a in raw.admins.items():
            if a["role"] != "chair":
                continue
            has_events = raw.collected(aid) != 0 or raw.remitted(aid) != 0 or any(
                p["collector_admin_id"] == aid for p in raw.pe) or any(r["group_admin_id"] == aid for r in raw.rem)
            if a["active"] or has_events:
                check(f"list_group_balances has {a['username']}", aid in rows, True)
                if aid in rows:
                    check(f"list_group_balances held {a['username']}", rows[aid].held_cents,
                          raw.collected(aid) - raw.remitted(aid))
            else:
                check(f"list_group_balances omits idle former {a['username']}", aid in rows, False)
        want_roll = raw.chair_rollup()
        got_roll = {r.chair_id: (r.collected_cents, r.remitted_cents, r.held_cents) for r in groups.chair_rollup(db)}
        check("chair_rollup", got_roll, want_roll)
        # sums: every group admin's held adds up to the roll-up (all collectors with role chair)
        check("sum(held per admin) == sum(held per chair)",
              sum(r.held_cents for r in rows.values()), sum(v[2] for v in want_roll.values()))
        # 3. overview services
        st = overview.site_totals(db)
        non_merged = [uid for uid in raw.users if not raw.users[uid]["merged_into_id"]]
        bal = {uid: totals[uid]["consumed"] - totals[uid]["paid"] for uid in non_merged}
        check("site total shots", st.total_shots, sum(totals[u]["shots"] for u in non_merged))
        check("site consumed", st.consumed_cents, sum(totals[u]["consumed"] for u in non_merged))
        check("site paid", st.paid_cents, sum(totals[u]["paid"] for u in non_merged))
        check("site owed", st.owed_total_cents, sum(b for b in bal.values() if b > 0))
        check("site credit", st.credit_total_cents, sum(-b for b in bal.values() if b < 0))
        chair_over = {c.chair_id: c for c in overview.chairs_overview(db)}
        for cid in raw.chairs:
            members = [u for u in non_merged if raw.users[u]["chair_id"] == cid]
            owed = sum(bal[u] for u in members if bal[u] > 0)
            credit = sum(-bal[u] for u in members if bal[u] < 0)
            visible = [u for u in members if raw.users[u]["status"] == "active" or bal[u] != 0]
            c = chair_over.get(cid)
            if c is None:
                check(f"chair {raw.chairs[cid]['short_name']} listed", bool(members) or cid in want_roll, False)
                continue
            check(f"chairs_overview {c.name}", (c.members, c.owed_cents, c.credit_cents), (len(visible), owed, credit))
            wr = want_roll.get(cid, (0, 0, 0))
            check(f"chairs_overview group money {c.name}", (c.collected_cents, c.handed_over_cents, c.held_cents), wr)

    # 4. HTTP
    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)
    with write_session() as db:
        boss = admin_auth.get_by_username(db, "boss")
        sess, rawtok = admin_auth._new_session(db, boss, now=utcnow())
    client.cookies.set(admin_auth.ADMIN_COOKIE, rawtok, path="/admin")
    r = client.get("/admin/groups")
    check("/admin/groups status", r.status_code, 200)
    tabs = tables(r.text)
    name_of = {}
    for aid, a in raw.admins.items():
        if a["role"] == "chair":
            name_of[raw.users[a["user_id"]]["display_name"]] = aid
    admin_table = next(t for t in tabs if len(t["head"]) == 5 and t["rows"] and len(t["rows"][0]) == 5
                       and t["rows"][0][0].startswith("Member Number"))
    seen_admins = set()
    for row in admin_table["rows"]:
        disp = re.sub(r"\s+(Former group admin|former group admin).*$", "", row[0])
        disp = " ".join(disp.split()[:2])  # "Member NumberN"
        aid = name_of.get(disp)
        if aid is None:
            continue
        seen_admins.add(aid)
        coll, rem = money(row[2]), money(row[3])
        h_abs, h_neg = abs_and_negative(row[4])
        want_h = raw.collected(aid) - raw.remitted(aid)
        check(f"/admin/groups {disp} collected", coll, raw.collected(aid))
        check(f"/admin/groups {disp} handed over", rem, raw.remitted(aid))
        check(f"/admin/groups {disp} held (abs, negative flag)", (h_abs, h_neg), (abs(want_h), want_h < 0))
    must_list = {aid for aid, a in raw.admins.items() if a["role"] == "chair" and (
        a["active"] or any(p["collector_admin_id"] == aid for p in raw.pe) or any(
            r["group_admin_id"] == aid for r in raw.rem))}
    check("/admin/groups lists every group admin that is active or has any collection/remittance event",
          sorted(raw.users[raw.admins[a]["user_id"]]["display_name"] for a in must_list - seen_admins), [])
    roll_table = next(t for t in tabs if len(t["head"]) == 4 and t["rows"] and t["rows"][0][0] in
                      {c["short_name"] for c in raw.chairs.values()})
    short_to_id = {c["short_name"]: cid for cid, c in raw.chairs.items()}
    seen_chairs = {}
    for row in roll_table["rows"]:
        cid = short_to_id[row[0]]
        h_abs, h_neg = abs_and_negative(row[3])
        seen_chairs[cid] = (money(row[1]), money(row[2]), h_abs, h_neg)
    want_chairs = {cid: (v[0], v[1], abs(v[2]), v[2] < 0) for cid, v in want_roll.items()}
    check("/admin/groups roll-up table", seen_chairs, want_chairs)
    held_total = sum(raw.collected(aid) - raw.remitted(aid) for aid, a in raw.admins.items() if a["role"] == "chair")
    check("/admin/groups total held", abs(money(re.search(r"<strong>(.*?)</strong>", r.text).group(1))), abs(held_total))

    # dashboard tile
    r = client.get("/admin")
    check("/admin dashboard status", r.status_code, 200)

    # open site, signed in as an ordinary account
    with write_session() as db:
        member = db.scalars(__import__("sqlalchemy").select(User).where(User.account_kind == "member",
                                                                        User.status == "active")).first()
        tok = sessions.issue_session(db, member.id)
    site = TestClient(app, raise_server_exceptions=False)
    site.cookies.set(sessions.SESSION_COOKIE, tok)
    r = site.get("/overview/chairs")
    check("/overview/chairs status", r.status_code, 200)
    blocks = re.findall(r'<section class="card chair".*?</section>', r.text, flags=re.S)
    site_chairs = {}
    for b in blocks:
        name = re.search(r"<h2[^>]*>(.*?)</h2>", b, re.S).group(1).strip()
        g = lambda cls: re.search(rf'class="chair-{cls}">(.*?)</dd>', b, re.S).group(1)  # noqa: E731
        h_abs, h_neg = abs_and_negative(g("held"))
        site_chairs[name] = {"members": int(g("members")), "owed": money(g("owed")), "credit": money(g("credit")),
                             "collected": money(g("collected")), "handed": money(g("handed")), "held": (h_abs, h_neg)}
    non_merged = [uid for uid in raw.users if not raw.users[uid]["merged_into_id"]]
    bal = {uid: totals[uid]["consumed"] - totals[uid]["paid"] for uid in non_merged}
    for cid, c in raw.chairs.items():
        members = [u for u in non_merged if raw.users[u]["chair_id"] == cid]
        visible = [u for u in members if raw.users[u]["status"] == "active" or bal[u] != 0]
        wr = want_roll.get(cid, (0, 0, 0))
        want = {"members": len(visible), "owed": sum(bal[u] for u in members if bal[u] > 0),
                "credit": sum(-bal[u] for u in members if bal[u] < 0), "collected": wr[0], "handed": wr[1],
                "held": (abs(wr[2]), wr[2] < 0)}
        if c["short_name"] in site_chairs:
            check(f"/overview/chairs {c['short_name']}", site_chairs[c["short_name"]], want)
        else:
            check(f"/overview/chairs lists {c['short_name']}", bool(members) or cid in want_roll, False)
    # the same held numbers on the site and on the admin page
    for cid, v in want_chairs.items():
        check(f"site held == admin held ({raw.chairs[cid]['short_name']})",
              site_chairs[raw.chairs[cid]["short_name"]]["held"], (v[2], v[3]))
    r = site.get("/overview")
    dds = re.findall(r"<dd>(.*?)</dd>", r.text, re.S)
    check("/overview totals", [int(dds[0])] + [money(x) for x in dds[1:5]],
          [sum(totals[u]["shots"] for u in non_merged), sum(totals[u]["consumed"] for u in non_merged),
           sum(totals[u]["paid"] for u in non_merged), sum(b for b in bal.values() if b > 0),
           sum(-b for b in bal.values() if b < 0)])

    # 5. CSV exports (head admin)
    def parse_csv(resp):
        text = resp.content.decode("utf-8-sig")
        return list(csv.reader(io.StringIO(text), delimiter=";"))

    def cents(cell: str) -> int:
        return int(round(float(cell.replace(",", ".")) * 100)) if cell != "" else 0

    r = client.get("/admin/exports/group-balances.csv")
    check("group-balances.csv status", r.status_code, 200)
    rows = parse_csv(r)[1:]
    csv_admin = {row[1]: (cents(row[3]), cents(row[4]), cents(row[5])) for row in rows if row[0] == rows[0][0]
                 and row[2] != "" and row[1] != ""}
    for aid, a in raw.admins.items():
        if a["role"] != "chair":
            continue
        disp = raw.users[a["user_id"]]["display_name"]
        if disp in csv_admin:
            check(f"csv group {disp}", csv_admin[disp], (raw.collected(aid), raw.remitted(aid),
                                                          raw.collected(aid) - raw.remitted(aid)))
    csv_chair = {row[2]: (cents(row[3]), cents(row[4]), cents(row[5])) for row in rows if row[1] == ""}
    check("csv chair roll-up", csv_chair,
          {raw.chairs[cid]["short_name"]: v for cid, v in want_roll.items()})

    r = client.get("/admin/users/export.csv")
    rows = parse_csv(r)[1:]
    by_name = {row[0]: row for row in rows}
    for uid in non_merged:
        u = raw.users[uid]
        row = by_name.get(u["display_name"])
        check(f"users.csv has {u['display_name']}", row is not None, True)
        if row:
            check(f"users.csv {u['display_name']}", (int(row[2]), cents(row[3]), cents(row[4]), cents(row[5])),
                  (totals[uid]["shots"], totals[uid]["consumed"], totals[uid]["paid"],
                   totals[uid]["consumed"] - totals[uid]["paid"]))
    check("users.csv row count", len(rows), len(non_merged))

    r = client.get("/admin/exports/ledger.csv")
    rows = parse_csv(r)[1:]
    check("ledger.csv row count", len(rows), len(raw.ce) + len(raw.pe))
    cons_types = {"single", "double", "adjustment", "reversal"}
    check("ledger.csv consumption amount", sum(cents(x[6]) for x in rows if x[1] in cons_types),
          sum(e["amount_cents"] for e in raw.ce))
    check("ledger.csv payment amount", sum(cents(x[6]) for x in rows if x[1] not in cons_types),
          sum(p["amount_cents"] for p in raw.pe))
    norm = lambda i: str(i).replace("-", "")  # noqa: E731
    check("ledger.csv event ids complete", sorted(norm(x[9]) for x in rows),
          sorted(norm(i) for i in [e["id"] for e in raw.ce] + [p["id"] for p in raw.pe]))

    # 6. a group admin sees and exports only the own chair; the head-only pages refuse
    ga = next(a for a in raw.admins.values() if a["role"] == "chair" and a["active"]
              and raw.users[a["user_id"]]["status"] == "active")
    with write_session() as db:
        gadmin = db.get(AdminUser, ga["id"])
        _s, gtok = admin_auth._new_session(db, gadmin, now=utcnow())
    gclient = TestClient(app, raise_server_exceptions=False)
    gclient.cookies.set(admin_auth.ADMIN_COOKIE, gtok, path="/admin")
    my_chair = raw.users[ga["user_id"]]["chair_id"]
    rows = parse_csv(gclient.get("/admin/users/export.csv"))[1:]
    want_names = {raw.users[u]["display_name"] for u in non_merged if raw.users[u]["chair_id"] == my_chair}
    check("group admin users.csv is own chair only", {r_[0] for r_ in rows}, want_names)
    for path in ("/admin/groups", "/admin/exports/group-balances.csv", "/admin/admins", "/admin/prices",
                 "/admin/audit", "/admin/chairs"):
        check(f"group admin {path} refused", gclient.get(path).status_code, 403)

    print(json.dumps({"checks": CHECKS, "failures": FAILS}, indent=1))
    return 0 if not FAILS else 1


if __name__ == "__main__":
    sys.exit(main())
