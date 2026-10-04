"""Task 5.1: open site pages `/overview` and `/overview/people` (HTTP level)."""

from __future__ import annotations

import re
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from app.models import AuditLog, ConsumptionEvent, PaymentEvent, PendingAction
from app.services import audit, groups, ledger
from app.timeutil import local_month_bounds, utcnow
from app.web import routes_overview
from tests import factories as f
from tests.user_support import make_account

SITE_PATHS = ("/overview", "/overview/people")
ROW_RE = re.compile(r'<tr(?: class="is-inactive")?>\s*<th scope="row"><a href="/overview/people/([0-9a-f-]+)">'
                    r'([^<]*)</a>(?: <span class="badge">inactive</span>)?</th>\s*<td>([^<]*)</td>\s*'
                    r'<td class="num">(\d+)</td>\s*<td class="num">(\d+)</td>\s*<td><span class="balance[^"]*">'
                    r'([^<]*)</span></td>')


@pytest.fixture
def old_price(db):
    return f.set_price(db, 50, effective_from=utcnow() - timedelta(days=400))


@pytest.fixture
def viewer(db, chair):
    return make_account(db, "Viewer Person", chair, username="viewer")


def rows(html: str) -> list[dict]:
    return [{"id": m[0], "name": m[1], "chair": m[2], "month": int(m[3]), "total": int(m[4]), "balance": m[5]}
            for m in ROW_RE.findall(html)]


def names(html: str) -> list[str]:
    return [r["name"] for r in rows(html)]


def count(db, model) -> int:
    db.rollback()
    return db.scalar(select(func.count()).select_from(model))


# ----- access -------------------------------------------------------------------------------------
@pytest.mark.parametrize("path", SITE_PATHS)
def test_anonymous_visit_creates_one_view_site_pending_and_redirects_to_login(path, client, db):
    before = {m: count(db, m) for m in (ConsumptionEvent, PaymentEvent)}
    r = client.get(path, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert r.headers["cache-control"] == "private, no-store"
    db.rollback()
    pend = list(db.scalars(select(PendingAction)))
    assert [p.kind for p in pend] == ["view_site"] and pend[0].consumed_at is None
    assert client.cookies.get("coffee_pending") == pend[0].id
    assert "location" in r.headers and "?" not in r.headers["location"]  # no redirect parameter
    assert {m: count(db, m) for m in (ConsumptionEvent, PaymentEvent)} == before
    # A second anonymous visit with the pending cookie does not pile up rows.
    client.get(path, follow_redirects=False)
    assert count(db, PendingAction) == 1


def test_anonymous_visit_keeps_an_existing_pending_coffee(client, db, old_price):
    from tests.user_support import scan

    scan(client, "single")
    db.rollback()
    first = list(db.scalars(select(PendingAction)))
    assert [p.kind for p in first] == ["single"]
    r = client.get("/overview", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert [p.kind for p in db.scalars(select(PendingAction))] == ["single"]
    assert "coffee_pending" not in r.headers.get("set-cookie", "")


def test_anonymous_with_garbage_session_cookie_is_redirected(client, db):
    client.cookies.set("coffee_session", "x" * 40)
    r = client.get("/overview/people", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


@pytest.mark.parametrize("path", SITE_PATHS)
def test_signed_in_access_and_headers(path, client, viewer, login, old_price):
    login(viewer)
    r = client.get(path)
    assert r.status_code == 200
    assert r.headers["cache-control"] == "private, no-store"
    assert "content-security-policy" in r.headers
    assert client.get(path, follow_redirects=False).status_code == 200


def test_revoked_and_deactivated_sessions_are_anonymous(client, db, viewer, login):
    from app.db import write_session
    from app.services import sessions

    login(viewer)
    assert client.get("/overview").status_code == 200
    with write_session() as w:
        sessions.revoke_user_sessions(w, viewer.id)
    r = client.get("/overview", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    login(viewer)
    assert client.get("/overview/people").status_code == 200
    viewer.status = "inactive"
    db.commit()
    assert client.get("/overview/people", follow_redirects=False).status_code == 303


def test_route_enumeration_all_site_routes_are_get_only_and_gated(client, db):
    routes = [r for r in routes_overview.router.routes]
    assert {r.path for r in routes} == {"/overview", "/overview/people"}
    for r in routes:
        assert r.methods == {"GET"}, r.path  # nothing here changes state
        resp = client.get(r.path, follow_redirects=False)
        assert resp.status_code == 303 and resp.headers["location"] == "/login", r.path
        assert client.post(r.path, follow_redirects=False).status_code == 405


def test_routes_are_mounted_in_the_app(client):
    assert client.get("/overview", follow_redirects=False).status_code == 303
    assert client.get("/overview/people", follow_redirects=False).status_code == 303


# ----- no sensitive field ever leaves (HTTP level) ----------------------------------------------------
def test_sentinels_never_appear_in_any_response(client, db, chair, other_chair, global_admin, login, old_price):
    keys = ("email", "username", "hash", "paynote", "consnote", "audit", "ip", "adminname", "viewuser", "viewmail")
    S = {k: f"SENTINEL-{k}-{uuid.uuid4().hex[:10]}" for k in keys}
    gadmin = f.make_admin(db, role="chair", chairs=[chair], username=S["adminname"])
    member = f.make_member(db, "Visible Member", chair, username=S["username"], email=f"{S['email']}@tum.de",
                           password_hash=S["hash"])
    guest = f.make_guest(db, member, "Visible Guest", username=S["username"] + "g", password_hash=S["hash"] + "g")
    other = f.make_member(db, "Other Member", other_chair)
    viewer = f.make_member(db, "Viewer Sentinel", chair, username=S["viewuser"], email=f"{S['viewmail']}@tum.de",
                           password_hash=S["hash"] + "v")
    now = utcnow()
    f.add_events(db, member, ["single", "double"], at=now - timedelta(minutes=5))
    f.add_events(db, guest, "single", at=now - timedelta(minutes=5))
    rev = f.add_events(db, other, "single", at=now - timedelta(minutes=5))[0]
    ledger.admin_reverse_event(db, admin=global_admin, event_id=rev.id, note=S["consnote"], ip=S["ip"])
    ledger.add_adjustment(db, admin=global_admin, user_id=member.id, quantity=1, note=S["consnote"], ip=S["ip"])
    f.make_payment(db, member, gadmin, 100, note=S["paynote"])
    f.make_payment(db, guest, global_admin, 25, note=S["paynote"])
    groups.record_remittance(db, head_admin=global_admin, group_admin_id=gadmin.id, amount_cents=40,
                             idempotency_key="sent-1", note=S["paynote"])
    audit.log(db, actor_type="admin", actor_id=global_admin.id, action="sentinel.test", target_type="user",
              target_id=member.id, metadata={"detail": S["audit"]}, ip=S["ip"])
    db.commit()
    assert db.query(AuditLog).filter(AuditLog.source_ip == S["ip"]).count() >= 1  # really stored

    login(viewer)
    urls = ["/overview", "/overview/people", "/overview/people?q=visible", "/overview/people?sort=balance",
            f"/overview/people?chair={chair.id}&sort=shots_total", "/overview/people?q=sentinel",
            f"/overview/people?q={S['username']}", "/overview/people?page=9&sort=shots_month"]
    seen_visible = False
    for url in urls:
        r = client.get(url)
        assert r.status_code == 200, url
        blob = r.text + repr(sorted(r.headers.items())) + repr(client.cookies.jar)
        for key, sentinel in S.items():
            if key == "username" and "q=" in url and S["username"] in url:
                blob = blob.replace(url, "")  # the searched text is echoed back into the box, by design
                blob = blob.replace(f'value="{S["username"]}"', "")
            assert sentinel not in blob, (key, url)
        assert "@tum.de" not in r.text, url
        seen_visible |= "Visible Member" in r.text
    assert seen_visible
    # the viewer's own e-mail and username are not shown either
    assert S["viewuser"] not in client.get("/overview/people?q=viewer").text


# ----- /overview content ---------------------------------------------------------------------------
def test_overview_numbers_trend_and_chairs(client, db, viewer, chair, other_chair, global_admin, login, old_price):
    login(viewer)
    alice = f.make_member(db, "Alice", chair)
    bob = f.make_member(db, "Bob", other_chair)
    month_start = local_month_bounds(utcnow())[0]
    f.add_events(db, alice, ["single", "double"], at=month_start + timedelta(seconds=5))  # 3 shots, 1.50
    f.add_events(db, bob, "single", at=month_start - timedelta(seconds=1))  # previous month, 0.50
    f.make_payment(db, alice, global_admin, 100, at=month_start + timedelta(seconds=10))
    f.make_payment(db, bob, global_admin, 150, at=month_start + timedelta(seconds=10))
    r = client.get("/overview")
    html = r.text
    for text in ("<dt>Shots in total</dt><dd>4</dd>", "<dt>Amount consumed</dt><dd>€2.00</dd>",
                 "<dt>Amount paid</dt><dd>€2.50</dd>", "<dt>Still owed by people</dt><dd>€0.50</dd>",
                 "<dt>Credit held by people</dt><dd>€1.00</dd>", "<dt>Current price per shot</dt><dd>€0.50</dd>",
                 "<dt>Shots this month</dt><dd>3</dd>", "<dt>Amount this month</dt><dd>€1.50</dd>"):
        assert text in html, text
    # trend: 12 months, an accessible table and an inline SVG with plain attributes
    assert html.count('class="trend-bar') == 12
    table = html[html.index('<details class="trend-table"'):html.index("</details>")]
    assert len(re.findall(r"<tr><th scope=\"row\">\d{4}-\d{2}</th>", table)) == 12
    assert 'role="img"' in html and "<title>" in html
    # per-chair summary with links to the people filter
    assert f'href="/overview/people?chair={chair.id}"' in html and f'href="/overview/people?chair={other_chair.id}"' in html
    chair_block = html[html.index('id="chairs-h"'):]
    assert chair.short_name in chair_block and other_chair.short_name in chair_block
    assert "−" not in html and not re.search(r"-\s*€", html)


def test_overview_trend_boundary_current_month_and_previous(client, db, viewer, chair, login, old_price):
    login(viewer)
    alice = f.make_member(db, "Alice", chair)
    start = local_month_bounds(utcnow())[0]
    f.add_events(db, alice, "single", at=start - timedelta(seconds=1))
    f.add_events(db, alice, ["single", "single"], at=start)
    html = client.get("/overview").text
    months = re.findall(r'<tr><th scope="row">(\d{4}-\d{2})</th><td class="num">(\d+)</td>', html)
    assert len(months) == 12
    assert [m[1] for m in months[-2:]] == ["1", "2"]
    assert months[-1][0] > months[-2][0]
    assert "<dt>Shots this month</dt><dd>2</dd>" in html


def test_overview_without_price_or_data(client, db, viewer, login):
    login(viewer)
    html = client.get("/overview").text
    assert "Not set" in html and "<dt>Shots in total</dt><dd>0</dd>" in html


def test_negative_month_figures_never_show_a_minus_sign(client, db, viewer, chair, global_admin, login, old_price):
    """A reversal booked this month for last month's coffee makes the month's shots negative in the service."""
    login(viewer)
    alice = f.make_member(db, "Alice", chair)
    start = local_month_bounds(utcnow())[0]
    ev = f.add_events(db, alice, "double", at=start - timedelta(days=2))[0]
    ledger.admin_reverse_event(db, admin=global_admin, event_id=ev.id, note="x", now=start + timedelta(minutes=1))
    db.commit()
    for path in SITE_PATHS:
        html = client.get(path).text
        assert "−" not in html and not re.search(r"-\s*€|>-\d", html), path
    assert "<dt>Shots this month</dt><dd>0</dd>" in client.get("/overview").text


# ----- /overview/people -----------------------------------------------------------------------------
@pytest.fixture
def people(db, chair, other_chair, global_admin, old_price):
    """Alice (owes 1.50, 3 shots), Bob (credit 2.00), Cleo (even), Müller (other chair, owes 0.50)."""
    start = local_month_bounds(utcnow())[0]
    d = {}
    d["alice"] = f.make_member(db, "Alice", chair)
    d["bob"] = f.make_member(db, "Bob", chair)
    d["cleo"] = f.make_member(db, "Cleo", chair)
    d["mueller"] = f.make_member(db, "Jürgen Müller", other_chair)
    f.add_events(db, d["alice"], ["single", "double"], at=start + timedelta(seconds=1))
    f.add_events(db, d["mueller"], "single", at=start - timedelta(days=5))
    f.make_payment(db, d["bob"], global_admin, 200)
    return d


def test_people_listing_wording_and_links(client, viewer, people, login):
    login(viewer)
    html = client.get("/overview/people").text
    got = {r["name"]: r for r in rows(html)}
    assert set(got) == {"Alice", "Bob", "Cleo", "Jürgen Müller", "Viewer Person"}
    assert got["Alice"]["balance"] == "Owes €1.50" and got["Alice"]["month"] == 3 and got["Alice"]["total"] == 3
    assert got["Bob"]["balance"] == "Credit €2.00"
    assert got["Cleo"]["balance"] == "Even"
    assert got["Jürgen Müller"]["month"] == 0 and got["Jürgen Müller"]["total"] == 1
    assert got["Jürgen Müller"]["balance"] == "Owes €0.50"
    assert f'href="/overview/people/{people["alice"].id}"' in html
    assert "−" not in html and "Owes -" not in html and not re.search(r"-\s*€", html)
    for r in got.values():
        assert "-" not in r["balance"]
    assert "5 people" in html


@pytest.mark.parametrize("term", ["muller", "mueller", "MÜLLER", "müller", "jurgen", "  Müller  ", "ller"])
def test_search_with_umlauts(term, client, viewer, people, login):
    login(viewer)
    html = client.get("/overview/people", params={"q": term}).text
    assert names(html) == ["Jürgen Müller"], term
    assert "1 person" in html


def test_search_no_match_and_escaped_echo(client, viewer, people, login):
    login(viewer)
    html = client.get("/overview/people", params={"q": '"><script>alert(1)</script>'}).text
    assert "Nobody matches" in html and names(html) == []
    assert "<script>" not in html and "&lt;script&gt;" in html


def test_search_term_is_length_limited(client, viewer, people, login):
    login(viewer)
    r = client.get("/overview/people", params={"q": "a" * 5000})
    assert r.status_code == 200
    echoed = re.search(r'name="q" value="([^"]*)"', r.text).group(1)
    assert len(echoed) == routes_overview.Q_MAX
    r = client.get("/overview/people", params={"q": "Alice" + " " * 3000})
    assert names(r.text) == ["Alice"]
    assert client.get("/overview/people", params={"q": "%", "sort": "name"}).status_code == 200  # LIKE wildcard is literal
    assert names(client.get("/overview/people", params={"q": "%"}).text) == []
    assert client.get("/overview/people?q=a%00b").status_code == 200


def test_sorting(client, viewer, people, login):
    login(viewer)
    by = lambda s: names(client.get("/overview/people", params={"sort": s}).text)  # noqa: E731
    assert by("name") == ["Alice", "Bob", "Cleo", "Jürgen Müller", "Viewer Person"]
    assert by("balance")[:2] == ["Alice", "Jürgen Müller"] and by("balance")[-1] == "Bob"
    assert by("shots_month")[0] == "Alice"
    assert by("shots_total")[:2] == ["Alice", "Jürgen Müller"]
    for bad in ("", "bogus", "name; DROP TABLE users", "BALANCE", "balance,name", "x" * 300):
        assert by(bad) == by("name"), bad
    html = client.get("/overview/people", params={"sort": "balance"}).text
    assert re.search(r'<option value="balance" selected>', html)
    assert 'aria-sort="descending"' in html


def test_chair_filter_and_bad_values(client, viewer, people, chair, other_chair, login):
    login(viewer)
    html = client.get("/overview/people", params={"chair": str(other_chair.id)}).text
    assert names(html) == ["Jürgen Müller"] and rows(html)[0]["chair"] == other_chair.short_name
    assert f'<option value="{other_chair.id}" selected>' in html
    html = client.get("/overview/people", params={"chair": str(chair.id)}).text
    assert set(names(html)) == {"Alice", "Bob", "Cleo", "Viewer Person"}
    # combined with a search and a sort
    html = client.get("/overview/people", params={"chair": str(chair.id), "q": "ali", "sort": "balance"}).text
    assert names(html) == ["Alice"]
    # not a UUID: ignored; unknown UUID: ignored (all chairs)
    for bad in ("zzz", "' OR 1=1 --", str(uuid.uuid4()), "1" * 400):
        assert len(names(client.get("/overview/people", params={"chair": bad}).text)) == 5, bad


def test_month_boundary_through_the_page(client, db, viewer, chair, login, old_price):
    login(viewer)
    ann = f.make_member(db, "Ann Boundary", chair)
    start = local_month_bounds(utcnow())[0]
    f.add_events(db, ann, "single", at=start - timedelta(seconds=1))  # last local month
    f.add_events(db, ann, "single", at=start)  # first instant of this month
    row = {r["name"]: r for r in rows(client.get("/overview/people").text)}["Ann Boundary"]
    assert (row["month"], row["total"]) == (1, 2)
    f.add_events(db, ann, "single", at=start - timedelta(seconds=30))
    row = {r["name"]: r for r in rows(client.get("/overview/people").text)}["Ann Boundary"]
    assert (row["month"], row["total"]) == (1, 3)


def test_inactive_hidden_unless_balance(client, db, viewer, chair, global_admin, login, old_price):
    login(viewer)
    hidden = f.make_user(db, "Hidden Gone", chair, status="inactive")
    owing = f.make_user(db, "Owing Gone", chair)
    f.add_events(db, owing, "single")
    owing.status = "inactive"
    db.commit()
    html = client.get("/overview/people").text
    assert "Hidden Gone" not in html
    got = {r["name"]: r for r in rows(html)}
    assert got["Owing Gone"]["balance"] == "Owes €0.50"
    assert re.search(r'<tr class="is-inactive">\s*<th scope="row"><a href="/overview/people/[^"]+">Owing Gone</a> '
                     r'<span class="badge">inactive</span>', html)
    f.make_payment(db, owing, global_admin, 50)  # settled: disappears
    assert "Owing Gone" not in client.get("/overview/people").text
    assert hidden.id  # exists but not listed


def test_duplicate_names_get_a_suffix(client, db, viewer, chair, other_chair, login):
    login(viewer)
    f.make_member(db, "Same Name", chair)
    f.make_member(db, "Same Name", other_chair)
    html = client.get("/overview/people").text
    assert [n for n in names(html) if n.startswith("Same Name")] == ["Same Name", "Same Name (2)"]
    assert names(client.get("/overview/people", params={"chair": str(other_chair.id)}).text) == ["Same Name (2)"]


def test_pagination_and_clamping(client, db, viewer, chair, login, monkeypatch):
    login(viewer)
    monkeypatch.setattr(routes_overview, "PAGE_SIZE", 2)
    for n in "ABCD":
        f.make_member(db, f"Person {n}", chair)  # 4 + the viewer = 5 people, 3 pages
    page = lambda p, **kw: client.get("/overview/people", params={"page": p, **kw}).text  # noqa: E731
    p1, p2, p3 = page(1), page(2), page(3)
    assert names(p1) == ["Person A", "Person B"] and names(p2) == ["Person C", "Person D"]
    assert names(p3) == ["Viewer Person"]
    assert "Page 1 of 3" in p1 and 'rel="prev"' not in p1 and 'rel="next" href="/overview/people?page=2"' in p1
    assert 'rel="prev" href="/overview/people"' in p2 and 'rel="next" href="/overview/people?page=3"' in p2
    assert 'rel="next"' not in p3
    for bad, expected in (("999", p3), ("0", p1), ("-4", p1), ("abc", p1), ("", p1), ("1.5", p1), ("9" * 50, p1),
                          ("٣", p1)):
        r = client.get("/overview/people", params={"page": bad})
        assert r.status_code == 200 and names(r.text) == names(expected), repr(bad)
    # filters and sort survive in the links
    html = page(1, sort="balance", q="person")
    assert "q=person" in html and "sort=balance" in html
    link = re.search(r'rel="next" href="([^"]+)"', html).group(1).replace("&amp;", "&")
    assert "page=2" in link and "q=person" in link and "sort=balance" in link
    assert names(client.get(link).text) == ["Person C", "Person D"]
    assert "Page 1" not in client.get("/overview/people", params={"q": "viewer"}).text  # single page: no pager


def test_html_escaping_of_names(client, db, viewer, chair, login):
    login(viewer)
    f.make_member(db, '<img src=x onerror=alert(1)> & "Bob"', chair)
    html = client.get("/overview/people").text
    assert "<img src=x" not in html and "&lt;img src=x" in html


# ----- page structure: navigation, no JS, strict CSP ----------------------------------------------------
@pytest.mark.parametrize("path", SITE_PATHS)
def test_navigation_bar(path, client, viewer, login, old_price):
    login(viewer)
    html = client.get(path).text
    nav = html[html.index('<nav class="site-nav"'):html.index("</nav>")]
    for label, href in (("Overview", "/overview"), ("People", "/overview/people"), ("Chairs", "/overview/chairs"),
                        ("Prices", "/overview/prices"), ("My account", "/account")):
        assert f'<a href="{href}"' in nav and f">{label}</a>" in nav
    current = "People" if path.endswith("people") else "Overview"
    assert re.search(rf'aria-current="page" class="is-current">{current}</a>', nav)
    assert nav.count('aria-current="page"') == 1


@pytest.mark.parametrize("path", ["/overview", "/overview/people", "/overview/people?q=a&sort=balance&page=2"])
def test_no_javascript_and_csp_compliance(path, client, viewer, people, login):
    login(viewer)
    r = client.get(path)
    html = r.text
    assert "<script" not in html.lower()
    assert not re.search(r"\sstyle\s*=", html, re.I)
    assert not re.search(r"\son[a-z]+\s*=", html, re.I)
    assert "javascript:" not in html.lower() and "<style" not in html.lower()
    assert re.search(r'href="/static/site\.css"', html)
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "style-src 'self'" in csp and "unsafe-inline" not in csp
    # Everything that loads is local.
    assert not re.search(r'(?:src|href)="https?://', html)
    # filter form works with a plain GET
    if path == "/overview/people":
        assert '<form class="card people-filter" method="get" action="/overview/people">' in html
        assert '<button type="submit">' in html


def test_site_css_is_served_and_has_no_remote_imports(client):
    r = client.get("/static/site.css")
    assert r.status_code == 200 and "@import" not in r.text and "url(http" not in r.text
