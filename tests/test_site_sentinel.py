"""Task 5.2, definition of done: privacy sentinel crawl of EVERY /overview* page.

Distinct sentinel values are seeded for everything the open site must never show (e-mail, username, password
hash, session token, audit entry, IP address, payment and consumption notes, collector admin names, recording
admins). The crawl signs in as an ordinary member, starts at /overview, follows every /overview* link it finds
(paginated, sorted and chair-filtered variants and every person page) and asserts that no sentinel appears in any
body or header, including the 404 page.
"""

from __future__ import annotations

import html as html_lib
import re
import uuid
from datetime import timedelta

import pytest

from app.models import AdminUser, AuditLog
from app.services import audit, groups, ledger, sessions, users
from app.timeutil import utcnow
from app.web import routes_overview
from tests import factories as f

HREF_RE = re.compile(r'href="(/overview[^"#]*)"')


def sentinel(name: str) -> str:
    return f"SENTINEL{name.upper()}{uuid.uuid4().hex[:12]}"


@pytest.fixture
def world(db, chair, other_chair):
    """A populated database plus the dict of sentinels and the viewer's raw session token."""
    S = {k: sentinel(k) for k in ("email", "username", "hash", "audit", "ip", "paynote", "consnote", "recnote",
                                  "headadmin", "groupadminuser", "headadminpw", "sponsormail", "viewuser",
                                  "viewmail", "viewhash", "guestuser", "guestmail")}
    now = utcnow()
    f.set_price(db, 50, effective_from=now - timedelta(days=400), admin=None)
    head = f.make_admin(db, role="global", username=S["headadmin"], password_hash=S["headadminpw"])
    f.set_price(db, 60, effective_from=now - timedelta(days=30), admin=head)
    gadmin = f.make_admin(db, role="chair", chairs=[chair], username=S["groupadminuser"])
    gadmin.user.display_name, gadmin.user.normalized_name = "Gabriela Collector", "gabriela collector"
    gadmin.user.username = S["groupadminuser"] + "acct"
    gadmin.user.username_normalized = gadmin.user.username.casefold()
    gadmin.user.email = f"{S['groupadminuser']}@tum.de"
    member = f.make_member(db, "Visible Member", chair, username=S["username"], email=f"{S['email']}@tum.de",
                           password_hash=S["hash"])
    guest = f.make_guest(db, member, "Visible Guest", username=S["guestuser"], password_hash=S["hash"] + "g")
    guest.email = None
    other = f.make_member(db, "Other Member", other_chair, username=S["username"] + "o",
                          email=f"{S['sponsormail']}@tum.de", password_hash=S["hash"] + "o")
    viewer = f.make_member(db, "Viewer Sentinel", chair, username=S["viewuser"], email=f"{S['viewmail']}@tum.de",
                           password_hash=S["viewhash"])
    old_inactive = f.make_member(db, "Left Owing", other_chair, username=S["username"] + "x")
    gone = f.make_member(db, "Left Settled", other_chair, username=S["username"] + "y")
    dup = f.make_member(db, "Merged Duplicate", chair, username=S["username"] + "m")

    t = now - timedelta(minutes=10)
    f.add_events(db, member, ["single", "double"], at=t)
    f.add_events(db, guest, "single", at=t)
    rev = f.add_events(db, other, "single", at=t)[0]
    f.add_events(db, old_inactive, "single", at=t)
    f.add_events(db, dup, "double", at=t)
    ledger.admin_reverse_event(db, admin=head, event_id=rev.id, note=S["consnote"], ip=S["ip"])
    ledger.add_adjustment(db, admin=head, user_id=member.id, quantity=1, note=S["consnote"], ip=S["ip"])
    ledger.add_payment(db, admin=gadmin, user_id=member.id, amount_cents=100, note=S["paynote"], ip=S["ip"])
    ledger.add_payment(db, admin=gadmin, user_id=member.id, amount_cents=-20, note=S["paynote"], ip=S["ip"])
    ledger.add_payment(db, admin=head, user_id=guest.id, amount_cents=25, note=S["paynote"], ip=S["ip"])
    ledger.set_balance(db, admin=head, user_id=other.id, target_balance_cents=-300, idempotency_key="sent-sb",
                       note=S["recnote"])
    ledger.add_adjustment(db, admin=head, user_id=gone.id, quantity=1, amount_cents=50, note=S["consnote"])
    f.make_payment(db, gone, head, 50, note=S["paynote"])  # settled and inactive: hidden
    groups.record_remittance(db, head_admin=head, group_admin_id=gadmin.id, amount_cents=40,
                             idempotency_key="sent-rem", note=S["paynote"])
    users.merge_users(db, admin=head, duplicate_id=dup.id, target_id=member.id, ip=S["ip"])
    old_inactive.status = "inactive"
    gone.status = "inactive"
    audit.log(db, actor_type="admin", actor_id=head.id, action="sentinel.test", target_type="user",
              target_id=member.id, metadata={"detail": S["audit"]}, ip=S["ip"])
    db.commit()
    assert db.query(AuditLog).filter(AuditLog.source_ip == S["ip"]).count() >= 1  # really stored
    return {"S": S, "head": head, "gadmin": gadmin, "member": member, "guest": guest, "other": other,
            "viewer": viewer, "old_inactive": old_inactive, "gone": gone, "dup": dup}


def forbidden_values(world, raw_token: str) -> dict[str, str]:
    S = world["S"]
    values = dict(S)
    values["session_token"] = raw_token
    values["session_token_hash"] = sessions.hash_token(raw_token)
    values["head_admin_name_lower"] = S["headadmin"].lower()
    return values


def assert_clean(response, values: dict[str, str], where: str) -> None:
    blob = response.text + "\n" + "\n".join(f"{k}: {v}" for k, v in response.headers.items())
    unescaped = html_lib.unescape(blob)
    for key, value in values.items():
        assert value not in blob and value not in unescaped, f"{key} leaked on {where}"
    assert "@tum.de" not in blob and "@mytum.de" not in blob, f"e-mail address on {where}"
    assert "−" not in response.text and not re.search(r"-\s*€|>-\d", response.text), f"minus sign on {where}"


def crawl(client, start: str = "/overview") -> dict[str, object]:
    seen: dict[str, object] = {}
    queue = [start]
    while queue:
        url = queue.pop(0)
        if url in seen:
            continue
        r = client.get(url, follow_redirects=False)
        seen[url] = r
        assert r.status_code == 200, (url, r.status_code)
        for href in HREF_RE.findall(r.text):
            queue.append(html_lib.unescape(href))
    return seen


def test_sentinel_crawl_of_every_overview_page(client, db, login, world, chair, other_chair, monkeypatch):
    monkeypatch.setattr(routes_overview, "PAGE_SIZE", 2)  # force paginated variants
    raw = login(world["viewer"])
    values = forbidden_values(world, raw)

    seen = crawl(client)
    # the crawl really covers the whole site
    paths = {u.split("?")[0] for u in seen}
    assert {"/overview", "/overview/people", "/overview/chairs", "/overview/prices"} <= paths
    assert any("page=2" in u for u in seen), "no paginated variant was crawled"
    assert any("sort=balance" in u for u in seen) and any("sort=shots_total" in u for u in seen)
    assert any(f"chair={chair.id}" in u for u in seen) and any(f"chair={other_chair.id}" in u for u in seen)
    # extra variants a browser could produce by submitting the filter form
    extra = ["/overview/people?q=visible", "/overview/people?q=sentinel&sort=balance",
             f"/overview/people?chair={chair.id}&sort=shots_month&page=2", "/overview/people?q=müller&page=3"]
    for url in extra:
        seen[url] = client.get(url)
        assert seen[url].status_code == 200, url
    # every visible person has a page, and all of them were reached by links
    person_urls = {u for u in seen if re.fullmatch(r"/overview/people/[0-9a-f-]{36}", u)}
    visible = {world[k].id for k in ("member", "guest", "other", "viewer", "old_inactive", "gadmin")
               if k != "gadmin"} | {world["gadmin"].user.id}
    assert {u.rsplit("/", 1)[1] for u in person_urls} == {str(i) for i in visible}
    assert len(seen) > 12

    for url, response in seen.items():
        assert response.headers["cache-control"] == "private, no-store", url
        assert_clean(response, values, url)

    # the display name of the collecting group admin is shown as a current group admin, but a person page
    # never says who collected one of its payments
    chairs_html = seen["/overview/chairs"].text
    assert "Gabriela Collector" in chairs_html
    member_page = seen[f"/overview/people/{world['member'].id}"].text
    assert "Gabriela Collector" not in member_page and "Gabriela" not in member_page
    assert world["S"]["headadmin"] not in "".join(r.text for r in seen.values())
    # hidden and merged people were not part of the crawl
    assert f"/overview/people/{world['gone'].id}" not in seen and f"/overview/people/{world['dup'].id}" not in seen
    assert "Left Settled" not in "".join(r.text for r in seen.values())


def test_sentinels_absent_from_404_pages(client, db, login, world):
    raw = login(world["viewer"])
    values = forbidden_values(world, raw)
    urls = ["/overview/people/" + str(uuid.uuid4()), "/overview/people/not-a-uuid",
            f"/overview/people/{world['gone'].id}",  # inactive, settled: hidden
            f"/overview/people/{world['dup'].id}",  # merged
            "/overview/nothing-here", "/overview/people/" + world["S"]["username"]]
    for url in urls:
        r = client.get(url)
        assert r.status_code == 404, url
        assert_clean(r, values, url)
        assert "This page does not exist." in r.text or url.endswith("nothing-here")
    # the 404 for a hidden person is byte-identical to the one for an unknown id except for what the layout adds
    a = client.get(f"/overview/people/{world['gone'].id}").text
    b = client.get(f"/overview/people/{uuid.uuid4()}").text
    assert a == b


def test_anonymous_pages_leak_nothing(client, db, world):
    values = forbidden_values(world, "x" * 43)
    paths = ["/overview", "/overview/people", "/overview/chairs", "/overview/prices",
             f"/overview/people/{world['member'].id}"]
    for path in paths:
        r = client.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/login"
        assert_clean(r, values, path)
    assert "Visible Member" not in client.get("/login").text


def test_group_admin_user_session_sees_the_same_clean_pages(client, db, login, world):
    """Signing in as a group admin adds only the Edit balance link, which carries no secret."""
    raw = login(world["gadmin"].user)
    values = forbidden_values(world, raw)
    page = client.get(f"/overview/people/{world['member'].id}")
    assert 'href="/admin/users/%s"' % world["member"].id in page.text
    assert_clean(page, values, "person page as group admin")
    for url, response in crawl(client).items():
        assert_clean(response, values, url)
    assert db.get(AdminUser, world["gadmin"].id).active
