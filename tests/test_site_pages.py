"""Task 5.2: person page, chairs page, prices page (HTTP level)."""

from __future__ import annotations

import html as html_lib
import re
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.models import AdminUser, PendingAction
from app.services import groups, ledger, users
from app.timeutil import format_local, local_month_bounds, utcnow
from tests import factories as f
from tests.admin_support import fast_hasher, login_as, make_real_admin, new_client  # noqa: F401

NEW_PATHS = ("/overview/chairs", "/overview/prices", "/overview/people/{pid}")


@pytest.fixture
def old_price(db):
    return f.set_price(db, 50, effective_from=utcnow() - timedelta(days=400))


@pytest.fixture
def viewer(db, chair):
    return f.make_member(db, "Viewer Person", chair, username="viewer")


def text(html: str) -> str:
    return " ".join(html_lib.unescape(re.sub(r"<[^>]+>", " ", html)).split())


def history_rows(html: str, section_id: str) -> list[list[str]]:
    block = html[html.index(f'id="{section_id}"'):]
    block = block[:block.index("</section>")]
    out = []
    for tr in re.findall(r"<tr class=\"kind-[a-z]+\">(.*?)</tr>", block, re.S):
        out.append([text(c) for c in re.findall(r"<t[hd][^>]*>(.*?)</t[hd]>", tr, re.S)])
    return out


def kinds(html: str) -> list[str]:
    return re.findall(r'<tr class="kind-([a-z]+)">', html)


# ----- access --------------------------------------------------------------------------------------------
@pytest.mark.parametrize("path", NEW_PATHS)
def test_anonymous_gets_view_site_pending_and_login_redirect(path, client, db, user):
    r = client.get(path.format(pid=user.id), follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert r.headers["cache-control"] == "private, no-store"
    db.rollback()
    assert [p.kind for p in db.scalars(select(PendingAction))] == ["view_site"]


@pytest.mark.parametrize("path", NEW_PATHS)
def test_signed_in_headers_nav_and_no_script(path, client, db, user, viewer, login, old_price):
    login(viewer)
    r = client.get(path.format(pid=user.id))
    assert r.status_code == 200
    assert r.headers["cache-control"] == "private, no-store"
    html = r.text
    nav = html[html.index('<nav class="site-nav"'):html.index("</nav>")]
    for href in ("/overview", "/overview/people", "/overview/chairs", "/overview/prices", "/account"):
        assert f'<a href="{href}"' in nav
    assert nav.count('aria-current="page"') == 1
    assert "<script" not in html.lower() and "<style" not in html.lower()
    assert not re.search(r"\sstyle\s*=", html, re.I) and not re.search(r"\son[a-z]+\s*=", html, re.I)
    assert "javascript:" not in html.lower()
    csp = r.headers["content-security-policy"]
    assert "unsafe-inline" not in csp
    assert "−" not in html and not re.search(r"-\s*€", html)


def test_nav_current_marks_the_right_item(client, viewer, login, old_price):
    login(viewer)
    for path, label in (("/overview/chairs", "Chairs"), ("/overview/prices", "Prices")):
        html = client.get(path).text
        assert re.search(rf'aria-current="page" class="is-current">{label}</a>', html), path


def test_admin_cookie_alone_is_not_a_site_session(app, db, user):
    admin_id, _ = make_real_admin(username="boss")
    c = new_client(app)
    login_as(c, admin_id)
    r = c.get(f"/overview/people/{user.id}", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


# ----- person page: content --------------------------------------------------------------------------------
def test_person_page_history_and_totals(client, db, viewer, chair, global_admin, login, old_price):
    login(viewer)
    ann = f.make_member(db, "Ann History", chair)
    start = local_month_bounds(utcnow())[0]
    t0 = start + timedelta(days=1, hours=3)
    f.add_events(db, ann, "single", at=t0)
    ev = f.add_events(db, ann, "double", at=t0 + timedelta(minutes=1))[0]
    f.add_events(db, ann, "single", at=t0 + timedelta(minutes=2))
    ledger.admin_reverse_event(db, admin=global_admin, event_id=ev.id, note="oops", now=t0 + timedelta(minutes=3))
    f.make_payment(db, ann, global_admin, 100, at=t0 + timedelta(minutes=4))
    f.make_payment(db, ann, global_admin, -30, at=t0 + timedelta(minutes=5))
    db.commit()
    r = client.get(f"/overview/people/{ann.id}")
    assert r.status_code == 200
    html = r.text
    assert "<h1>Ann History</h1>" in html and "Chair: CHA" in html
    # consumption: newest first; reversal marked, original marked as reversed
    cons = history_rows(html, "cons-h")
    assert [c[4] for c in cons] == ["Reversal", "Coffee", "Reversed", "Coffee"]
    assert cons[0][1:4] == ["2", "€0.50", "€1.00"]  # absolute values, no minus
    assert cons[2][1:4] == ["2", "€0.50", "€1.00"]
    assert cons[3][0] == format_local(t0, "%Y-%m-%d %H:%M")
    # payments: a paid-back entry is worded, not signed
    pays = history_rows(html, "pay-h")
    assert [p[2] for p in pays] == ["Paid back", "Payment"]
    assert [p[1] for p in pays] == ["€0.30", "€1.00"]
    # totals after the reversal: 2 shots (both singles), consumed 1.00, paid 0.70 -> owes 0.30
    summary = text(html[html.index('id="summary-h"'):html.index("</section>", html.index('id="summary-h"'))])
    assert "Owes €0.30" in summary and "Shots this month 2" in summary and "Shots in total 2" in summary


def test_balance_wording_credit_even_and_owes(client, db, viewer, chair, global_admin, login, old_price):
    login(viewer)
    owes = f.make_member(db, "Oscar Owes", chair)
    credit = f.make_member(db, "Cara Credit", chair)
    even = f.make_member(db, "Eve Even", chair)
    f.add_events(db, owes, "double")
    f.make_payment(db, credit, global_admin, 250)
    for person, expected in ((owes, "Owes €1.00"), (credit, "Credit €2.50"), (even, "Even")):
        html = client.get(f"/overview/people/{person.id}").text
        assert f'class="balance balance-' in html
        assert expected in html and "−" not in html and not re.search(r"-\s*€", html)
    assert "No coffee recorded yet." in client.get(f"/overview/people/{even.id}").text
    assert "No payments recorded yet." in client.get(f"/overview/people/{even.id}").text


def test_month_boundary_europe_berlin_on_person_page(client, db, viewer, chair, login, old_price):
    login(viewer)
    assert str(local_month_bounds(utcnow())[0].tzinfo) == "UTC"
    ann = f.make_member(db, "Ann Boundary", chair)
    start = local_month_bounds(utcnow())[0]  # first instant of this month in Berlin (UTC clock: the evening before)
    f.add_events(db, ann, "single", at=start - timedelta(seconds=1))  # still last month
    f.add_events(db, ann, "single", at=start + timedelta(seconds=1))  # Berlin: already this month, UTC: not
    html = client.get(f"/overview/people/{ann.id}").text
    summary = text(html[html.index('id="summary-h"'):])
    assert "Shots this month 1" in summary and "Shots in total 2" in summary
    # the dates in the table are Berlin local time
    assert format_local(start + timedelta(seconds=1), "%Y-%m-%d %H:%M") in html
    assert f'<th scope="row">{format_local(start - timedelta(seconds=1), "%Y-%m-%d %H:%M")}</th>' in html


def test_duplicate_name_suffix_matches_people_list(client, db, viewer, chair, other_chair, login):
    login(viewer)
    f.make_member(db, "Same Name", chair)
    second = f.make_member(db, "Same Name", other_chair)
    assert "<h1>Same Name (2)</h1>" in client.get(f"/overview/people/{second.id}").text


def test_names_are_escaped(client, db, viewer, chair, login):
    login(viewer)
    evil = f.make_member(db, '<img src=x onerror=alert(1)> & "Bob"', chair)
    html = client.get(f"/overview/people/{evil.id}").text
    assert "<img src=x" not in html and "&lt;img src=x" in html


def test_people_list_links_to_person_pages(client, db, viewer, chair, login):
    login(viewer)
    ann = f.make_member(db, "Ann Link", chair)
    html = client.get("/overview/people").text
    href = f'href="/overview/people/{ann.id}"'
    assert href in html
    assert client.get(f"/overview/people/{ann.id}").status_code == 200


# ----- person page: hidden people, 404 --------------------------------------------------------------------
@pytest.mark.parametrize("bad", ["not-a-uuid", "00000000-0000-0000-0000-000000000000", "1" * 300,
                                 "%27%20OR%201=1"])
def test_unknown_or_malformed_id_is_a_plain_404(bad, client, viewer, login):
    login(viewer)
    r = client.get(f"/overview/people/{bad}")
    assert r.status_code == 404
    assert r.headers["cache-control"] == "private, no-store"
    assert "This page does not exist." in r.text and "Traceback" not in r.text
    assert bad not in html_lib.unescape(r.text) or len(bad) < 5


def test_path_traversal_id_is_404(client, viewer, login):
    login(viewer)
    assert client.get("/overview/people/..%2F..%2Fadmin").status_code == 404
    assert client.get("/overview/people/a/b").status_code == 404


def test_inactive_and_merged_rules(client, db, viewer, chair, global_admin, login, old_price):
    login(viewer)
    gone = f.make_user(db, "Gone Zero", chair, status="inactive")  # inactive, balance 0: hidden
    owing = f.make_user(db, "Gone Owing", chair)
    f.add_events(db, owing, "single")
    owing.status = "inactive"
    db.commit()
    assert client.get(f"/overview/people/{gone.id}").status_code == 404
    r = client.get(f"/overview/people/{owing.id}")
    assert r.status_code == 200 and '<span class="badge">inactive</span>' in r.text and "Owes €0.50" in r.text
    f.make_payment(db, owing, global_admin, 50)  # settled: now hidden
    assert client.get(f"/overview/people/{owing.id}").status_code == 404


def test_merged_profile_id_is_404_and_target_counts_both(client, db, viewer, chair, global_admin, login, old_price):
    login(viewer)
    keep = f.make_member(db, "Keep Me", chair)
    dup = f.make_member(db, "Duplicate Me", chair)
    f.add_events(db, keep, "single")
    ev = f.add_events(db, dup, ["single", "double"])[0]
    f.make_payment(db, dup, global_admin, 40)
    users.merge_users(db, admin=global_admin, duplicate_id=dup.id, target_id=keep.id)
    ledger.admin_reverse_event(db, admin=global_admin, event_id=ev.id, note="x")
    db.commit()
    assert client.get(f"/overview/people/{dup.id}").status_code == 404
    html = client.get(f"/overview/people/{keep.id}").text
    assert "Duplicate Me" not in html
    assert kinds(html).count("coffee") + kinds(html).count("reversed") == 3 and kinds(html).count("reversal") == 1
    summary = text(html[html.index('id="summary-h"'):])
    # kept: 1 shot (0.50); duplicate: single reversed, double 1.00; paid 0.40 -> consumed 1.50, owes 1.10
    assert "Shots in total 3" in summary and "Owes €1.10" in summary
    assert "Duplicate Me" not in client.get("/overview/people").text


# ----- person page: Edit balance button ---------------------------------------------------------------------
def make_group_admin(db, chair, name="Gina Group", username="gina"):
    admin = f.make_admin(db, role="chair", chairs=[chair], username=f"adm-{username}")
    admin.user.display_name = name
    admin.user.normalized_name = users.normalize_name(name)
    db.commit()
    return admin


def test_edit_balance_button_only_for_active_group_admin_of_the_same_chair(client, db, chair, other_chair, login,
                                                                          old_price):
    admin = make_group_admin(db, chair)
    mine = f.make_member(db, "Same Chair Person", chair)
    foreign = f.make_member(db, "Other Chair Person", other_chair)
    link = f'href="/admin/users/{mine.id}"'
    login(admin.user)
    html = client.get(f"/overview/people/{mine.id}").text
    assert link in html and ">Edit balance</a>" in html
    assert "Edit balance" not in client.get(f"/overview/people/{foreign.id}").text
    assert "Edit balance" not in client.get(f"/overview/people/{admin.user.id}").text  # not on one's own page
    # a former (inactive) group admin gets no button
    admin_row = db.get(AdminUser, admin.id)
    admin_row.active = False
    db.commit()
    assert "Edit balance" not in client.get(f"/overview/people/{mine.id}").text


def test_edit_balance_button_not_shown_to_members_guests_or_other_roles(client, db, viewer, chair, login, old_price):
    mine = f.make_member(db, "Same Chair Person", chair)
    guest = f.make_guest(db, viewer, "Plain Guest")
    for who in (viewer, guest):
        login(who)
        html = client.get(f"/overview/people/{mine.id}").text
        assert "Edit balance" not in html and "/admin/" not in html
    # a head admin is a CLI account without user session: nothing is linked to a user
    head = f.make_admin(db, role="global")
    assert head.user_id is None


def test_group_admin_of_other_chair_sees_no_button_on_the_page(client, db, chair, other_chair, login):
    admin = make_group_admin(db, other_chair, name="Otto Other", username="otto")
    mine = f.make_member(db, "Same Chair Person", chair)
    login(admin.user)
    assert "Edit balance" not in client.get(f"/overview/people/{mine.id}").text


# ----- chairs page -----------------------------------------------------------------------------------------
def chair_cards(html: str) -> dict[str, dict[str, str]]:
    out = {}
    for card in re.findall(r'<section class="card chair".*?</section>', html, re.S):
        name = text(re.search(r"<h2[^>]*>(.*?)</h2>", card, re.S).group(1))
        cells = {cls: text(val) for cls, val in re.findall(r'<dd class="chair-([a-z]+)">(.*?)</dd>', card, re.S)}
        out[name] = cells
    return out


def money(cents: int) -> str:
    return f"€{abs(cents) // 100}.{abs(cents) % 100:02d}"


@pytest.fixture
def money_world(db, chair, other_chair, global_admin, old_price):
    """Two chairs; group admin Gina (chair A) collects, hands over part; former group admin Fred still holds
    money; chair B has a member with credit and no group admin."""
    gina = make_group_admin(db, chair, "Gina Group", "gina")
    fred = make_group_admin(db, chair, "Fred Former", "fred")
    a1 = f.make_member(db, "Alice A", chair)
    a2 = f.make_member(db, "Alfred A", chair)
    b1 = f.make_member(db, "Berta B", other_chair)
    f.add_events(db, a1, ["double", "double"])  # owes 2.00 less payments
    f.add_events(db, a2, "single")
    ledger.add_payment(db, admin=gina, user_id=a1.id, amount_cents=500)
    ledger.add_payment(db, admin=fred, user_id=a2.id, amount_cents=300)
    f.make_payment(db, b1, global_admin, 700)  # bookkeeping-free cash by a head admin: no group money
    groups.record_remittance(db, head_admin=global_admin, group_admin_id=gina.id, amount_cents=200,
                             idempotency_key="r1")
    fred_row = db.get(AdminUser, fred.id)
    fred_row.active = False  # demoted, still holds 3.00
    db.commit()
    return {"gina": gina, "fred": fred, "a1": a1, "a2": a2, "b1": b1}


def test_chairs_page_content(client, db, viewer, chair, other_chair, money_world, login):
    login(viewer)
    html = client.get("/overview/chairs").text
    cards = chair_cards(html)
    assert set(cards) == {"CHA", "CHB"}
    a, b = cards["CHA"], cards["CHB"]
    assert a["admins"] == "Gina Group"  # current group admins only, by name
    assert "Fred" not in html.split('id="chair-')[1] and "Fred Former" not in a["admins"]
    assert a["members"] == "5"  # Gina, Fred, Alice, Alfred and the viewer
    assert b["admins"] == "None" and b["members"] == "1"
    assert b["credit"] == "€7.00" and b["owed"] == "€0.00"
    assert a["collected"] == "€8.00" and a["handed"] == "€2.00" and a["held"] == "€6.00"
    assert b["collected"] == "€0.00" and b["held"] == "€0.00"
    assert f'href="/overview/people?chair={chair.id}"' in html
    # no admin account names anywhere
    for name in ("adm-gina", "adm-fred", "member-adm-gina", "boss"):
        assert name not in html


def test_chairs_page_matches_rollup_and_admin_groups_page(app, client, db, viewer, chair, other_chair, money_world,
                                                         global_admin, login):
    # one more event after the first rollup: a negative cash entry and a larger remittance than collected
    gina = money_world["gina"]
    ledger.add_payment(db, admin=gina, user_id=money_world["a1"].id, amount_cents=-100)
    groups.record_remittance(db, head_admin=global_admin, group_admin_id=gina.id, amount_cents=900,
                             idempotency_key="r2")
    db.commit()
    login(viewer)
    cards = chair_cards(client.get("/overview/chairs").text)

    # 1. the service rollup
    db.rollback()
    rollup = {r.chair_short_name: r for r in groups.chair_rollup(db)}
    assert set(rollup) == {"CHA"}
    a = cards["CHA"]
    assert a["collected"] == money(rollup["CHA"].collected_cents)
    assert a["handed"] == money(rollup["CHA"].remitted_cents)
    assert a["held"].startswith(money(rollup["CHA"].held_cents))
    assert rollup["CHA"].held_cents < 0 and "More handed over than collected" in a["held"]  # worded, no minus
    # chairs without group money show zeros
    assert cards["CHB"]["collected"] == cards["CHB"]["handed"] == cards["CHB"]["held"] == "€0.00"

    # 2. the admin page for the same data
    admin_id, _ = make_real_admin(username="boss")
    head = new_client(app)
    login_as(head, admin_id)
    admin_html = head.get("/admin/groups").text
    section = admin_html[admin_html.index("<h2>Per ", admin_html.index("<h2>Per group admin") + 10):]
    section = section[:section.index("</section>")]
    admin_rows = {}
    for tr in re.findall(r"<tr>(.*?)</tr>", section, re.S):
        cells = [text(c) for c in re.findall(r"<td[^>]*>(.*?)</td>", tr, re.S)]
        if cells:
            admin_rows[cells[0]] = cells
    assert set(admin_rows) == {"CHA"}
    _, collected, handed, held = admin_rows["CHA"]
    assert (a["collected"], a["handed"]) == (collected, handed)
    assert a["held"] == held


def test_chairs_page_without_group_money_and_empty_admin_list(client, db, viewer, chair, old_price, login):
    login(viewer)
    cards = chair_cards(client.get("/overview/chairs").text)
    assert cards["CHA"]["admins"] == "None" and cards["CHA"]["held"] == "€0.00"


def test_group_admin_names_current_only(client, db, viewer, chair, money_world, login):
    login(viewer)
    admins = chair_cards(client.get("/overview/chairs").text)["CHA"]["admins"]
    assert admins == "Gina Group"
    second = make_group_admin(db, chair, "Anna Another", "anna")
    assert second.active
    assert chair_cards(client.get("/overview/chairs").text)["CHA"]["admins"] == "Anna Another, Gina Group"


def test_chairs_owed_and_credit_match_overview(client, db, viewer, chair, money_world, login):
    login(viewer)
    overview_html = client.get("/overview").text
    cards = chair_cards(client.get("/overview/chairs").text)
    row = re.search(r'<th scope="row"><a href="/overview/people\?chair=%s">CHA</a></th>\s*<td class="num">\d+</td>'
                    r'<td class="num">\d+</td>\s*<td class="num">([^<]*)</td><td class="num">([^<]*)</td>' % chair.id,
                    overview_html)
    assert row and (row.group(1), row.group(2)) == (cards["CHA"]["owed"], cards["CHA"]["credit"])


# ----- prices page -----------------------------------------------------------------------------------------
def test_prices_page_history_order_and_badges(client, db, viewer, global_admin, login):
    now = utcnow()
    f.set_price(db, 40, effective_from=now - timedelta(days=300), admin=global_admin)
    f.set_price(db, 50, effective_from=now - timedelta(days=100), admin=global_admin)
    f.set_price(db, 60, effective_from=now + timedelta(days=10), admin=global_admin)
    login(viewer)
    html = client.get("/overview/prices").text
    rows = [[text(c) for c in re.findall(r"<t[hd][^>]*>(.*?)</t[hd]>", tr, re.S)]
            for tr in re.findall(r"<tr>(.*?)</tr>", html[html.index("<tbody>"):], re.S)]
    assert [r[1] for r in rows] == ["€0.60", "€0.50", "€0.40"]
    assert rows[0][0].endswith("scheduled") and rows[1][0].endswith("current") and "current" not in rows[2][0]
    assert rows[1][0].startswith(format_local(now - timedelta(days=100), "%Y-%m-%d %H:%M"))
    assert global_admin.username not in html


def test_prices_page_empty(client, viewer, login):
    login(viewer)
    assert "No price has been set yet." in client.get("/overview/prices").text
