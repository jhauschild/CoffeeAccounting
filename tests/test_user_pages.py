"""Task 3.2: scan result page and account page (headline in words, month shots, change password, group admin)."""

from __future__ import annotations

import re
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.db import write_session
from app.models import AdminSession, AdminUser, AuditLog, ConsumptionEvent, RateLimitEvent, User, UserSession
from app.services import admin_auth, ledger, passwords, sessions
from app.timeutil import local_month_bounds, utcnow
from tests import factories
from tests.test_user_account import _csrf_for, _undo
from tests.user_support import PASSWORD, event_id_from, field, make_account, scan

NEW_PASSWORD = "another horse battery staple"


def headline_text(html: str) -> str:
    m = re.search(r'<p class="headline headline-(?:owes|credit|even)" role="status">([^<]*)</p>', html)
    assert m, "headline not found"
    return m.group(1)


def month_shots_of(html: str) -> int:
    m = re.search(r"Shots this month</dt><dd>(-?\d+)</dd>", html)
    assert m, "month shots not found"
    return int(m.group(1))


@pytest.fixture
def member(db, chair):
    return make_account(db, "Alice Example", chair, username="alice")


@pytest.fixture
def old_price(db):
    return factories.set_price(db, 50, effective_from=utcnow() - timedelta(days=400))


def _change(client, current=PASSWORD, new=NEW_PASSWORD, new2=None, csrf=None):
    page = client.get("/account")
    data = {"csrf_token": field(page.text, "csrf_token") if csrf is None else csrf, "current_password": current,
            "password": new, "password2": new if new2 is None else new2}
    return client.post("/account/password", data=data, follow_redirects=False)


# ----- headline wording -----------------------------------------------------------------------
@pytest.mark.parametrize("path", ["done", "/account"])
def test_headline_for_owed_credit_and_settled(path, client, db, member, global_admin, price, login):
    login(member)
    event = event_id_from(scan(client, "double"))  # 2 shots * 0.50 = 1.00 owed
    url = f"/coffee/done/{event}" if path == "done" else path
    assert headline_text(client.get(url).text) == "Outstanding: €1.00"
    ledger.add_payment(db, admin=global_admin, user_id=member.id, amount_cents=100)
    db.commit()
    assert headline_text(client.get(url).text) == "All settled"
    ledger.add_payment(db, admin=global_admin, user_id=member.id, amount_cents=250)
    db.commit()
    page = client.get(url).text
    assert headline_text(page) == "Credit: €2.50"
    assert 'headline-credit' in page


def test_no_minus_sign_in_owed_or_credit_text(client, db, member, global_admin, price, login):
    login(member)
    event = event_id_from(scan(client))
    for cents in (0, 1000):  # owing, then in credit
        if cents:
            ledger.add_payment(db, admin=global_admin, user_id=member.id, amount_cents=cents)
            db.commit()
        for url in (f"/coffee/done/{event}", "/account"):
            text = headline_text(client.get(url).text)
            assert "-" not in text and "−" not in text and "–" not in text, text
    # Paid-back money and balance corrections are described in words, with no sign.
    ledger.add_payment(db, admin=global_admin, user_id=member.id, amount_cents=-300)
    ledger.set_balance(db, admin=global_admin, user_id=member.id, target_balance_cents=-700, idempotency_key="sb1")
    db.commit()
    page = client.get("/account").text
    payments = page[page.index("Recent payments"):page.index("Change password")]
    assert "−" not in payments and "-€" not in payments
    assert "Paid back to you" in payments and "Balance correction" in payments


def test_done_page_keeps_recorded_details_undo_and_links(client, db, member, price, login):
    raw = login(member)
    event = event_id_from(scan(client, "double"))
    page = client.get(f"/coffee/done/{event}").text
    for expected in ("Double recorded", "€0.50", "€1.00", "Undo this coffee", 'href="/account"', 'href="/overview"'):
        assert expected in page
    assert re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", page)
    _undo(client, event, _csrf_for(client, raw))
    page = client.get(f"/coffee/done/{event}").text
    assert "Undo this coffee" not in page and "All settled" in page


def test_event_of_another_user_is_not_viewable(client, db, member, chair, price, login):
    login(member)
    event = event_id_from(scan(client))
    other = make_account(db, "Bob Other", chair, username="bob")
    login(other)
    assert client.get(f"/coffee/done/{event}").status_code == 404
    assert client.get("/coffee/done/not-a-uuid").status_code == 404
    client.cookies.clear()
    assert client.get(f"/coffee/done/{event}", follow_redirects=False).headers["location"] == "/login"


# ----- month shots ----------------------------------------------------------------------------
def test_month_shots_net_of_a_reversal(client, db, member, price, login):
    raw = login(member)
    first = event_id_from(scan(client, "double"))
    assert month_shots_of(client.get(f"/coffee/done/{first}").text) == 2
    second = event_id_from(scan(client, "single"))
    assert month_shots_of(client.get(f"/coffee/done/{second}").text) == 3
    _undo(client, second, _csrf_for(client, raw))
    assert month_shots_of(client.get(f"/coffee/done/{second}").text) == 2
    assert month_shots_of(client.get("/account").text) == 2


def test_month_shots_boundary_counts_only_this_local_month(client, db, member, old_price, login):
    start, _end = local_month_bounds(utcnow())
    factories.add_events(db, member, ["double"], at=start - timedelta(seconds=1))  # last month: not counted
    factories.add_events(db, member, ["single"], at=start)  # first instant of this month: counted
    login(member)
    page = client.get("/account").text
    assert month_shots_of(page) == 1
    assert "Shots consumed" in page and re.search(r"Shots consumed</dt><dd>3</dd>", page)


def test_month_shots_never_shown_negative(client, db, member, global_admin, old_price, login):
    start, _end = local_month_bounds(utcnow())
    (old,) = factories.add_events(db, member, ["double"], at=start - timedelta(hours=1))
    ledger.admin_reverse_event(db, admin=global_admin, event_id=old.id)
    db.commit()
    assert ledger.get_month_shots(db, member.id) == -2  # the reversal lands in this month
    login(member)
    assert month_shots_of(client.get("/account").text) == 0


# ----- account page ---------------------------------------------------------------------------
def test_account_page_profile_and_privacy_line(client, db, member, price, login):
    login(member)
    page = client.get("/account").text
    assert "Alice Example" in page and "CHA" in page
    assert "alice" in page and member.email in page  # the owner sees username and e-mail
    assert "visible to every signed-in account" in page
    assert 'href="/overview"' in page and 'action="/account/password"' in page and 'action="/logout"' in page
    assert "Remove this browser" in page and 'href="/account/edit"' in page


def test_username_and_email_are_not_shown_to_other_accounts(client, db, member, chair, price, login):
    other = make_account(db, "Bob Other", chair, username="bob")
    login(other)
    page = client.get("/account").text
    assert member.email not in page and "alice" not in page.lower().replace("alice example", "")


def test_remove_this_browser_revokes_only_this_session(client, db, member, login):
    raw = login(member)
    elsewhere = factories.make_session(db, member, raw_token="x" * 43)
    r = client.post("/logout", data={"csrf_token": _csrf_for(client, raw)}, follow_redirects=False)
    assert r.status_code == 303
    db.rollback()
    assert sessions.resolve_session(db, raw, touch=False) is None
    assert sessions.resolve_session(db, "x" * 43, touch=False) is not None
    assert elsewhere.revoked_at is None


# ----- change password ------------------------------------------------------------------------
def test_password_change_revokes_other_sessions_and_keeps_this_one(client, db, member, login):
    raw = login(member)
    factories.make_session(db, member, raw_token="o" * 43)
    r = _change(client)
    assert r.status_code == 303 and r.headers["location"] == "/account?notice=password"
    db.rollback()
    assert sessions.resolve_session(db, raw, touch=False) is not None
    assert sessions.resolve_session(db, "o" * 43, touch=False) is None
    db.refresh(member)
    assert passwords.verify_password(member.password_hash, NEW_PASSWORD)
    assert not passwords.verify_password(member.password_hash, PASSWORD)
    assert "Your password has been changed" in client.get("/account?notice=password").text
    (entry,) = db.scalars(select(AuditLog).where(AuditLog.action == "password.changed")).all()
    assert entry.actor_id == str(member.id) and entry.meta["sessions_revoked"] == 1
    assert NEW_PASSWORD not in repr(entry.meta) and PASSWORD not in repr(entry.meta)
    # The new password signs in, the old one does not.
    other = type(client)(client.app)
    page = other.get("/login")
    data = {"csrf_token": field(page.text, "csrf_token"), "username": "alice"}
    assert other.post("/login", data={**data, "password": NEW_PASSWORD}, follow_redirects=False).status_code == 303
    third = type(client)(client.app)
    page = third.get("/login")
    data = {"csrf_token": field(page.text, "csrf_token"), "username": "alice", "password": PASSWORD}
    assert third.post("/login", data=data, follow_redirects=False).status_code == 401


def test_password_change_revokes_linked_admin_sessions(client, db, chair, login):
    ga = factories.make_admin(db, role="chair", chairs=[chair], username="ga")
    user = ga.user
    user.password_hash = passwords.hash_password(PASSWORD)
    other_admin = factories.make_admin(db, role="global", username="rootadmin")
    with write_session() as w:
        mine, _ = admin_auth._new_session(w, w.get(AdminUser, ga.id), now=utcnow())
        mine2, _ = admin_auth._new_session(w, w.get(AdminUser, ga.id), now=utcnow())
        unrelated, _ = admin_auth._new_session(w, w.get(AdminUser, other_admin.id), now=utcnow())
        ids = (mine.id, mine2.id, unrelated.id)
    login(user)
    assert _change(client).status_code == 303
    db.rollback()
    revoked = {i: db.get(AdminSession, i).revoked_at is not None for i in ids}
    assert revoked == {ids[0]: True, ids[1]: True, ids[2]: False}
    (entry,) = db.scalars(select(AuditLog).where(AuditLog.action == "password.changed")).all()
    assert entry.meta["admin_sessions_revoked"] == 2


def test_wrong_current_password_is_refused_and_changes_nothing(client, db, member, login):
    raw = login(member)
    other_session = factories.make_session(db, member, raw_token="o" * 43)
    before = member.password_hash
    r = _change(client, current="not my password at all")
    assert r.status_code == 400 and "current password is not correct" in r.text
    db.rollback()
    db.refresh(member)
    assert member.password_hash == before
    assert sessions.resolve_session(db, "o" * 43, touch=False) is not None
    assert sessions.resolve_session(db, raw, touch=False) is not None
    assert not db.scalars(select(AuditLog).where(AuditLog.action == "password.changed")).all()
    assert db.query(RateLimitEvent).filter_by(bucket="pw_change").count() == 1  # the failure is recorded
    assert other_session.revoked_at is None


def test_current_password_guessing_is_rate_limited(client, db, member, login):
    login(member)
    for _ in range(5):
        assert _change(client, current="wrong password here").status_code == 400
    r = _change(client)  # even the right password is refused once the cap is reached
    assert r.status_code == 429
    db.rollback()
    db.refresh(member)
    assert passwords.verify_password(member.password_hash, PASSWORD)


@pytest.mark.parametrize("new,reason", [
    ("short", "too short"),
    ("alice", "too short"),
    ("a" * 9, "too short"),
    ("x" * 129, "too long"),
])
def test_password_policy_is_enforced(new, reason, client, db, member, login):
    login(member)
    r = _change(client, new=new)
    assert r.status_code == 400 and reason in r.text
    db.rollback()
    db.refresh(member)
    assert passwords.verify_password(member.password_hash, PASSWORD)


def test_password_may_not_equal_username_or_email_local_part(client, db, chair, login):
    user = make_account(db, "Long Name", chair, username="longusername1")
    login(user)
    r = _change(client, new="longusername1")
    assert r.status_code == 400 and "same as the username" in r.text
    user.email = "different.local.part@tum.de"
    db.commit()
    r = _change(client, new="different.local.part")
    assert r.status_code == 400 and "same as your e-mail" in r.text


def test_password_mismatch_and_csrf(client, db, member, login):
    login(member)
    r = _change(client, new2="something else entirely")
    assert r.status_code == 400 and "not the same" in r.text
    assert _change(client, csrf="forged").status_code == 403
    db.rollback()
    db.refresh(member)
    assert passwords.verify_password(member.password_hash, PASSWORD)


def test_password_change_requires_a_session(client, db, member):
    r = client.post("/account/password", data={"current_password": PASSWORD, "password": NEW_PASSWORD,
                                               "password2": NEW_PASSWORD}, follow_redirects=False)
    assert r.status_code in (303, 403)
    db.rollback()
    db.refresh(member)
    assert passwords.verify_password(member.password_hash, PASSWORD)


# ----- edit display name and chair ------------------------------------------------------------
def test_group_admin_is_not_offered_the_chair_field(client, db, chair, price, login):
    ga = factories.make_admin(db, role="chair", chairs=[chair], username="ga")
    login(ga.user)
    page = client.get("/account/edit").text
    assert 'name="chair_id"' not in page and "<select" not in page and "is fixed" in page
    data = {"csrf_token": field(page, "csrf_token"), "display_name": "Renamed GA"}  # no chair field at all
    r = client.post("/account/edit", data=data, follow_redirects=False)
    assert r.status_code == 303
    db.rollback()
    db.refresh(ga.user)
    assert ga.user.display_name == "Renamed GA" and ga.user.chair_id == chair.id


def test_group_admin_cannot_change_chair_through_the_form(client, db, chair, other_chair, price, login):
    ga = factories.make_admin(db, role="chair", chairs=[chair], username="ga")
    login(ga.user)
    page = client.get("/account/edit").text
    data = {"csrf_token": field(page, "csrf_token"), "display_name": "Sneaky", "chair_id": str(other_chair.id)}
    r = client.post("/account/edit", data=data, follow_redirects=False)
    assert r.status_code == 403 and "cannot change" in r.text
    db.rollback()
    db.refresh(ga.user)
    assert ga.user.chair_id == chair.id and ga.user.display_name != "Sneaky"  # nothing was applied
    assert not db.scalars(select(AuditLog).where(AuditLog.action == "user.chair_changed")).all()


def test_member_still_sees_and_changes_the_chair(client, db, member, chair, other_chair, login):
    login(member)
    assert 'name="chair_id"' in client.get("/account/edit").text
    page = client.get("/account/edit").text
    data = {"csrf_token": field(page, "csrf_token"), "display_name": "Alice Example", "chair_id": str(other_chair.id)}
    assert client.post("/account/edit", data=data, follow_redirects=False).status_code == 303
    db.rollback()
    db.refresh(member)
    assert member.chair_id == other_chair.id
    assert db.scalars(select(AuditLog).where(AuditLog.action == "user.chair_changed")).all()


def test_demoted_group_admin_can_edit_the_chair_again(client, db, chair, other_chair, login):
    ga = factories.make_admin(db, role="chair", chairs=[chair], username="ga")
    ga.active = False
    db.commit()
    login(ga.user)
    assert 'name="chair_id"' in client.get("/account/edit").text


def test_new_pages_use_only_known_string_keys_and_no_inline_assets(client, db, member, price, login):
    login(member)
    event = event_id_from(scan(client))
    for path in ("/account", "/account/edit", f"/coffee/done/{event}"):
        html = client.get(path).text
        assert " style=" not in html and "<style" not in html and not re.search(r"<script(?![^>]*\bsrc=)", html)
        assert not re.search(r">\s*(user|common)\.[a-z_.]+\s*<", html), path  # a missing key renders as itself
    assert db.query(ConsumptionEvent).count() == 1 and db.query(UserSession).count() >= 1 and User is not None
