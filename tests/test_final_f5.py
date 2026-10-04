"""Task F5: regression tests for the M5 review findings (M-1 to M-4, L-1 to L-6, L-8; L-7 lives in
test_admin_routes_authz.py, L-9 in test_admin_mail_qr.py)."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select

from app.config import Settings
from app.db import read_session, write_session
from app.models import AdminUser, AuditLog, PaymentEvent, PendingAction, RateLimitEvent, User
from app.services import admin_auth, exports, groups, keys, ledger, ratelimit, users
from app.services.checker import check_ledger
from app.services.errors import Forbidden, InvalidAmount, PaybackExceedsCredit
from app.timeutil import utcnow
from tests import factories
from tests.admin_support import fast_hasher, login_as, make_real_admin, new_client, submit  # noqa: F401
from tests.conftest import ROOT, reload_settings
from tests.user_support import PASSWORD

IP = "203.0.113.77"


# ----- fixtures ---------------------------------------------------------------------------------------------------
@pytest.fixture
def ga(db, chair, price):
    return factories.make_admin(db, role="chair", chairs=[chair], username="ga1")


@pytest.fixture
def person_a(db, chair):
    return factories.make_user(db, "Person A", chair=chair)


@pytest.fixture
def person_b(db, chair):
    return factories.make_user(db, "Person B", chair=chair)


def count(db, model) -> int:
    db.rollback()
    return db.scalar(select(func.count()).select_from(model))


# ----- M-1: a negative cash payment is capped at the person's credit ---------------------------------------------
def test_group_admin_cannot_cover_missing_cash_with_a_fake_paid_back(db, ga, person_a, person_b):
    ledger.add_payment(db, admin=ga, user_id=person_a.id, amount_cents=5000)
    db.commit()
    assert groups.held(db, ga.id) == 5000
    with pytest.raises(PaybackExceedsCredit):
        ledger.add_payment(db, admin=ga, user_id=person_b.id, amount_cents=-5000)  # B never paid
    db.rollback()
    assert groups.held(db, ga.id) == 5000 and count(db, PaymentEvent) == 1
    assert ledger.get_totals(db, person_b.id).balance_cents == 0
    assert issubclass(PaybackExceedsCredit, InvalidAmount)


def test_paid_back_is_allowed_up_to_the_credit_and_not_beyond(db, ga, person_a, global_admin):
    ledger.add_payment(db, admin=ga, user_id=person_a.id, amount_cents=300)  # person A has a credit of 3.00
    db.commit()
    with pytest.raises(PaybackExceedsCredit):
        ledger.add_payment(db, admin=ga, user_id=person_a.id, amount_cents=-301)
    db.rollback()
    paid = ledger.add_payment(db, admin=ga, user_id=person_a.id, amount_cents=-300)  # exactly the credit
    db.commit()
    assert paid.amount_cents == -300 and groups.held(db, ga.id) == 0
    with pytest.raises(PaybackExceedsCredit):  # the credit is used up
        ledger.add_payment(db, admin=ga, user_id=person_a.id, amount_cents=-1)
    db.rollback()
    assert groups.over_credit_paybacks(db) == [] and check_ledger(db).ok


def test_the_credit_is_computed_on_the_effective_user(db, ga, chair, global_admin):
    keep = factories.make_user(db, "Keep", chair=chair)
    dup = factories.make_user(db, "Dup", chair=chair)
    ledger.add_payment(db, admin=global_admin, user_id=dup.id, amount_cents=400)  # credit sits on the duplicate
    users.merge_users(db, admin=global_admin, duplicate_id=dup.id, target_id=keep.id)
    db.commit()
    with pytest.raises(PaybackExceedsCredit):
        ledger.add_payment(db, admin=ga, user_id=keep.id, amount_cents=-401)
    db.rollback()
    ledger.add_payment(db, admin=ga, user_id=keep.id, amount_cents=-400)
    db.commit()
    assert ledger.get_totals(db, keep.id).balance_cents == 0


def test_a_person_who_owes_money_has_no_credit_to_pay_back(db, ga, person_a, price):
    factories.add_events(db, person_a, ["double"])  # owes 1.00
    with pytest.raises(PaybackExceedsCredit):
        ledger.add_payment(db, admin=ga, user_id=person_a.id, amount_cents=-1)
    db.rollback()


def test_head_admin_may_exceed_the_credit_and_the_entry_is_flagged(db, ga, person_a, person_b, global_admin):
    ledger.add_payment(db, admin=ga, user_id=person_a.id, amount_cents=5000)
    over = ledger.add_payment(db, admin=global_admin, user_id=person_b.id, amount_cents=-700, note="refund")
    ok = ledger.add_payment(db, admin=global_admin, user_id=person_a.id, amount_cents=-500)  # within A's credit
    db.commit()
    flagged = groups.over_credit_paybacks(db)
    assert [(f.payment_id, f.amount_cents, f.credit_cents, f.user_name) for f in flagged] == \
        [(over.id, 700, 0, "Person B")]
    assert ok.id not in {f.payment_id for f in flagged}
    report = check_ledger(db)
    assert report.ok  # a note, never a failure
    assert any("exceeded the person's credit" in n and str(over.id) in n for n in report.notes)
    assert not any(str(ok.id) in n for n in report.notes)


def test_flag_looks_at_the_credit_at_the_time_not_today(db, ga, person_a, global_admin):
    ledger.add_payment(db, admin=ga, user_id=person_a.id, amount_cents=500, now=utcnow().replace(microsecond=0))
    back = ledger.add_payment(db, admin=global_admin, user_id=person_a.id, amount_cents=-500)
    db.commit()
    assert groups.over_credit_paybacks(db) == []  # fine then and now
    ledger.add_payment(db, admin=ga, user_id=person_a.id, amount_cents=999)  # later money does not rescue a bad entry
    bad = ledger.add_payment(db, admin=global_admin, user_id=person_a.id, amount_cents=-1500)
    db.commit()
    assert [f.payment_id for f in groups.over_credit_paybacks(db)] == [bad.id]
    assert back.id != bad.id


def test_a_correction_by_its_collector_is_not_capped_nor_flagged(db, ga, person_a, price):
    factories.add_events(db, person_a, ["single"] * 6)  # owes 3.00, so there is no credit
    pay = ledger.add_payment(db, admin=ga, user_id=person_a.id, amount_cents=250)
    db.commit()
    corr = ledger.add_payment(db, admin=ga, user_id=person_a.id, amount_cents=-250, correction_of_id=pay.id)
    db.commit()
    assert corr.amount_cents == -250 and groups.held(db, ga.id) == 0
    assert groups.over_credit_paybacks(db) == [] and check_ledger(db).ok


def test_an_idempotent_replay_of_a_valid_paid_back_still_returns_the_entry(db, ga, person_a):
    ledger.add_payment(db, admin=ga, user_id=person_a.id, amount_cents=300)
    first = ledger.add_payment(db, admin=ga, user_id=person_a.id, amount_cents=-300, idempotency_key="pb-1")
    db.commit()  # the credit is gone now; the replay must not be refused
    again = ledger.add_payment(db, admin=ga, user_id=person_a.id, amount_cents=-300, idempotency_key="pb-1")
    assert again.id == first.id


def test_over_credit_paid_back_through_the_admin_route_is_refused(app, db, chair, price, person_a):
    admin_id, _ = make_real_admin(role="chair", chairs=[chair], username="gadm")
    c = new_client(app)
    csrf = login_as(c, admin_id)
    r = submit(c, csrf, f"/admin/users/{person_a.id}/payment", {"amount": "-5"})
    assert r.status_code == 303 and "err=payback_exceeds_credit" in r.headers["location"]
    assert count(db, PaymentEvent) == 0
    r = c.get(r.headers["location"])
    assert "paid back up to the person" in r.text


def test_flagged_entries_are_listed_on_the_groups_page(app, db, chair, person_b, global_admin):
    over = ledger.add_payment(db, admin=global_admin, user_id=person_b.id, amount_cents=-700)
    db.commit()
    head_id, _ = make_real_admin(username="boss")
    c = new_client(app)
    login_as(c, head_id)
    html = c.get("/admin/groups").text
    assert "Paid back above credit" in html and "Person B" in html and "7.00" in html
    assert str(over.user_id) in html


def test_the_groups_page_has_no_flag_section_without_flagged_entries(app, db, chair, person_a, ga):
    ledger.add_payment(db, admin=ga, user_id=person_a.id, amount_cents=300)
    ledger.add_payment(db, admin=ga, user_id=person_a.id, amount_cents=-300)
    db.commit()
    head_id, _ = make_real_admin(username="boss")
    c = new_client(app)
    login_as(c, head_id)
    assert "Paid back above credit" not in c.get("/admin/groups").text


# ----- M-2: bookkeeping is never "Paid back" on the open site ----------------------------------------------------
def test_open_site_labels_set_balance_as_a_balance_adjustment(client, db, chair, global_admin, login, price):
    person = factories.make_user(db, "Adjusted Person", chair=chair)
    viewer = factories.make_member(db, "Viewer", chair, username="viewer")
    ledger.set_balance(db, admin=global_admin, user_id=person.id, target_balance_cents=500, idempotency_key="sb-1")
    db.commit()  # owes 5.00 now: a NEGATIVE bookkeeping payment
    login(viewer)
    html = client.get(f"/overview/people/{person.id}").text
    assert "Balance adjustment" in html and 'class="kind-adjustment"' in html
    assert "bookkeeping correction of the balance" in html
    assert "Paid back" not in html and "returned to the person" not in html
    ledger.set_balance(db, admin=global_admin, user_id=person.id, target_balance_cents=-200, idempotency_key="sb-2")
    db.commit()  # and a positive one
    html = client.get(f"/overview/people/{person.id}").text
    assert html.count('class="kind-adjustment"') == 2 and "Paid back" not in html and "Payment</td>" not in html


def test_open_site_still_says_paid_back_for_real_paid_back_cash(client, db, chair, global_admin, login, price):
    person = factories.make_user(db, "Refunded Person", chair=chair)
    viewer = factories.make_member(db, "Viewer", chair, username="viewer")
    ledger.add_payment(db, admin=global_admin, user_id=person.id, amount_cents=300)
    ledger.add_payment(db, admin=global_admin, user_id=person.id, amount_cents=-100)
    db.commit()
    login(viewer)
    html = client.get(f"/overview/people/{person.id}").text
    assert "Paid back" in html and "returned to the person" in html
    assert "Balance adjustment" not in html


def test_the_owners_account_page_words_a_set_balance_as_a_balance_correction(client, db, chair, global_admin, price):
    from tests.user_support import make_account, sign_in

    owner = make_account(db, "Owner Person", chair, username="ownerp")
    ledger.set_balance(db, admin=global_admin, user_id=owner.id, target_balance_cents=500, idempotency_key="sb-3")
    db.commit()
    sign_in(client, owner)
    html = client.get("/account").text
    assert "Balance correction (charged)" in html
    assert "Paid back" not in html


# ----- M-3: cookie-less /overview* visits are rate limited per IP --------------------------------------------------
def test_anonymous_overview_rows_are_capped_per_ip(client, db):
    bucket, limit, _window = ratelimit.OVERVIEW_ANON
    assert (limit, _window) == (30, 600)
    for i in range(limit):
        client.cookies.clear()
        r = client.get("/overview", follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/login" and "coffee_pending" in r.headers["set-cookie"]
    assert count(db, PendingAction) == limit
    for path in ("/overview", "/overview/people", "/overview/chairs", "/overview/prices"):
        client.cookies.clear()
        r = client.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/login"  # still sent to the login page
        assert "set-cookie" not in r.headers  # but nothing is parked
    assert count(db, PendingAction) == limit
    assert db.scalar(select(func.count()).select_from(RateLimitEvent).where(RateLimitEvent.bucket == bucket)) == limit


def test_a_browser_with_a_live_pending_action_costs_nothing(client, db):
    r = client.get("/overview", follow_redirects=False)  # the cookie is kept by the client from now on
    assert "coffee_pending" in r.headers["set-cookie"]
    for _ in range(5):
        assert client.get("/overview/people", follow_redirects=False).status_code == 303
    assert count(db, PendingAction) == 1
    assert db.scalar(select(func.count()).select_from(RateLimitEvent).where(
        RateLimitEvent.bucket == ratelimit.OVERVIEW_ANON[0])) == 1


def test_the_cap_ends_with_its_window(client, db):
    bucket, limit, window = ratelimit.OVERVIEW_ANON
    key = ratelimit.ip_key("testclient")
    now = utcnow()
    for _ in range(limit):
        ratelimit.record_hit(db, bucket, key, now=now - timedelta(seconds=window + 5))
    db.commit()
    client.cookies.clear()
    r = client.get("/overview", follow_redirects=False)
    assert "coffee_pending" in r.headers["set-cookie"]  # old hits no longer count


# ----- M-4: only a head admin may deactivate the profile of an active group admin ------------------------------
def test_group_admin_cannot_deactivate_a_peer_group_admins_profile(db, chair, price, global_admin):
    g = factories.make_admin(db, role="chair", chairs=[chair], username="g1")
    peer = factories.make_admin(db, role="chair", chairs=[chair], username="g2")
    with pytest.raises(Forbidden):
        users.set_user_status(db, admin=g, user_id=peer.user_id, active=False)
    db.rollback()
    assert db.get(User, peer.user_id).status == "active"
    users.set_user_status(db, admin=global_admin, user_id=peer.user_id, active=False)  # a head admin may
    db.commit()
    assert db.get(User, peer.user_id).status == "inactive"
    # ordinary members, and the profile of a FORMER group admin, stay in the group admin's hands
    member = factories.make_user(db, "Plain Member", chair=chair)
    users.set_user_status(db, admin=g, user_id=member.id, active=False)
    other = factories.make_admin(db, role="chair", chairs=[chair], username="g3", active=False)
    users.set_user_status(db, admin=g, user_id=other.user_id, active=False)
    db.commit()
    assert db.get(User, member.id).status == "inactive" and db.get(User, other.user_id).status == "inactive"
    users.set_user_status(db, admin=g, user_id=member.id, active=True)  # reactivation is never restricted


def test_deactivating_a_peer_is_refused_through_the_admin_route(app, db, chair, price):
    g_id, _ = make_real_admin(role="chair", chairs=[chair], username="gone")
    peer_id, _ = make_real_admin(role="chair", chairs=[chair], username="gtwo")
    with write_session() as w:
        peer_user = w.get(AdminUser, peer_id).user_id
    c = new_client(app)
    csrf = login_as(c, g_id)
    r = c.post(f"/admin/users/{peer_user}/status", data={"csrf_token": csrf, "active": "0"}, follow_redirects=False)
    assert r.status_code == 403
    with read_session() as s:
        assert s.get(User, peer_user).status == "active"
        assert not s.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == "user.deactivated"))
    head_id, _ = make_real_admin(username="boss")
    h = new_client(app)
    hcsrf = login_as(h, head_id)
    r = h.post(f"/admin/users/{peer_user}/status", data={"csrf_token": hcsrf, "active": "0"}, follow_redirects=False)
    assert r.status_code == 303 and "msg=user_deactivated" in r.headers["location"]


# ----- L-1: failed logins store a keyed hash of the attempted name ------------------------------------------------
def _login_meta(action: str) -> list[dict]:
    with read_session() as s:
        return [e.meta for e in s.scalars(select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.id))]


def test_failed_login_of_an_unknown_name_stores_only_a_hash(db):
    typed = "hunter2-my-real-password"
    out = admin_auth.start_login(username=typed, password="x" * 12, ip=IP)
    assert out.status == "invalid"
    (meta,) = _login_meta("admin.login.failed")
    expected = hmac.new(keys.derive_key("admin-login-username"), typed.encode(), hashlib.sha256).hexdigest()[:16]
    assert meta == {"step": "password", "username_hash": expected}
    with read_session() as s:
        dump = json.dumps([e.meta for e in s.scalars(select(AuditLog))])
    assert typed not in dump and "hunter2" not in dump


def test_failed_login_of_an_existing_admin_also_stores_the_name(db):
    make_real_admin(username="realboss")
    admin_auth.start_login(username="RealBoss", password="wrong wrong wrong", ip=IP)
    (meta,) = _login_meta("admin.login.failed")
    assert meta["username"] == "RealBoss" and len(meta["username_hash"]) == 16 and "username_attempted" not in meta
    admin_auth.start_login(username="realboss", password="wrong wrong wrong", ip=IP)
    h1, h2 = (m["username_hash"] for m in _login_meta("admin.login.failed"))
    assert h1 == h2  # the hash is over the normalised name: repeated attempts correlate
    admin_auth.start_login(username="someone-else", password="wrong wrong wrong", ip=IP)
    assert _login_meta("admin.login.failed")[-1]["username_hash"] != h1


def test_rate_limited_login_stores_only_a_hash_for_an_unknown_name(db):
    typed = "not-an-admin-but-a-password-1"
    for _ in range(ratelimit.ADMIN_LOGIN_FAILURES[1]):
        assert admin_auth.start_login(username=typed, password="x" * 12, ip=IP).status == "invalid"
    assert admin_auth.start_login(username=typed, password="x" * 12, ip=IP).status == "limited"
    (meta,) = _login_meta("admin.login.rate_limited")
    assert set(meta) == {"step", "username_hash"}
    with read_session() as s:
        assert typed not in json.dumps([e.meta for e in s.scalars(select(AuditLog))])


# ----- L-2: BALANCE_TOTP_REQUIRED=false is refused in production --------------------------------------------------
PROD = dict(_env_file=None, environment="production", public_base_url="https://coffee.example.org",
            secret_key="Zq3v8K1mR7tXw2pL9sD4fG6hJ0kN5bVc", mail_from="Coffee Ledger <coffee@example.org>")


def test_production_refuses_balance_totp_required_false():
    with pytest.raises(ValidationError) as exc:
        Settings(**PROD, balance_totp_required=False)
    assert "BALANCE_TOTP_REQUIRED" in str(exc.value)
    assert Settings(**PROD).balance_totp_required is True  # unset: on
    assert Settings(**PROD, balance_totp_required=True).balance_totp_required is True
    assert Settings(_env_file=None, balance_totp_required=False).balance_totp_required is False  # development


def test_production_refuses_the_environment_variable_too(monkeypatch):
    for k, v in {"ENVIRONMENT": "production", "PUBLIC_BASE_URL": "https://coffee.example.org",
                 "SECRET_KEY": PROD["secret_key"], "MAIL_FROM": PROD["mail_from"],
                 "BALANCE_TOTP_REQUIRED": "false"}.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(ValidationError):
        reload_settings()
        from app.config import get_settings
        get_settings()
    monkeypatch.delenv("BALANCE_TOTP_REQUIRED")
    reload_settings()


def test_docs_say_production_refuses_it():
    assert "refuses to start" in (ROOT / ".env.example").read_text()
    assert "refused when `ENVIRONMENT=production`" in (ROOT / "README.md").read_text()


# ----- L-3: remittance chair and the authoritative per-admin figure ----------------------------------------------
def test_remittance_records_the_chair_at_event_time_and_held_stays_per_admin(db, chair, other_chair, ga, person_a,
                                                                          global_admin):
    ledger.add_payment(db, admin=ga, user_id=person_a.id, amount_cents=1000)  # collected in `chair`
    r1 = groups.record_remittance(db, head_admin=global_admin, group_admin_id=ga.id, amount_cents=300,
                                  idempotency_key="l3-1")
    assert r1.chair_id == chair.id
    ga.user.chair_id = other_chair.id  # the profile moved (after demotion, role and link kept)
    db.commit()
    r2 = groups.record_remittance(db, head_admin=global_admin, group_admin_id=ga.id, amount_cents=200,
                                  idempotency_key="l3-2")
    corr = groups.record_remittance(db, head_admin=global_admin, group_admin_id=ga.id, amount_cents=250,
                                    idempotency_key="l3-3", correction_of_id=r1.id)
    db.commit()
    assert r2.chair_id == other_chair.id and corr.chair_id == chair.id  # a correction keeps its original's chair
    assert groups.held(db, ga.id) == 1000 - 300 - 200 - 250  # the authoritative figure, whatever the chairs say
    (row,) = [b for b in groups.list_group_balances(db) if b.admin_id == ga.id]
    assert row.held_cents == groups.held(db, ga.id)
    assert check_ledger(db).ok


def test_l3_decision_is_documented():
    contract = (ROOT / "docs" / "V2-CONTRACT.md").read_text()
    assert "Decision L-3" in contract and "authoritative per-admin figure" in contract
    doc = Path(groups.__file__).read_text()
    assert "Authoritative figure (decision L-3)" in doc


# ----- L-4: former group admins with any history stay listed ------------------------------------------------------
def test_former_admin_with_any_collection_or_remittance_stays_listed(db, chair, price, person_a, global_admin):
    never = factories.make_admin(db, role="chair", chairs=[chair], username="never", active=False)
    settled = factories.make_admin(db, role="chair", chairs=[chair], username="settled")
    only_remit = factories.make_admin(db, role="chair", chairs=[chair], username="onlyrem")
    ledger.add_payment(db, admin=settled, user_id=person_a.id, amount_cents=500)
    groups.record_remittance(db, head_admin=global_admin, group_admin_id=settled.id, amount_cents=500,
                             idempotency_key="l4-1")
    groups.record_remittance(db, head_admin=global_admin, group_admin_id=only_remit.id, amount_cents=100,
                             idempotency_key="l4-2")
    settled.active = False
    only_remit.active = False
    db.commit()
    rows = {b.admin_id: b for b in groups.list_group_balances(db)}
    assert never.id not in rows  # no events at all: not listed
    assert rows[settled.id].held_cents == 0 and rows[settled.id].is_current is False
    assert rows[only_remit.id].held_cents == -100 and rows[only_remit.id].is_current is False
    text = exports.group_balances_csv(db, global_admin).decode("utf-8")
    db.commit()
    assert text.count("former group admin") >= 2 and settled.user.display_name in text


def test_old_remittance_of_a_settled_former_admin_can_still_be_corrected(app, db, chair, price, person_a,
                                                                       global_admin):
    ga = factories.make_admin(db, role="chair", chairs=[chair], username="gold")
    ledger.add_payment(db, admin=ga, user_id=person_a.id, amount_cents=500)
    groups.record_remittance(db, head_admin=global_admin, group_admin_id=ga.id, amount_cents=500,
                             idempotency_key="l4-3")
    ga.active = False
    db.commit()
    head_id, _ = make_real_admin(username="boss")
    c = new_client(app)
    login_as(c, head_id)
    html = c.get("/admin/groups").text
    assert "former group admin" in html and ga.user.display_name in html
    before_entries = html.split("Received entries")[1]
    assert "/correct" in before_entries


# ----- L-5: admin-only pages and exports use the linked user's display name ---------------------------------------
def test_group_admin_shows_with_the_members_display_name_in_exports_and_pages(app, db, chair, price, person_a):
    ga_id, _ = make_real_admin(role="chair", chairs=[chair], username="gadmin5")
    with write_session() as w:
        w.get(AdminUser, ga_id).user.display_name = "Gina Group"
    head_id, _ = make_real_admin(username="boss5")
    with write_session() as w:
        ledger.add_payment(w, admin=w.get(AdminUser, ga_id), user_id=person_a.id, amount_cents=700, note="by gina")
        ledger.add_adjustment(w, admin=w.get(AdminUser, head_id), user_id=person_a.id, quantity=1, note="by boss")
    with write_session() as w:
        csv_text = exports.ledger_csv(w, w.get(AdminUser, head_id)).decode("utf-8")
    assert "Gina Group" in csv_text and "gadmin5" not in csv_text
    assert "boss5" in csv_text  # a CLI admin keeps the username
    c = new_client(app)
    login_as(c, head_id)
    html = c.get(f"/admin/users/{person_a.id}").text
    assert "Gina Group" in html and "gadmin5" not in html  # collected by, and the recorder in brackets
    assert "boss5" in html  # a CLI admin recorder keeps the username
    audit_html = c.get("/admin/audit").text
    assert "Gina Group" in audit_html and "gadmin5" not in audit_html


# ----- L-6: the correction dropdown lists only payments the actor may correct ------------------------------------
def test_correction_dropdown_lists_only_correctable_payments(app, db, chair, price, person_a, global_admin):
    ga1_id, _ = make_real_admin(role="chair", chairs=[chair], username="gca")
    ga2_id, _ = make_real_admin(role="chair", chairs=[chair], username="gcb")
    with write_session() as w:
        p1 = ledger.add_payment(w, admin=w.get(AdminUser, ga1_id), user_id=person_a.id, amount_cents=100).id
        p2 = ledger.add_payment(w, admin=w.get(AdminUser, ga2_id), user_id=person_a.id, amount_cents=200).id
        p3 = ledger.add_payment(w, admin=w.get(AdminUser, global_admin.id), user_id=person_a.id, amount_cents=300).id
        p4 = ledger.set_balance(w, admin=w.get(AdminUser, global_admin.id), user_id=person_a.id,
                                target_balance_cents=0, idempotency_key="l6").id

    def options(admin_id):
        c = new_client(app)
        login_as(c, admin_id)
        html = c.get(f"/admin/users/{person_a.id}").text
        block = re.search(r'<select id="pay_corr".*?</select>', html, re.S)
        return set(re.findall(r'<option value="([0-9a-f-]{36})"', block.group(0))) if block else set()

    assert options(ga1_id) == {str(p1)}
    assert options(ga2_id) == {str(p2)}
    head_id, _ = make_real_admin(username="boss6")
    assert options(head_id) == {str(p) for p in (p1, p2, p3, p4)}


# ----- L-8: service-level rules the route tests did not pin -------------------------------------------------------
def test_set_balance_refuses_a_group_admin_at_service_level(db, ga, person_a, global_admin, price):
    factories.add_events(db, person_a, ["single"])
    with pytest.raises(Forbidden):
        ledger.set_balance(db, admin=ga, user_id=person_a.id, target_balance_cents=0, idempotency_key="l8-1")
    db.rollback()
    assert count(db, PaymentEvent) == 0
    # the refusal comes first: a group admin cannot even replay a head admin's key to read the booked entry
    booked = ledger.set_balance(db, admin=global_admin, user_id=person_a.id, target_balance_cents=0,
                                idempotency_key="l8-2")
    db.commit()
    with pytest.raises(Forbidden):
        ledger.set_balance(db, admin=ga, user_id=person_a.id, target_balance_cents=0, idempotency_key="l8-2")
    db.rollback()
    assert ledger.set_balance(db, admin=global_admin, user_id=person_a.id, target_balance_cents=0,
                              idempotency_key="l8-2").id == booked.id


def _own_account_attempts(db, ga, target, event):
    """Every ledger entry point a group admin could use against `target` (an account that counts as theirs)."""
    return {
        "payment": lambda: ledger.add_payment(db, admin=ga, user_id=target.id, amount_cents=100),
        "adjustment": lambda: ledger.add_adjustment(db, admin=ga, user_id=target.id, quantity=1),
        "reversal": lambda: ledger.admin_reverse_event(db, admin=ga, event_id=event.id),
    }


@pytest.mark.parametrize("entry", ["payment", "adjustment", "reversal", "correction"])
def test_own_account_rule_follows_a_merge_of_the_admins_own_profile(db, chair, price, global_admin, entry):
    """The group admin's linked profile was merged into another account B: B is now their own account."""
    ga = factories.make_admin(db, role="chair", chairs=[chair], username="own1")
    b = factories.make_user(db, "Account B", chair=chair)
    event = factories.add_events(db, b, ["single"])[0]
    original = ledger.add_payment(db, admin=ga, user_id=b.id, amount_cents=500)  # collected before the merge
    users.merge_users(db, admin=global_admin, duplicate_id=ga.user_id, target_id=b.id)
    db.commit()
    attempts = _own_account_attempts(db, ga, b, event)
    attempts["correction"] = lambda: ledger.add_payment(db, admin=ga, user_id=b.id, amount_cents=-100,
                                                        correction_of_id=original.id)
    with pytest.raises(Forbidden):
        attempts[entry]()
    db.rollback()
    assert count(db, PaymentEvent) == 1  # only the setup payment before the merge


def test_a_profile_merged_into_the_group_admins_own_account_is_blocked_too(db, chair, price, global_admin):
    ga = factories.make_admin(db, role="chair", chairs=[chair], username="own2")
    dup = factories.make_user(db, "Old Profile", chair=chair)
    event = factories.add_events(db, dup, ["single"])[0]
    users.merge_users(db, admin=global_admin, duplicate_id=dup.id, target_id=ga.user_id)
    db.commit()
    with pytest.raises(Forbidden):  # the event of the merged profile counts as the admin's own
        ledger.admin_reverse_event(db, admin=ga, event_id=event.id)
    db.rollback()
    with pytest.raises(Forbidden):  # and so does the account itself
        ledger.add_payment(db, admin=ga, user_id=ga.user_id, amount_cents=100)
    db.rollback()
    ledger.admin_reverse_event(db, admin=global_admin, event_id=event.id)  # a head admin may
    db.commit()
