"""Task 4.4: /admin/groups, remittances through the step-up flow, set balance, group balance CSV."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app.db import read_session, write_session
from app.models import AdminUser, AuditLog, GroupRemittance, PaymentEvent, UsedNonce
from app.services import groups, ledger, stepup
from tests import factories
from tests.admin_support import (
    confirm, current_code, fast_hasher, login_as, make_real_admin, new_client, submit,  # noqa: F401
)


# ----- fixtures -----------------------------------------------------------------------------------
@pytest.fixture
def head(app):
    admin_id, secret = make_real_admin(username="boss")
    c = new_client(app)
    return c, login_as(c, admin_id)


@pytest.fixture
def ga_id(chair):
    admin_id, _ = make_real_admin(role="chair", chairs=[chair], username="gadmin")
    with write_session() as w:
        w.get(AdminUser, admin_id).user.display_name = "Gina Group"
    return admin_id


@pytest.fixture
def ga_client(app, ga_id):
    c = new_client(app)
    return c, login_as(c, ga_id)


@pytest.fixture
def alice(db, chair, price):
    return factories.make_user(db, "Alice Müller", chair)


def collect(admin_id, user_id, cents):
    """A cash payment recorded by the group admin (the collector)."""
    with write_session() as w:
        return ledger.add_payment(w, admin=w.get(AdminUser, admin_id), user_id=user_id, amount_cents=cents).id


def held(admin_id) -> int:
    with read_session() as r:
        return groups.held(r, admin_id)


def count(model) -> int:
    with read_session() as r:
        return r.scalar(select(func.count()).select_from(model))


def actions() -> list[str]:
    with read_session() as r:
        return [a.action for a in r.scalars(select(AuditLog).order_by(AuditLog.id))]


def remit(pair, ga_id, amount, note=""):
    client, csrf = pair
    return submit(client, csrf, "/admin/groups/remittances",
                  {"group_admin_id": str(ga_id), "amount": amount, "note": note})


def entry_ids(admin_id) -> list:
    with read_session() as r:
        return list(r.scalars(select(GroupRemittance.id).where(GroupRemittance.group_admin_id == admin_id)
                              .order_by(GroupRemittance.created_at)))


# ----- the page -------------------------------------------------------------------------------------
def test_page_shows_collected_handed_over_held_and_rollup(head, ga_id, alice, chair):
    collect(ga_id, alice.id, 2500)
    remit(head, ga_id, "10")
    r = head[0].get("/admin/groups")
    assert r.status_code == 200
    html = r.text
    assert "Gina Group" in html and "Held by group" in html and "Handed over" in html and "Collected" in html
    assert "25.00" in html and "10.00" in html and "15.00" in html
    assert chair.short_name in html  # per-chair rollup
    assert "Received entries" in html and "Correct" in html


def test_page_has_no_minus_signs_for_held(head, ga_id, alice):
    collect(ga_id, alice.id, 1000)
    remit(head, ga_id, "40")  # more handed over than collected: held would be -30
    html = head[0].get("/admin/groups").text
    assert "More handed over than collected" in html
    assert "30.00" in html
    for line in html.splitlines():
        if 'data-label="Held by group"' in line:
            assert "−" not in line and "-3" not in line


def test_group_admin_without_money_is_listed(head, ga_id):
    html = head[0].get("/admin/groups").text
    assert "Gina Group" in html and "0.00" in html


# ----- remittance flow --------------------------------------------------------------------------------
def test_preview_writes_nothing_and_shows_held_before_and_after(head, ga_id, alice):
    collect(ga_id, alice.id, 2000)
    client, csrf = head
    r = client.post("/admin/groups/remittances", data={"csrf_token": csrf, "group_admin_id": str(ga_id),
                                                       "amount": "12,50", "note": "June"}, follow_redirects=False)
    assert r.status_code == 200 and "Money received from a group admin" in r.text
    assert "Held by group now" in r.text and "Held by group afterwards" in r.text
    assert "20.00" in r.text and "7.50" in r.text and "12.50" in r.text and "Gina Group" in r.text
    assert count(GroupRemittance) == 0 and held(ga_id) == 2000 and count(UsedNonce) == 0
    assert "remittance.recorded" not in actions()


def test_head_admin_records_remittance_and_held_decreases(head, ga_id, alice):
    collect(ga_id, alice.id, 2000)
    r = remit(head, ga_id, "12.50", "cash handover")
    assert r.status_code == 303 and "msg=remittance_recorded" in r.headers["location"]
    assert r.headers["location"].startswith("/admin/groups")
    assert held(ga_id) == 750
    with read_session() as r2:
        entry = r2.scalars(select(GroupRemittance)).one()
        assert entry.amount_cents == 1250 and entry.note == "cash handover"
        assert entry.idempotency_key.startswith("stepup:")
    assert "remittance.recorded" in actions() and "stepup.executed" in actions()
    assert "Money received from the group admin recorded." in head[0].get(r.headers["location"]).text
    assert "cash handover" in head[0].get("/admin/groups").text


def test_double_submit_books_once(head, ga_id, alice):
    collect(ga_id, alice.id, 2000)
    client, csrf = head
    page = client.post("/admin/groups/remittances", data={"csrf_token": csrf, "group_admin_id": str(ga_id),
                                                          "amount": "5"}, follow_redirects=False)
    first = confirm(client, page.text)
    second = confirm(client, page.text)
    assert first.status_code == 303 and "msg=remittance_recorded" in first.headers["location"]
    assert second.status_code == 303 and "msg=already_executed" in second.headers["location"]
    assert count(GroupRemittance) == 1 and held(ga_id) == 1500 and count(UsedNonce) == 1


@pytest.mark.parametrize("amount", ["", "0", "abc", "1.234", "€5"])
def test_invalid_amount_is_rejected_before_the_confirm_page(head, ga_id, amount):
    r = remit(head, ga_id, amount)
    assert r.status_code == 303 and "err=invalid_amount" in r.headers["location"]
    assert count(GroupRemittance) == 0


def test_remittance_for_a_non_group_admin_is_rejected(head, db):
    other_head = factories.make_admin(db, "global", username="second")
    r = remit(head, other_head.id, "5")
    assert r.status_code == 303 and "err=invalid_input" in r.headers["location"]
    r = remit(head, "not-a-uuid", "5")
    assert r.status_code == 303 and "err=" in r.headers["location"]
    assert count(GroupRemittance) == 0


def test_remittance_needs_a_code_when_the_window_is_closed(app, chair, monkeypatch, ga_id, alice):
    from tests.conftest import reload_settings
    monkeypatch.setenv("BALANCE_TOTP_REQUIRED", "true")
    reload_settings()
    admin_id, secret = make_real_admin(username="boss2")
    client = new_client(app)
    csrf = login_as(client, admin_id)
    collect(ga_id, alice.id, 1000)
    page = client.post("/admin/groups/remittances", data={"csrf_token": csrf, "group_admin_id": str(ga_id),
                                                          "amount": "4"}, follow_redirects=False)
    assert 'name="code"' in page.text
    r = confirm(client, page.text)  # no code
    assert r.status_code == 200 and count(GroupRemittance) == 0
    r = confirm(client, page.text, code="000000")
    assert r.status_code == 401 and count(GroupRemittance) == 0
    r = confirm(client, page.text, code=current_code(secret))
    assert r.status_code == 303 and "msg=remittance_recorded" in r.headers["location"]
    assert held(ga_id) == 600


# ----- correction ---------------------------------------------------------------------------------------
def test_correction_books_the_difference_once(head, ga_id, alice):
    collect(ga_id, alice.id, 5000)
    remit(head, ga_id, "30")
    (first,) = entry_ids(ga_id)
    client, csrf = head
    path = f"/admin/groups/remittances/{first}/correct"
    page = client.post(path, data={"csrf_token": csrf, "corrected_to": "20", "note": "typo"},
                       follow_redirects=False)
    assert page.status_code == 200 and "Correct a received amount" in page.text
    assert "30.00" in page.text and "20.00" in page.text and "10.00" in page.text  # entry so far / afterwards / diff
    assert held(ga_id) == 2000  # preview booked nothing
    r = confirm(client, page.text)
    assert r.status_code == 303 and "msg=remittance_corrected" in r.headers["location"]
    assert held(ga_id) == 3000
    assert count(GroupRemittance) == 2 and "remittance.corrected" in actions()
    html = client.get("/admin/groups").text
    assert "correction" in html and "corrected" in html
    assert f"/remittances/{first}/correct" not in html  # one correction per entry: the form is gone
    # a second correction is refused by the dry run of a forged request, too
    r = client.post(path, data={"csrf_token": csrf, "corrected_to": "25"}, follow_redirects=False)
    assert r.status_code == 303 and "err=conflict" in r.headers["location"]
    assert count(GroupRemittance) == 2


def test_second_correction_is_refused(head, ga_id, alice):
    collect(ga_id, alice.id, 5000)
    remit(head, ga_id, "30")
    (first,) = entry_ids(ga_id)
    r = submit(*head, f"/admin/groups/remittances/{first}/correct", {"corrected_to": "20"})
    assert "msg=remittance_corrected" in r.headers["location"]
    r = submit(*head, f"/admin/groups/remittances/{first}/correct", {"corrected_to": "25"})
    assert r.status_code == 303 and "err=conflict" in r.headers["location"]
    assert count(GroupRemittance) == 2


def test_correction_of_a_correction_and_unknown_entry_are_refused(head, ga_id, alice):
    collect(ga_id, alice.id, 5000)
    remit(head, ga_id, "30")
    (first,) = entry_ids(ga_id)
    submit(*head, f"/admin/groups/remittances/{first}/correct", {"corrected_to": "20"})
    second = [e for e in entry_ids(ga_id) if e != first][0]
    r = submit(*head, f"/admin/groups/remittances/{second}/correct", {"corrected_to": "1"})
    assert r.status_code == 303 and "err=conflict" in r.headers["location"]
    r = submit(*head, "/admin/groups/remittances/00000000-0000-0000-0000-000000000000/correct", {"corrected_to": "1"})
    assert r.status_code == 303 and "err=not_found" in r.headers["location"]
    r = head[0].post("/admin/groups/remittances/nope/correct", data={"csrf_token": head[1], "corrected_to": "1"},
                     follow_redirects=False)
    assert r.status_code == 404
    assert count(GroupRemittance) == 2


def test_correction_to_the_same_amount_is_refused(head, ga_id, alice):
    collect(ga_id, alice.id, 5000)
    remit(head, ga_id, "30")
    (first,) = entry_ids(ga_id)
    r = submit(*head, f"/admin/groups/remittances/{first}/correct", {"corrected_to": "30"})
    assert r.status_code == 303 and "err=no_change" in r.headers["location"]
    assert "Nothing to book" in head[0].get(r.headers["location"]).text
    assert count(GroupRemittance) == 1


def test_correction_to_zero_reverses_the_entry(head, ga_id, alice):
    collect(ga_id, alice.id, 5000)
    remit(head, ga_id, "30")
    (first,) = entry_ids(ga_id)
    submit(*head, f"/admin/groups/remittances/{first}/correct", {"corrected_to": "0"})
    assert held(ga_id) == 5000


# ----- negative and former group admins -------------------------------------------------------------------
def test_negative_held_is_flagged(head, ga_id, alice):
    collect(ga_id, alice.id, 1000)
    remit(head, ga_id, "25")
    assert held(ga_id) == -1500
    assert "More handed over than collected" in head[0].get("/admin/groups").text


def test_former_group_admin_is_listed_while_non_zero(head, ga_id, alice):
    collect(ga_id, alice.id, 1000)
    with write_session() as w:
        w.get(AdminUser, ga_id).active = False  # demoted: role stays `chair`, no more sign-in
    html = head[0].get("/admin/groups").text
    assert "Gina Group" in html and "former group admin" in html
    r = remit(head, ga_id, "10")  # a former group admin can still hand over what they held
    assert r.status_code == 303 and "msg=remittance_recorded" in r.headers["location"]
    assert "Gina Group" not in head[0].get("/admin/groups").text.split("Received entries")[0]


# ----- authorisation ---------------------------------------------------------------------------------------
def test_group_admin_is_forbidden_everywhere_in_the_money_area(ga_client, ga_id, alice):
    collect(ga_id, alice.id, 1000)
    client, csrf = ga_client
    assert client.get("/admin/groups", follow_redirects=False).status_code == 403
    assert client.get("/admin/exports/group-balances.csv", follow_redirects=False).status_code == 403
    r = client.post("/admin/groups/remittances", data={"csrf_token": csrf, "group_admin_id": str(ga_id),
                                                       "amount": "5"}, follow_redirects=False)
    assert r.status_code == 403
    r = client.post(f"/admin/users/{alice.id}/balance", data={"csrf_token": csrf, "amount": "0",
                                                              "direction": "owes"}, follow_redirects=False)
    assert r.status_code == 403
    assert count(GroupRemittance) == 0 and count(PaymentEvent) == 1
    assert "/admin/groups" not in client.get("/admin").text  # no nav link


def test_group_admin_cannot_confirm_a_forged_remittance_payload(head, ga_client, ga_id, alice):
    """A payload minted for the head admin is bound to the head session: the group admin's confirm is refused."""
    collect(ga_id, alice.id, 1000)
    page = head[0].post("/admin/groups/remittances", data={"csrf_token": head[1], "group_admin_id": str(ga_id),
                                                           "amount": "5"}, follow_redirects=False)
    r = confirm(ga_client[0], page.text, csrf_token=ga_client[1])
    assert r.status_code == 400 and count(GroupRemittance) == 0


def test_actions_are_registered():
    assert {"remittance", "remittance_correction", "set_balance"} <= set(stepup.REGISTRY)


def test_anonymous_and_user_cookies_never_reach_the_pages(app, client, login, db, chair):
    anon = new_client(app)
    for path in ("/admin/groups", "/admin/exports/group-balances.csv"):
        r = anon.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/admin/login"
    login(factories.make_user(db, "Normal Person", chair))
    r = client.get("/admin/groups", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/admin/login"


# ----- set balance --------------------------------------------------------------------------------------------
def test_head_sees_set_balance_group_admin_does_not(head, ga_client, alice):
    assert "Set balance" in head[0].get(f"/admin/users/{alice.id}").text
    assert "Set balance" not in ga_client[0].get(f"/admin/users/{alice.id}").text


def totals(user_id):
    with read_session() as r:
        return ledger.get_totals(r, user_id)


def test_set_balance_down_books_a_bookkeeping_payment(head, ga_id, alice, db):
    factories.add_events(db, alice, ["single", "double"])  # 3 shots, 1.50 at the 0.50 test price
    before = totals(alice.id).balance_cents
    assert before == 150
    client, csrf = head
    page = client.post(f"/admin/users/{alice.id}/balance",
                       data={"csrf_token": csrf, "amount": "0.50", "direction": "owes", "note": "settled in kind"},
                       follow_redirects=False)
    assert page.status_code == 200 and "Set balance" in page.text
    assert "Owes €1.50" in page.text and "Owes €0.50" in page.text and "owes €1.00 less" in page.text
    assert totals(alice.id).balance_cents == 150  # preview wrote nothing
    r = confirm(client, page.text)
    assert r.status_code == 303 and "msg=balance_set" in r.headers["location"]
    assert totals(alice.id).balance_cents == 50
    with read_session() as r2:
        p = r2.scalars(select(PaymentEvent)).one()
        assert p.kind == "bookkeeping" and p.collector_admin_id is None and p.amount_cents == 100
        assert p.note == "settled in kind"
    assert "payment.recorded" in actions() and "stepup.executed" in actions()


def test_set_balance_up_to_credit_and_back(head, alice, db):
    factories.add_events(db, alice, ["single"])
    r = submit(*head, f"/admin/users/{alice.id}/balance", {"amount": "2", "direction": "credit"})
    assert "msg=balance_set" in r.headers["location"]
    assert totals(alice.id).balance_cents == -200
    page = head[0].get(f"/admin/users/{alice.id}").text
    assert "Credit €2.00" in page
    r = submit(*head, f"/admin/users/{alice.id}/balance", {"amount": "1", "direction": "owes"})
    assert totals(alice.id).balance_cents == 100
    with read_session() as r2:
        kinds = [p.kind for p in r2.scalars(select(PaymentEvent).order_by(PaymentEvent.created_at))]
        assert kinds == ["bookkeeping", "bookkeeping"]


def test_set_balance_confirm_page_wording_has_no_minus_sign(head, alice, db):
    factories.add_events(db, alice, ["single"])
    page = head[0].post(f"/admin/users/{alice.id}/balance",
                        data={"csrf_token": head[1], "amount": "3", "direction": "credit"}, follow_redirects=False)
    assert "Credit €3.00" in page.text and "owes €3.50 less" in page.text
    assert "−" not in page.text


def test_set_balance_never_touches_group_balances(head, ga_id, alice, db):
    collect(ga_id, alice.id, 1000)
    before = (held(ga_id), groups.collected(db, ga_id))
    submit(*head, f"/admin/users/{alice.id}/balance", {"amount": "7", "direction": "credit"})
    submit(*head, f"/admin/users/{alice.id}/balance", {"amount": "0", "direction": "owes"})
    db.expire_all()
    assert (held(ga_id), groups.collected(db, ga_id)) == before
    with read_session() as r:
        assert groups.chair_rollup(r)[0].collected_cents == 1000


def test_set_balance_to_the_same_value_is_refused(head, alice):
    r = submit(*head, f"/admin/users/{alice.id}/balance", {"amount": "0", "direction": "owes"})
    assert r.status_code == 303 and "err=no_change" in r.headers["location"]
    assert count(PaymentEvent) == 0


@pytest.mark.parametrize("data", [{"amount": "-3", "direction": "owes"}, {"amount": "x", "direction": "owes"},
                                  {"amount": "3", "direction": ""}, {"amount": "3", "direction": "minus"},
                                  {"amount": "", "direction": "credit"}])
def test_set_balance_rejects_bad_input(head, alice, data):
    r = submit(*head, f"/admin/users/{alice.id}/balance", data)
    assert r.status_code == 303 and "err=" in r.headers["location"]
    assert count(PaymentEvent) == 0


def test_set_balance_double_submit_books_once(head, alice, db):
    factories.add_events(db, alice, ["single"])
    client, csrf = head
    page = client.post(f"/admin/users/{alice.id}/balance", data={"csrf_token": csrf, "amount": "0",
                                                                 "direction": "owes"}, follow_redirects=False)
    a, b = confirm(client, page.text), confirm(client, page.text)
    assert "msg=balance_set" in a.headers["location"] and "msg=already_executed" in b.headers["location"]
    assert count(PaymentEvent) == 1 and totals(alice.id).balance_cents == 0


# ----- collector on the user detail page ---------------------------------------------------------------------
def test_user_detail_shows_the_collector_to_admins_only(head, ga_client, ga_id, alice, db, login, client):
    collect(ga_id, alice.id, 800)
    html = head[0].get(f"/admin/users/{alice.id}").text
    assert "Collected by" in html and "Gina Group" in html
    assert "Gina Group" in ga_client[0].get(f"/admin/users/{alice.id}").text
    submit(*head, f"/admin/users/{alice.id}/balance", {"amount": "9", "direction": "credit"})
    assert "bookkeeping" in head[0].get(f"/admin/users/{alice.id}").text
    # the public site never shows who collected
    login(alice)
    for path in ("/account", "/overview"):
        r = client.get(path, follow_redirects=True)
        assert "Gina Group" not in r.text and "gadmin" not in r.text and "Collected by" not in r.text


# ----- CSV --------------------------------------------------------------------------------------------------------
def test_group_balances_csv_content_and_audit(head, ga_id, alice, chair):
    collect(ga_id, alice.id, 2000)
    remit(head, ga_id, "5")
    r = head[0].get("/admin/exports/group-balances.csv")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"] and "group-balances" in r.headers["content-disposition"]
    assert r.headers["cache-control"].startswith("no-store")
    text = r.content.decode("utf-8")
    assert text.startswith("﻿")
    lines = text.lstrip("﻿").strip().split("\r\n")
    assert lines[0].split(";")[:2] == ["Row", "Group admin"]
    admin_row = [l for l in lines if "Gina Group" in l][0]
    assert "20,00" in admin_row and "5,00" in admin_row and "15,00" in admin_row
    assert any(chair.short_name in l and "total" in l for l in lines[1:])
    assert "export.group_balances_csv" in actions()


def test_group_balances_csv_flags_negative_and_former(head, ga_id, alice):
    collect(ga_id, alice.id, 1000)
    remit(head, ga_id, "25")
    text = head[0].get("/admin/exports/group-balances.csv").content.decode()
    row = [l for l in text.split("\r\n") if "Gina Group" in l][0]
    assert "-15,00" in row and "more handed over than collected" in row  # signed numbers, flagged


def test_group_balances_csv_is_injection_safe(head, ga_id, alice):
    with write_session() as w:
        w.get(AdminUser, ga_id).user.display_name = "=HYPERLINK(\"http://evil\")"
    collect(ga_id, alice.id, 100)
    text = head[0].get("/admin/exports/group-balances.csv").content.decode()
    assert "'=HYPERLINK" in text
    for line in text.lstrip("﻿").split("\r\n")[1:]:
        for cell in line.split(";"):
            assert not cell.startswith(("=", "+", "@")), cell


def test_group_admin_csv_attempt_is_not_audited(ga_client):
    assert ga_client[0].get("/admin/exports/group-balances.csv", follow_redirects=False).status_code == 403
    assert "export.group_balances_csv" not in actions()


def test_exports_page_links_group_csv_for_head_only(head, ga_client):
    assert "group-balances.csv" in head[0].get("/admin/exports").text
    assert "group-balances.csv" not in ga_client[0].get("/admin/exports").text


# ----- page hygiene -------------------------------------------------------------------------------------------------
def test_pages_have_no_inline_script_or_style_and_forms_carry_csrf(head, ga_id, alice):
    collect(ga_id, alice.id, 1000)
    remit(head, ga_id, "3")
    for path in ("/admin/groups", f"/admin/users/{alice.id}"):
        html = head[0].get(path).text
        assert " style=" not in html and "onclick=" not in html
        assert "<script>" not in html
        posts = html.count('method="post"')
        assert posts == html.count('name="csrf_token"')
