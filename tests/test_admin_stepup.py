"""Step-up for balance-changing admin actions (task 4.2): two-step confirm flow, signed payload, one-time
nonce, step-up window, TOTP / recovery codes, enforcement in the dependency, audit."""

from __future__ import annotations

import base64
import json
import threading
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from app.db import read_session, write_session
from app.models import (
    AdminSession, AdminUser, AuditLog, ConsumptionEvent, PaymentEvent, UsedNonce, User,
)
from app.money import format_money
from app.services import admin_auth, ledger, stepup
from app.timeutil import utcnow
from tests import factories
from tests.admin_support import (  # noqa: F401
    CONFIRM_PATH, confirm, confirm_fields, current_code, fast_hasher, login_as, make_real_admin, new_client, submit,
)
from tests.conftest import reload_settings


@pytest.fixture
def required(monkeypatch):
    """BALANCE_TOTP_REQUIRED on (as in production)."""
    monkeypatch.setenv("BALANCE_TOTP_REQUIRED", "true")
    reload_settings()


@pytest.fixture
def alice(db, chair, price):
    return factories.make_user(db, "Alice Müller", chair)


@pytest.fixture
def boss(app, required):
    admin_id, secret = make_real_admin(username="boss")
    c = new_client(app)
    return {"id": admin_id, "secret": secret, "client": c, "csrf": login_as(c, admin_id)}


@pytest.fixture
def group(app, required, chair):
    admin_id, secret = make_real_admin(role="chair", chairs=[chair], username="grp")
    c = new_client(app)
    return {"id": admin_id, "secret": secret, "client": c, "csrf": login_as(c, admin_id)}


def count(model):
    with read_session() as r:
        return r.scalar(select(func.count()).select_from(model))


def audit_rows(action=None):
    with read_session() as r:
        q = select(AuditLog).order_by(AuditLog.id)
        if action:
            q = q.where(AuditLog.action == action)
        rows = list(r.scalars(q))
        r.expunge_all()
        return rows


def session_of(admin_id) -> AdminSession:
    with read_session() as r:
        found = r.scalars(select(AdminSession).where(AdminSession.admin_id == admin_id)
                          .order_by(AdminSession.created_at.desc())).first()
        r.expunge_all()
        return found


def set_window(admin_id, until):
    with write_session() as w:
        for s in w.scalars(select(AdminSession).where(AdminSession.admin_id == admin_id)):
            s.stepup_until = until


def preview(who, path, **data):
    return who["client"].post(path, data={"csrf_token": who["csrf"], **data}, follow_redirects=False)


def pay_preview(who, user, amount="3,00", **data):
    return preview(who, f"/admin/users/{user.id}/payment", amount=amount, **data)


def snapshot_counts():
    return (count(PaymentEvent), count(ConsumptionEvent), count(UsedNonce), count(AuditLog))


# ----- the confirm page is read-only ------------------------------------------------------------
def test_preview_shows_details_and_writes_nothing(boss, db, alice):
    factories.add_events(db, alice, ["single", "single"])  # balance: owes 1.00
    before = snapshot_counts()
    r = pay_preview(boss, alice, "3,00", note="cash box")
    assert r.status_code == 200
    page = r.text
    assert "Alice Müller" in page and "CHA" in page and "Record payment" in page and "cash box" in page
    assert format_money(3_00) in page
    assert format_money(100) in page            # balance now: owes 1.00
    assert format_money(-200) in page           # balance afterwards: credit 2.00
    fields = confirm_fields(page)
    assert fields["payload"] and fields["nonce"]
    assert 'name="code"' in page                # window closed and TOTP required: the code field is shown
    assert snapshot_counts() == before          # nothing persisted, not even an audit entry
    assert r.headers["cache-control"] == "no-store"


def test_preview_of_each_action_reports_the_resulting_balance(boss, db, alice, chair):
    events = factories.add_events(db, alice, ["double"])
    dup = factories.make_user(db, "Alice Two", chair)
    factories.add_events(db, dup, ["single"])
    r = preview(boss, f"/admin/users/{alice.id}/adjustment", quantity="2", amount="")
    assert "Consumption adjustment" in r.text and format_money(200) in r.text  # 100 now, +100 -> 200
    r = preview(boss, f"/admin/users/{alice.id}/events/{events[0].id}/reverse", note="oops")
    assert "Reverse event" in r.text and format_money(0) in r.text
    r = preview(boss, f"/admin/users/{dup.id}/merge", target_id=str(alice.id))
    assert "Merge profiles" in r.text and "Alice Müller (CHA)" in r.text and format_money(150) in r.text
    with read_session() as r2:
        assert r2.get(User, dup.id).status == "active"       # still not merged
    assert count(UsedNonce) == 0 and count(PaymentEvent) == 0


def test_preview_errors_go_back_to_the_form_and_book_nothing(boss, alice):
    before = snapshot_counts()
    for data in ({"amount": "abc"}, {"amount": "0"}, {"amount": "1,234"}):
        r = pay_preview(boss, alice, **data)
        assert r.status_code == 303 and "err=invalid_amount" in r.headers["location"]
    assert snapshot_counts() == before


# ----- enforcement: nothing happens without a valid payload and authorisation -------------------------
def test_confirm_without_payload_or_with_garbage_books_nothing(boss, alice):
    for data in ({}, {"payload": "x", "nonce": "y"}, {"payload": "a.b", "nonce": ""}):
        r = boss["client"].post(CONFIRM_PATH, data={"csrf_token": boss["csrf"], **data}, follow_redirects=False)
        assert r.status_code == 400
    assert count(PaymentEvent) == 0 and count(UsedNonce) == 0


def test_confirm_requires_csrf(boss, alice):
    html = pay_preview(boss, alice).text
    data = confirm_fields(html) | {"code": current_code(boss["secret"])}
    for token in (None, "bogus"):
        d = {k: v for k, v in data.items() if k != "csrf_token"} | ({"csrf_token": token} if token else {})
        assert boss["client"].post(CONFIRM_PATH, data=d, follow_redirects=False).status_code == 403
    assert count(PaymentEvent) == 0


def test_no_code_while_window_is_closed_shows_the_prompt_and_books_nothing(boss, alice):
    html = pay_preview(boss, alice).text
    r = confirm(boss["client"], html)
    assert r.status_code == 200 and 'name="code"' in r.text and "Please enter a code" in r.text
    assert count(PaymentEvent) == 0 and count(UsedNonce) == 0
    assert session_of(boss["id"]).stepup_until is None


def test_wrong_code_is_rejected_audited_and_rate_limited(boss, alice):
    html = pay_preview(boss, alice).text
    wrong = "000000" if current_code(boss["secret"]) != "000000" else "111111"
    for _ in range(5):
        r = confirm(boss["client"], html, code=wrong)
        assert r.status_code == 401 and "not correct" in r.text
    assert count(PaymentEvent) == 0 and session_of(boss["id"]).stepup_until is None
    assert len(audit_rows("admin.stepup.failed")) == 5
    # the limiter now blocks even the correct code
    r = confirm(boss["client"], html, code=current_code(boss["secret"]))
    assert r.status_code == 429 and count(PaymentEvent) == 0
    assert all(wrong not in json.dumps(a.meta or {}) for a in audit_rows())


def test_correct_code_books_and_opens_a_fixed_window(boss, db, alice):
    html = pay_preview(boss, alice, "3,00").text
    before = utcnow()
    r = confirm(boss["client"], html, code=current_code(boss["secret"]))
    assert r.status_code == 303 and r.headers["location"] == f"/admin/users/{alice.id}?msg=payment_recorded"
    with read_session() as s:
        assert ledger.get_totals(s, alice.id).paid_amount_cents == 300
    first_until = session_of(boss["id"]).stepup_until
    assert 299 <= (first_until - before).total_seconds() <= 302
    # a second action in a row needs no code; the window is NOT extended
    html2 = preview(boss, f"/admin/users/{alice.id}/adjustment", quantity="1", amount="").text
    assert 'name="code"' not in html2
    r2 = confirm(boss["client"], html2)
    assert r2.status_code == 303 and "msg=adjustment_recorded" in r2.headers["location"]
    assert session_of(boss["id"]).stepup_until == first_until
    vias = [a.meta["authorised_by"] for a in audit_rows("stepup.executed")]
    assert vias == ["totp", "window"]
    assert len(audit_rows("admin.stepup.opened")) == 1


def test_window_expiry_asks_for_a_code_again(boss, alice):
    set_window(boss["id"], utcnow() + timedelta(seconds=120))
    html = pay_preview(boss, alice).text
    assert 'name="code"' not in html
    set_window(boss["id"], utcnow() - timedelta(seconds=1))  # expires between preview and confirm
    r = confirm(boss["client"], html)
    assert r.status_code == 200 and 'name="code"' in r.text and count(PaymentEvent) == 0
    r = confirm(boss["client"], html, code=current_code(boss["secret"], 1))
    assert r.status_code == 303 and count(PaymentEvent) == 1


def test_totp_replay_within_120_seconds_is_rejected(boss, alice):
    code = current_code(boss["secret"])
    r = confirm(boss["client"], pay_preview(boss, alice).text, code=code)
    assert r.status_code == 303
    set_window(boss["id"], None)                      # window closed again
    r = confirm(boss["client"], pay_preview(boss, alice, "1").text, code=code)
    assert r.status_code == 401 and count(PaymentEvent) == 1
    r = confirm(boss["client"], pay_preview(boss, alice, "1").text, code=current_code(boss["secret"], 1))
    assert r.status_code == 303 and count(PaymentEvent) == 2


def test_window_already_open_does_not_consume_a_supplied_code(boss, alice):
    set_window(boss["id"], utcnow() + timedelta(seconds=200))
    code = current_code(boss["secret"])
    r = confirm(boss["client"], pay_preview(boss, alice).text, code=code)
    assert r.status_code == 303
    assert audit_rows("admin.stepup.opened") == [] and audit_rows("admin.stepup.failed") == []
    assert [a.meta["authorised_by"] for a in audit_rows("stepup.executed")] == ["window"]


# ----- recovery codes ---------------------------------------------------------------------------------
def give_recovery_codes(admin_id, codes):
    with write_session() as w:
        w.get(AdminUser, admin_id).recovery_codes = [admin_auth._recovery_hash(c) for c in codes]


def test_recovery_code_authorises_once_only(boss, alice):
    give_recovery_codes(boss["id"], ["ABCD-EFGH-JKLM", "NPQR-STUV-WXYZ"])
    r = confirm(boss["client"], pay_preview(boss, alice).text, code="abcd-efgh-jklm")
    assert r.status_code == 303 and count(PaymentEvent) == 1
    assert [a.meta["authorised_by"] for a in audit_rows("stepup.executed")] == ["recovery_code"]
    assert audit_rows("admin.stepup.opened")[0].meta["recovery_codes_left"] == 1
    set_window(boss["id"], None)
    r = confirm(boss["client"], pay_preview(boss, alice, "1").text, code="ABCD-EFGH-JKLM")
    assert r.status_code == 401 and count(PaymentEvent) == 1                     # used up
    r = confirm(boss["client"], pay_preview(boss, alice, "1").text, code="NPQR-STUV-WXYZ")
    assert r.status_code == 303 and count(PaymentEvent) == 2
    assert "ABCD" not in json.dumps([a.meta for a in audit_rows()])


def test_recovery_code_single_use_under_concurrency(app, required):
    """The same recovery code raced by several sessions of one admin opens at most one window."""
    admin_id, _ = make_real_admin(username="racer")
    give_recovery_codes(admin_id, ["RACE-RACE-RACE"])
    with write_session() as w:
        admin = w.get(AdminUser, admin_id)
        session_ids = [admin_auth._new_session(w, admin, now=utcnow())[0].id for _ in range(6)]
        w.expunge(admin)
    barrier = threading.Barrier(len(session_ids))
    results: list[str] = []

    def attempt(sid):
        barrier.wait()
        with write_session() as w:
            results.append(admin_auth.open_stepup(w, session_id=sid, admin=admin, code="RACE-RACE-RACE", ip="203.0.113.5"))

    threads = [threading.Thread(target=attempt, args=(sid,)) for sid in session_ids]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(results) == ["invalid"] * 5 + ["recovery_code"]
    with read_session() as r:
        assert r.get(AdminUser, admin_id).recovery_codes == []
        opened = [s for s in r.scalars(select(AdminSession).where(AdminSession.admin_id == admin_id)) if s.stepup_until]
        assert len(opened) == 1


def test_recovery_code_single_use_under_concurrency_over_http(app, required, db, alice):
    admin_id, _ = make_real_admin(username="racer2")
    give_recovery_codes(admin_id, ["HTTP-RACE-CODE"])
    clients = []
    for _ in range(4):
        c = new_client(app)
        clients.append({"client": c, "csrf": login_as(c, admin_id)})
    pages = [pay_preview(who, alice, "1").text for who in clients]
    barrier = threading.Barrier(len(clients))
    statuses: list[int] = []

    def go(who, page):
        barrier.wait()
        statuses.append(confirm(who["client"], page, code="HTTP-RACE-CODE").status_code)

    threads = [threading.Thread(target=go, args=(w, p)) for w, p in zip(clients, pages)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(statuses) == [303, 401, 401, 401]
    assert count(PaymentEvent) == 1


# ----- the signed payload -----------------------------------------------------------------------------
def split_payload(token):
    raw, sig = token.split(".")
    return json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))), raw, sig


def b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()).rstrip(b"=").decode()


@pytest.mark.parametrize("field,value", [
    ("k", "adjustment"), ("n", "other-nonce"), ("a", "00000000-0000-0000-0000-000000000000"),
    ("s", "00000000-0000-0000-0000-000000000000"), ("iat", 1), ("v", 2), ("p", {"user_id": "x", "amount_cents": 1}),
])
def test_tampering_with_any_payload_field_is_rejected(field, value, boss, alice):
    html = pay_preview(boss, alice).text
    fields = confirm_fields(html)
    body, raw, sig = split_payload(fields["payload"])
    body[field] = value
    forged = f"{b64(body)}.{sig}"                      # new content, old signature
    r = confirm(boss["client"], html, code=current_code(boss["secret"]), payload=forged)
    assert r.status_code == 400
    assert count(PaymentEvent) == 0 and count(UsedNonce) == 0 and session_of(boss["id"]).stepup_until is None
    assert audit_rows("stepup.rejected")[-1].meta["reason"] in ("signature", "malformed")


def test_tampering_with_params_inside_the_payload_is_rejected(boss, alice):
    html = pay_preview(boss, alice, "1").text
    body, raw, sig = split_payload(confirm_fields(html)["payload"])
    body["p"]["amount_cents"] = 100000
    r = confirm(boss["client"], html, code=current_code(boss["secret"]), payload=f"{b64(body)}.{sig}")
    assert r.status_code == 400 and count(PaymentEvent) == 0


def test_signature_and_nonce_field_must_match(boss, alice):
    html = pay_preview(boss, alice).text
    f = confirm_fields(html)
    for override in ({"payload": f["payload"][:-3] + "AAA"}, {"payload": f["payload"].split(".")[0]},
                     {"nonce": f["nonce"] + "x"}, {"nonce": ""}, {"payload": ""}):
        r = confirm(boss["client"], html, code=current_code(boss["secret"]), **override)
        assert r.status_code == 400, override
    assert count(PaymentEvent) == 0 and session_of(boss["id"]).stepup_until is None
    assert audit_rows("stepup.rejected")


def test_payload_is_valid_for_ten_minutes_only(boss, alice):
    html = pay_preview(boss, alice).text
    body, _, _ = split_payload(confirm_fields(html)["payload"])
    old = stepup.sign_payload(kind="payment", params=body["p"], nonce="n" * 22, admin_id=boss["id"],
                              session_id=body["s"], now=utcnow() - timedelta(seconds=601))
    fresh = stepup.sign_payload(kind="payment", params=body["p"], nonce="m" * 22, admin_id=boss["id"],
                                session_id=body["s"], now=utcnow() - timedelta(seconds=590))
    r = confirm(boss["client"], html, code=current_code(boss["secret"]), payload=old, nonce="n" * 22)
    assert r.status_code == 400 and count(PaymentEvent) == 0
    r = confirm(boss["client"], html, code=current_code(boss["secret"], 1), payload=fresh, nonce="m" * 22)
    assert r.status_code == 303 and count(PaymentEvent) == 1
    with pytest.raises(stepup.PayloadInvalid):
        stepup.verify_payload(fresh, now=utcnow() + timedelta(seconds=30))
    with pytest.raises(stepup.PayloadInvalid):  # issued in the future
        stepup.verify_payload(stepup.sign_payload(kind="payment", params={}, nonce="x", admin_id="a", session_id="s",
                                                  now=utcnow() + timedelta(hours=1)))


def test_payload_is_bound_to_the_admin_and_the_session(app, boss, alice):
    html = pay_preview(boss, alice).text
    other_id, other_secret = make_real_admin(username="other")
    other = new_client(app)
    other_csrf = login_as(other, other_id)
    r = other.post(CONFIRM_PATH, data=confirm_fields(html) | {"csrf_token": other_csrf,
                                                              "code": current_code(other_secret)},
                   follow_redirects=False)
    assert r.status_code == 400
    second_session = new_client(app)                   # same admin, another session
    csrf2 = login_as(second_session, boss["id"])
    r = second_session.post(CONFIRM_PATH, data=confirm_fields(html) | {"csrf_token": csrf2,
                                                                       "code": current_code(boss["secret"])},
                            follow_redirects=False)
    assert r.status_code == 400 and count(PaymentEvent) == 0


def test_payload_key_is_derived_with_the_stepup_label(boss, alice, monkeypatch):
    html = pay_preview(boss, alice).text
    token = confirm_fields(html)["payload"]
    assert stepup.verify_payload(token).kind == "payment"
    monkeypatch.setenv("SECRET_KEY", "another-secret-key-0123456789abcdef0123456789")
    reload_settings()
    with pytest.raises(stepup.PayloadInvalid):
        stepup.verify_payload(token)


# ----- one-time nonce / double submit -----------------------------------------------------------------
def test_double_submit_books_once(boss, alice):
    html = pay_preview(boss, alice, "3,00").text
    f = confirm_fields(html)
    r1 = confirm(boss["client"], html, code=current_code(boss["secret"]))
    r2 = confirm(boss["client"], html)
    assert r1.status_code == 303 and "msg=payment_recorded" in r1.headers["location"]
    assert r2.status_code == 303 and "msg=already_executed" in r2.headers["location"]
    assert count(PaymentEvent) == 1 and count(UsedNonce) == 1
    with read_session() as r:
        pay = r.scalars(select(PaymentEvent)).one()
        assert pay.idempotency_key == stepup.idempotency_key_for(f["nonce"]) and pay.amount_cents == 300
        assert r.scalars(select(UsedNonce)).one().nonce == f["nonce"]
    assert len(audit_rows("payment.recorded")) == 1 and len(audit_rows("stepup.executed")) == 1


def test_concurrent_double_submit_books_once(app, boss, alice):
    set_window(boss["id"], utcnow() + timedelta(seconds=250))
    html = pay_preview(boss, alice).text
    twin = new_client(app)
    twin.cookies.update(boss["client"].cookies)
    barrier = threading.Barrier(2)
    out: list[str] = []

    def go(c):
        barrier.wait()
        out.append(confirm(c, html).headers["location"])

    threads = [threading.Thread(target=go, args=(c,)) for c in (boss["client"], twin)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted("already_executed" in x for x in out) == [False, True]
    assert count(PaymentEvent) == 1 and count(UsedNonce) == 1


def test_a_failed_action_does_not_consume_the_nonce(boss, db, alice):
    (event,) = factories.add_events(db, alice, ["single"])
    html = preview(boss, f"/admin/users/{alice.id}/events/{event.id}/reverse").text
    with write_session() as w:                                  # someone reverses it in the meantime
        ledger.admin_reverse_event(w, admin=w.get(AdminUser, boss["id"]), event_id=event.id)
    set_window(boss["id"], utcnow() + timedelta(seconds=200))
    r = confirm(boss["client"], html)
    assert r.status_code == 303 and "err=already_reversed" in r.headers["location"]
    assert count(UsedNonce) == 0 and count(ConsumptionEvent) == 2


def test_each_preview_gets_its_own_nonce(boss, alice):
    a = confirm_fields(pay_preview(boss, alice).text)
    b = confirm_fields(pay_preview(boss, alice).text)
    assert a["nonce"] != b["nonce"] and a["payload"] != b["payload"]


# ----- every action goes through the flow -------------------------------------------------------------
def test_every_action_kind_executes_only_through_confirm_and_is_audited(boss, db, alice, chair):
    events = factories.add_events(db, alice, ["single", "double"])
    dup = factories.make_user(db, "Alice Two", chair)
    set_window(boss["id"], utcnow() + timedelta(seconds=250))
    # entry steps alone book nothing
    pay = pay_preview(boss, alice, "2")
    adj = preview(boss, f"/admin/users/{alice.id}/adjustment", quantity="1", amount="0,40")
    rev = preview(boss, f"/admin/users/{alice.id}/events/{events[0].id}/reverse")
    mrg = preview(boss, f"/admin/users/{dup.id}/merge", target_id=str(alice.id))
    assert (count(PaymentEvent), count(ConsumptionEvent), count(UsedNonce)) == (0, 2, 0)
    for page, flash in ((pay, "payment_recorded"), (adj, "adjustment_recorded"), (rev, "event_reversed"),
                        (mrg, "merged")):
        r = confirm(boss["client"], page.text)
        assert r.status_code == 303 and f"msg={flash}" in r.headers["location"]
    assert count(UsedNonce) == 4
    executed = audit_rows("stepup.executed")
    assert [a.meta["kind"] for a in executed] == ["payment", "adjustment", "reversal", "merge"]
    assert all(a.meta["authorised_by"] == "window" and a.actor_id == str(boss["id"]) for a in executed)
    with read_session() as r:
        assert r.get(User, dup.id).status == "merged"
    assert {"payment.recorded", "event.adjustment", "event.reversed", "user.merged"} <= {a.action for a in audit_rows()}


def test_correction_goes_through_the_flow_and_keeps_collector(boss, db, alice):
    set_window(boss["id"], utcnow() + timedelta(seconds=250))
    confirm(boss["client"], pay_preview(boss, alice, "5").text)
    with read_session() as r:
        original = r.scalars(select(PaymentEvent)).one()
        r.expunge_all()
    r = confirm(boss["client"], pay_preview(boss, alice, "-1", correction_of=str(original.id)).text)
    assert r.status_code == 303 and "msg=payment_recorded" in r.headers["location"]
    with read_session() as r2:
        corr = r2.scalars(select(PaymentEvent).where(PaymentEvent.correction_of_id == original.id)).one()
        assert corr.collector_admin_id == original.collector_admin_id
    assert [a.meta["amount_cents"] for a in audit_rows("stepup.executed")] == [500, -100]


# ----- scope and ledger rules still apply -------------------------------------------------------------
def test_group_admin_scope_is_enforced_at_both_steps(group, db, alice, other_chair):
    bob = factories.make_user(db, "Bob", other_chair)
    assert pay_preview(group, bob).status_code == 403                       # entry step
    html = pay_preview(group, alice).text
    set_window(group["id"], utcnow() + timedelta(seconds=250))
    with write_session() as w:                                              # Alice leaves the group admin's chair
        w.get(User, alice.id).chair_id = other_chair.id
    r = confirm(group["client"], html)
    assert r.status_code == 403 and count(PaymentEvent) == 0 and count(UsedNonce) == 0
    set_window(group["id"], utcnow() + timedelta(seconds=250))
    assert preview(group, f"/admin/users/{alice.id}/merge", target_id=str(alice.id)).status_code == 403


def test_group_admin_own_balance_rule_applies(group, db):
    with read_session() as r:
        own = r.get(AdminUser, group["id"]).user_id
    r = group["client"].post(f"/admin/users/{own}/payment", data={"csrf_token": group["csrf"], "amount": "5"},
                             follow_redirects=False)
    assert r.status_code == 403 and count(PaymentEvent) == 0


def test_group_admin_can_book_in_scope_with_a_code(group, alice):
    r = confirm(group["client"], pay_preview(group, alice, "4").text, code=current_code(group["secret"]))
    assert r.status_code == 303 and count(PaymentEvent) == 1
    with read_session() as s:
        pay = s.scalars(select(PaymentEvent)).one()
        assert pay.collector_admin_id == group["id"]


def test_merge_confirm_is_head_admin_only(group, db, alice, chair):
    dup = factories.make_user(db, "Alice Two", chair)
    assert preview(group, f"/admin/users/{dup.id}/merge", target_id=str(alice.id)).status_code == 403


# ----- BALANCE_TOTP_REQUIRED = false (development) ----------------------------------------------------
def test_without_totp_requirement_the_prompt_is_skipped_but_the_flow_stays(app, alice):
    admin_id, _ = make_real_admin(username="dev")
    c = new_client(app)
    who = {"client": c, "csrf": login_as(c, admin_id), "id": admin_id}
    page = pay_preview(who, alice).text
    assert 'name="code"' not in page and confirm_fields(page)["payload"]
    assert preview_status_without_payload(who) == 400
    r = confirm(c, page)
    assert r.status_code == 303 and count(PaymentEvent) == 1
    assert confirm(c, page).headers["location"].endswith("msg=already_executed") and count(PaymentEvent) == 1
    assert audit_rows("stepup.executed")[0].meta["authorised_by"] == "not_required"
    assert session_of(admin_id).stepup_until is None


def preview_status_without_payload(who):
    return who["client"].post(CONFIRM_PATH, data={"csrf_token": who["csrf"]}, follow_redirects=False).status_code


# ----- misc -------------------------------------------------------------------------------------------
def test_revoked_session_during_confirmation_redirects_to_login(boss, alice):
    html = pay_preview(boss, alice).text
    with write_session() as w:
        for s in w.scalars(select(AdminSession)):
            s.revoked_at = utcnow()
    r = confirm(boss["client"], html, code=current_code(boss["secret"]))
    assert r.status_code == 303 and r.headers["location"] == "/admin/login" and count(PaymentEvent) == 0


def test_run_refuses_a_grant_that_authorise_did_not_issue(boss, alice):
    forged = stepup.StepupGrant(admin=None, action=stepup.REGISTRY["payment"], params={}, nonce="n",
                                authorised_by="window")
    with write_session() as w, pytest.raises(PermissionError):
        stepup.run(w, forged)
    assert count(UsedNonce) == 0


def test_stepup_window_setting_is_used(boss, alice, monkeypatch):
    monkeypatch.setenv("STEPUP_WINDOW_SECONDS", "60")
    reload_settings()
    before = utcnow()
    confirm(boss["client"], pay_preview(boss, alice).text, code=current_code(boss["secret"]))
    assert 58 <= (session_of(boss["id"]).stepup_until - before).total_seconds() <= 62
