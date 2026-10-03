"""ledger-audit: adversarial replay / idempotency / pending-action tests (real HTTP + threads)."""

from __future__ import annotations

import threading
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db import write_session
from app.models import PendingAction, User
from app.services import onboarding, pending, users
from app.services.sessions import SESSION_COOKIE
from app.timeutil import utcnow
from app.web import tokens
from tests import factories
from tests.user_support import event_id_from, events, field, pass_gate, post_scan, register, scan_token, select_profile


def run_threads(n, fn):
    barrier = threading.Barrier(n)
    results, errors = [], []

    def worker(i):
        barrier.wait()
        try:
            results.append(fn(i))
        except Exception as exc:  # noqa: BLE001 - collected for assertions
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    return results, errors


def coffees(db):
    return [e for e in events(db) if e.type in ("single", "double")]


# ----- replay after registration / after undo -------------------------------------------------
def test_replay_after_registration_returns_the_same_event(client, db, chair, price):
    token = scan_token(client, "double")
    assert post_scan(client, "double", token).headers["location"] == "/join"
    pass_gate(client)
    first = event_id_from(register(client, "Replay Person", chair))
    # The browser now has a session; the same scan token is posted again (Back + resubmit).
    again = post_scan(client, "double", token)
    assert event_id_from(again) == first
    assert len(events(db)) == 1


def test_replay_after_undo_does_not_resurrect_the_coffee(client, db, user, price, login):
    login(user)
    token = scan_token(client, "single")
    eid = event_id_from(post_scan(client, "single", token))
    page = client.get(f"/coffee/done/{eid}")
    r = client.post(f"/coffee/undo/{eid}", data={"csrf_token": field(page.text, "csrf_token")},
                    follow_redirects=False)
    assert r.status_code == 303
    assert event_id_from(post_scan(client, "single", token)) == eid
    evs = events(db)
    assert [e.type for e in evs] == ["single", "reversal"]
    assert sum(e.amount_cents for e in evs) == 0


def test_token_used_by_session_then_replayed_anonymously_creates_nothing(client, app, db, chair, user, price, login):
    login(user)
    token = scan_token(client, "single")
    eid = event_id_from(post_scan(client, "single", token))
    with TestClient(app, raise_server_exceptions=False) as anon:
        assert post_scan(anon, "single", token).headers["location"] == "/join"
        pass_gate(anon)
        r = register(anon, "Somebody Else", chair)
        assert r.status_code == 303 and "/coffee/done/" not in r.headers["location"]
        assert eid not in r.headers["location"]
    (only,) = events(db)
    assert str(only.id) == eid and only.user_id == user.id


def test_consumed_pending_replayed_in_another_browser_records_nothing(client, app, db, chair, user, price):
    token = scan_token(client, "single")
    post_scan(client, "single", token)
    pass_gate(client)
    event_id_from(register(client, "First", chair))
    with TestClient(app, raise_server_exceptions=False) as other:
        assert post_scan(other, "single", token).headers["location"] == "/join"
        pass_gate(other)
        r = select_profile(other, user)
        assert r.headers["location"] == "/account?notice=expired"
    assert len(events(db)) == 1 and events(db)[0].user_id != user.id


# ----- concurrency ----------------------------------------------------------------------------
def test_concurrent_http_posts_of_one_token_record_once(app, db, user, price, login, client):
    raw = login(user)
    token = scan_token(client, "double")

    def go(_):
        with TestClient(app, raise_server_exceptions=False) as c:
            c.cookies.set(SESSION_COOKIE, raw)
            r = c.post("/coffee/double", data={"token": token}, follow_redirects=False)
            return r.status_code, r.headers.get("location")

    results, errors = run_threads(6, go)
    assert not errors
    assert {status for status, _ in results} == {303}
    assert len({loc for _, loc in results}) == 1
    assert len(events(db)) == 1


def test_concurrent_consumers_of_one_pending_action_record_once(db, chair, price):
    profiles = [factories.make_user(db, f"P{i}", chair=chair) for i in range(6)]
    with write_session() as w:
        pid = pending.create_pending(w, "double", "x" * 32)

    def go(i):
        with write_session() as w:
            res = onboarding.select_profile_and_start_session(w, user_id=profiles[i].id, pending_id=pid)
            return res.coffee_status

    results, errors = run_threads(6, go)
    assert not errors
    assert sorted(results).count(onboarding.COFFEE_RECORDED) == 1
    assert len(events(db)) == 1


def test_concurrent_registration_with_one_token_creates_one_profile_and_coffee(db, chair, price):
    with write_session() as w:
        pid = pending.create_pending(w, "single", "y" * 32)
    nonce = "r" * 32

    def go(_):
        with write_session() as w:
            res = onboarding.register_and_start_session(w, display_name="Twin", chair_id=chair.id, pending_id=pid,
                                                        registration_nonce=nonce)
            return res.created, res.event.id if res.event else None

    results, errors = run_threads(6, go)
    assert not errors
    assert sum(created for created, _ in results) == 1
    assert len({eid for _, eid in results}) == 1  # every submit shows the same coffee
    db.rollback()
    assert len(list(db.scalars(select(User)))) == 1 and len(events(db)) == 1


def test_concurrent_registrations_sharing_a_pending_cookie_book_one_coffee(db, chair, price):
    with write_session() as w:
        pid = pending.create_pending(w, "double", "z" * 32)

    def go(i):
        with write_session() as w:
            return onboarding.register_and_start_session(w, display_name=f"Tab {i}", chair_id=chair.id,
                                                         pending_id=pid, registration_nonce=f"{i}" * 32).coffee_status

    results, errors = run_threads(4, go)
    assert not errors
    assert results.count(onboarding.COFFEE_RECORDED) == 1
    assert len(events(db)) == 1


# ----- deactivation between pending creation and selection -----------------------------------
def test_deactivated_between_pending_and_selection_keeps_pending_unconsumed(client, db, user, price, global_admin):
    post_scan(client, "single")
    pass_gate(client)
    csrf = field(client.get("/profiles").text, "csrf_token")
    with write_session() as w:
        users.set_user_status(w, admin=w.get(type(global_admin), global_admin.id), user_id=user.id, active=False)
    r = select_profile(client, user, csrf=csrf)
    assert r.status_code in (403, 404, 409)
    db.rollback()
    assert events(db) == [] and db.scalars(select(PendingAction)).one().consumed_at is None


# ----- token tampering -----------------------------------------------------------------------
def test_scan_token_for_other_kind_or_purpose_rejected(client, db, user, price, login):
    login(user)
    assert post_scan(client, "double", scan_token(client, "single")).status_code == 400
    assert post_scan(client, "single", tokens.make_registration_token()).status_code == 400
    old = tokens.make_scan_token("single", now=utcnow() - timedelta(minutes=30, seconds=2))
    assert post_scan(client, "single", old).status_code == 400
    assert events(db) == []


@pytest.mark.xfail(strict=True, reason="BUG: signing.unsign/verify_csrf pass non-ASCII str to hmac.compare_digest "
                                       "-> TypeError -> 500 instead of a 400 rejection")
def test_non_ascii_scan_token_signature_is_rejected_not_500(client, db, user, price, login):
    login(user)
    raw, _sig = scan_token(client, "single").split(".")
    r = post_scan(client, "single", f"{raw}.é")
    assert r.status_code == 400
    assert events(db) == []


@pytest.mark.xfail(strict=True, reason="BUG: verify_csrf passes non-ASCII token to hmac.compare_digest -> 500")
def test_non_ascii_csrf_token_on_undo_is_rejected_not_500(client, db, user, price, login):
    login(user)
    eid = event_id_from(post_scan(client, "single"))
    r = client.post(f"/coffee/undo/{eid}", data={"csrf_token": "é" * 10}, follow_redirects=False)
    assert r.status_code in (400, 403)
    assert len(events(db)) == 1
