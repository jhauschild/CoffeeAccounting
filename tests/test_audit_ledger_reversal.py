"""ledger-audit: reversal races and reversal edge cases (service level + HTTP)."""

from __future__ import annotations

import threading

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.db import write_session
from app.models import AdminUser, ConsumptionEvent
from app.services import ledger, sessions, users
from app.services.checker import check_ledger
from app.services.errors import AlreadyReversed, Conflict, UndoNotAllowed
from app.timeutil import utcnow
from tests import factories
from tests.admin_support import fast_hasher, login_as, make_real_admin, submit  # noqa: F401
from tests.user_support import event_id_from, events, field, make_account, post_scan, sign_in


def run_threads(fns):
    barrier = threading.Barrier(len(fns))
    results, errors = [], []

    def worker(fn):
        barrier.wait()
        try:
            results.append(fn())
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(fn,)) for fn in fns]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    return results, errors


def reversals(db, original_id=None):
    db.rollback()
    q = select(func.count()).select_from(ConsumptionEvent).where(ConsumptionEvent.type == "reversal")
    if original_id is not None:
        q = q.where(ConsumptionEvent.reversal_of_id == original_id)
    return db.scalar(q)


def _undo_csrf(client, eid):
    return field(client.get(f"/coffee/done/{eid}").text, "csrf_token")


# ----- races -----------------------------------------------------------------------------------
def test_concurrent_user_undo_and_admin_reverse_produce_one_reversal(db, user, price, global_admin):
    session = factories.make_session(db, user)
    (event,) = factories.add_events(db, user, "double", session_id=session.id)

    def undo():
        with write_session() as w:
            return ledger.undo_coffee(w, user_id=user.id, session_id=session.id, event_id=event.id).id

    def reverse():
        with write_session() as w:
            return ledger.admin_reverse_event(w, admin=w.get(AdminUser, global_admin.id), event_id=event.id).id

    for _ in range(3):  # several rounds on fresh events to vary the interleaving
        results, errors = run_threads([undo, reverse, undo, reverse])
        assert len(results) == 1 and all(isinstance(e, AlreadyReversed) for e in errors), errors
        assert reversals(db, event.id) == 1, r.headers["location"]
        (event,) = factories.add_events(db, user, "double", session_id=session.id)
    assert check_ledger(db).ok


# ----- reversal shapes -------------------------------------------------------------------------
def test_reversal_of_overridden_adjustment_negates_exactly(db, user, price, global_admin):
    adj = ledger.add_adjustment(db, admin=global_admin, user_id=user.id, quantity=3, amount_cents=17)
    factories.set_price(db, 90, effective_from=utcnow())  # price changes before the reversal
    rev = ledger.admin_reverse_event(db, admin=global_admin, event_id=adj.id)
    assert (rev.quantity, rev.amount_cents, rev.unit_price_cents) == (-3, -17, adj.unit_price_cents)
    db.commit()
    assert ledger.get_totals(db, user.id).balance_cents == 0 and check_ledger(db).ok


def test_zero_amount_adjustment_can_be_reversed(db, user, price, global_admin):
    adj = ledger.add_adjustment(db, admin=global_admin, user_id=user.id, quantity=2, amount_cents=0,
                                note="free coffees")
    rev = ledger.admin_reverse_event(db, admin=global_admin, event_id=adj.id)
    assert (rev.quantity, rev.amount_cents) == (-2, 0)


def test_a_reversal_cannot_be_reversed_by_admin_or_user(db, user, price, global_admin):
    session = factories.make_session(db, user)
    (event,) = factories.add_events(db, user, "single", session_id=session.id)
    rev = ledger.undo_coffee(db, user_id=user.id, session_id=session.id, event_id=event.id)
    with pytest.raises(Conflict):
        ledger.admin_reverse_event(db, admin=global_admin, event_id=rev.id)
    with pytest.raises(UndoNotAllowed):
        ledger.undo_coffee(db, user_id=user.id, session_id=session.id, event_id=rev.id)
    assert reversals(db) == 0  # nothing committed; no reversal of a reversal anywhere


# ----- admin route: event must belong to the profile in the URL -------------------------------
def test_admin_reverse_route_rejects_event_of_other_user(app, db, chair, other_chair, price):
    alice = factories.make_user(db, "Alice", chair=chair)
    bob = factories.make_user(db, "Bob", chair=other_chair)
    (bob_event,) = factories.add_events(db, bob, "single")
    admin_id, _ = make_real_admin(role="chair", chairs=[chair], username="chairadmin")
    with TestClient(app, raise_server_exceptions=False) as c:
        csrf = login_as(c, admin_id)
        assert c.get(f"/admin/users/{alice.id}").status_code == 200  # logged in and in scope
        r = c.post(f"/admin/users/{alice.id}/events/{bob_event.id}/reverse", data={"csrf_token": csrf},
                   follow_redirects=False)
        assert r.status_code in (303, 404) and "/admin/login" not in r.headers.get("location", "")
    assert reversals(db) == 0


def test_admin_can_reverse_merged_duplicates_event_from_target_page(app, db, chair, price, global_admin):
    dup = factories.make_user(db, "Dup", chair=chair)
    target = factories.make_user(db, "Target", chair=chair)
    (event,) = factories.add_events(db, dup, "double")
    users.merge_users(db, admin=global_admin, duplicate_id=dup.id, target_id=target.id)
    db.commit()
    admin_id, _ = make_real_admin(username="boss")
    with TestClient(app, raise_server_exceptions=False) as c:
        csrf = login_as(c, admin_id)
        r = submit(c, csrf, f"/admin/users/{target.id}/events/{event.id}/reverse")
        assert r.status_code == 303 and "err=" not in r.headers["location"], r.headers["location"]
    assert reversals(db, event.id) == 1, r.headers["location"]
    db.rollback()
    assert ledger.get_totals(db, target.id).consumed_amount_cents == 0


# ----- user undo after the session changed ----------------------------------------------------
def test_undo_after_session_rotation_is_refused(client, db, chair, price):
    account = make_account(db, "Rotating", chair)
    sign_in(client, account)
    eid = event_id_from(post_scan(client, "single"))
    sign_in(client, account)  # same person signs in again: new session, old one revoked
    page = client.get(f"/coffee/done/{eid}")
    assert page.status_code == 200 and 'action="/coffee/undo/' not in page.text  # undo no longer offered
    csrf_new = field(client.get("/account/edit").text, "csrf_token")  # valid CSRF of the new session
    r = client.post(f"/coffee/undo/{eid}", data={"csrf_token": csrf_new}, follow_redirects=False)
    assert r.status_code in (303, 400, 403, 409)
    assert reversals(db) == 0


def test_undo_from_merged_profiles_old_session_is_refused(client, db, chair, user, price, login, global_admin):
    login(user)
    eid = event_id_from(post_scan(client, "single"))
    csrf = _undo_csrf(client, eid)
    target = factories.make_user(db, "Target", chair=chair)
    with write_session() as w:
        users.merge_users(w, admin=w.get(AdminUser, global_admin.id), duplicate_id=user.id, target_id=target.id)
    r = client.post(f"/coffee/undo/{eid}", data={"csrf_token": csrf}, follow_redirects=False)
    assert r.status_code in (303, 403)
    assert reversals(db) == 0


def test_undo_after_admin_revoked_sessions_is_refused(client, db, user, price, login):
    login(user)
    eid = event_id_from(post_scan(client, "single"))
    csrf = _undo_csrf(client, eid)
    with write_session() as w:
        sessions.revoke_user_sessions(w, user.id)
    r = client.post(f"/coffee/undo/{eid}", data={"csrf_token": csrf}, follow_redirects=False)
    assert r.status_code in (303, 403)
    assert reversals(db) == 0 and len(events(db)) == 1


def test_check_violation_is_not_reported_as_already_reversed(db, user, price):
    from sqlalchemy.exc import IntegrityError
    session = factories.make_session(db, user)
    (event,) = factories.add_events(db, user, "single", session_id=session.id)
    bad = ledger._make_reversal(event, now=event.created_at)
    bad.quantity = 1  # violates reversal_shape / signs_agree: a CHECK, not a unique conflict
    with pytest.raises(IntegrityError):
        ledger._insert_reversal(db, bad)
