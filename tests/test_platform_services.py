"""core-b: sessions, pending actions, onboarding, gate, rate limiting, signing."""

from __future__ import annotations

import threading
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from app.db import read_session, write_session
from app.models import ConsumptionEvent, PendingAction, RateLimitEvent, User, UserSession
from app.services import gate, onboarding, pending, ratelimit, sessions, signing
from app.services.errors import InvalidInput, NotFound, RateLimited, UserInactive
from app.services.ledger import record_coffee
from app.services.users import merge_users, set_user_status
from app.timeutil import utcnow
from tests import factories
from tests.conftest import reload_settings


def count(model, *where):
    with read_session() as db:
        return db.scalar(select(func.count()).select_from(model).where(*where))


# ----- sessions -------------------------------------------------------------------------------
def test_issue_stores_only_hash_and_resolves(user):
    with write_session() as db:
        raw = sessions.issue_session(db, user.id)
    assert len(raw) >= 43
    with read_session() as db:
        row = db.scalars(select(UserSession)).one()
        assert row.token_hash == sessions.hash_token(raw) and raw not in row.token_hash
        assert row.expires_at - row.created_at == timedelta(days=180)
        sess, u = sessions.resolve_session(db, raw, touch=False)
        assert u.id == user.id and sess.id == row.id
        assert sessions.resolve_session(db, raw + "x") is None
        assert sessions.resolve_session(db, None) is None


def test_expiry_and_lifetime_setting(user, monkeypatch):
    monkeypatch.setenv("SESSION_LIFETIME_DAYS", "2")
    reload_settings()
    now = utcnow()
    with write_session() as db:
        raw = sessions.issue_session(db, user.id, now=now)
    with read_session() as db:
        assert sessions.resolve_session(db, raw, now=now + timedelta(days=1), touch=False)
        assert sessions.resolve_session(db, raw, now=now + timedelta(days=2), touch=False) is None


def test_last_seen_touched_at_most_hourly(user):
    now = utcnow()
    with write_session() as db:
        raw = sessions.issue_session(db, user.id, now=now)
    with write_session() as db:
        sess, _ = sessions.resolve_session(db, raw, now=now + timedelta(minutes=59))
        assert sess.last_seen_at == now
    with write_session() as db:
        sessions.resolve_session(db, raw, now=now + timedelta(minutes=61))
    with read_session() as db:
        assert db.scalars(select(UserSession.last_seen_at)).one() == now + timedelta(minutes=61)


def test_revocation_and_inactive_or_merged_users(db, user, chair, global_admin):
    other = factories.make_user(db, display_name="Bob", chair=chair)
    with write_session() as w:
        s1, raw1 = sessions.create_session(w, user.id)
        raw2 = sessions.issue_session(w, user.id)
        raw3 = sessions.issue_session(w, other.id)
    with write_session() as w:
        assert sessions.revoke_session(w, s1.id) is True
        assert sessions.revoke_session(w, s1.id) is False
    with read_session() as r:
        assert sessions.resolve_session(r, raw1) is None
        assert sessions.resolve_session(r, raw2) is not None
    with write_session() as w:
        set_user_status(w, admin=w.merge(global_admin), user_id=user.id, active=False)
    with read_session() as r:
        assert sessions.resolve_session(r, raw2) is None  # inactive: invalid immediately
    with write_session() as w:
        merge_users(w, admin=w.merge(global_admin), duplicate_id=other.id, target_id=user.id)
    with read_session() as r:
        assert sessions.resolve_session(r, raw3) is None
    with write_session() as w:
        assert sessions.revoke_user_sessions(w, user.id) == 1


# ----- pending actions ------------------------------------------------------------------------
def test_pending_create_idempotent_and_consumed_once():
    with write_session() as db:
        pid = pending.create_pending(db, "double", "nonce-1")
        assert pending.create_pending(db, "double", "nonce-1") == pid
    with read_session() as db:
        assert pending.get_pending(db, pid).kind == "double"
    with write_session() as db:
        assert pending.consume_pending(db, pid).nonce == "nonce-1"
        assert pending.consume_pending(db, pid) is None
    with read_session() as db:
        assert pending.get_pending(db, pid) is None
    with write_session() as db, pytest.raises(InvalidInput):
        pending.create_pending(db, "triple", "n")


def test_pending_expires_after_one_hour():
    now = utcnow()
    with write_session() as db:
        pid = pending.create_pending(db, "single", "nonce-exp", now=now)
    with write_session() as db:
        assert pending.consume_pending(db, pid, now=now + timedelta(minutes=61)) is None
        assert pending.consume_pending(db, "unknown") is None


# ----- onboarding -----------------------------------------------------------------------------
def test_register_without_pending(chair):
    with write_session() as db:
        res = onboarding.register_and_start_session(db, display_name="  Carla  ", chair_id=chair.id)
    assert res.created and res.event is None and res.coffee_status == onboarding.COFFEE_NONE
    with read_session() as db:
        assert sessions.resolve_session(db, res.raw_token)[1].display_name == "Carla"
    assert count(ConsumptionEvent) == 0


@pytest.mark.parametrize("kind,qty", [("single", 1), ("double", 2)])
def test_register_after_scan_records_once(chair, price, kind, qty):
    with write_session() as db:
        pid = pending.create_pending(db, kind, f"scan-{kind}")
    with write_session() as db:
        res = onboarding.register_and_start_session(db, display_name="Dora", chair_id=chair.id, pending_id=pid,
                                                    registration_nonce="reg-1")
    assert res.coffee_status == onboarding.COFFEE_RECORDED
    assert (res.event.quantity, res.event.amount_cents) == (qty, qty * 50)
    assert res.event.session_id == res.session.id and res.event.user_id == res.user.id
    # second submit of the same form: same profile, same coffee, fresh session
    with write_session() as db:
        again = onboarding.register_and_start_session(db, display_name="Dora", chair_id=chair.id, pending_id=pid,
                                                      registration_nonce="reg-1", old_session_id=res.session.id)
    assert not again.created and again.user.id == res.user.id and again.event.id == res.event.id
    assert count(User) == 1 and count(ConsumptionEvent) == 1
    with read_session() as db:
        assert sessions.resolve_session(db, res.raw_token) is None  # rotated
        assert sessions.resolve_session(db, again.raw_token) is not None


def test_register_invalid_input_and_inactive_chair(db, chair):
    off = factories.make_chair(db, short_name="OFF", active=False)
    with write_session() as w, pytest.raises(InvalidInput):
        onboarding.register_and_start_session(w, display_name="   ", chair_id=chair.id)
    with write_session() as w, pytest.raises(InvalidInput):
        onboarding.register_and_start_session(w, display_name="Eve", chair_id=off.id)
    assert count(User) == 0 and count(UserSession) == 0


def test_register_no_price_keeps_registration_and_pending(chair):
    with write_session() as db:
        pid = pending.create_pending(db, "single", "scan-np")
    with write_session() as db:
        res = onboarding.register_and_start_session(db, display_name="Finn", chair_id=chair.id, pending_id=pid)
    assert res.coffee_status == onboarding.COFFEE_NO_PRICE and res.event is None
    assert count(User) == 1 and count(ConsumptionEvent) == 0
    assert count(PendingAction, PendingAction.consumed_at.is_(None)) == 1


def test_select_profile_rotates_and_records(user, price):
    with write_session() as db:
        old, old_raw = sessions.create_session(db, user.id)
        pid = pending.create_pending(db, "double", "scan-sel")
    with write_session() as db:
        res = onboarding.select_profile_and_start_session(db, user_id=user.id, pending_id=pid, old_session_id=old.id)
    assert res.coffee_status == onboarding.COFFEE_RECORDED and res.event.quantity == 2
    with read_session() as db:
        assert sessions.resolve_session(db, old_raw) is None
    # the same pending action can't be used again (consumed) -> expired, nothing recorded
    with write_session() as db:
        res2 = onboarding.select_profile_and_start_session(db, user_id=user.id, pending_id=pid)
    assert res2.coffee_status == onboarding.COFFEE_EXPIRED and count(ConsumptionEvent) == 1


def test_select_profile_rejects_inactive_merged_unknown(db, user, chair, global_admin):
    dup = factories.make_user(db, display_name="Dup", chair=chair)
    with write_session() as w:
        merge_users(w, admin=w.merge(global_admin), duplicate_id=dup.id, target_id=user.id)
    with write_session() as w, pytest.raises(UserInactive):
        onboarding.select_profile_and_start_session(w, user_id=dup.id)
    with write_session() as w, pytest.raises(NotFound):
        onboarding.select_profile_and_start_session(w, user_id=uuid.uuid4())


def test_pending_nonce_used_by_other_profile_is_not_shown(db, user, chair, price):
    other = factories.make_user(db, display_name="Other", chair=chair)
    with write_session() as w:
        record_coffee(w, user_id=other.id, kind="single", nonce="shared-nonce")
        pid = pending.create_pending(w, "single", "shared-nonce")
    with write_session() as w:
        res = onboarding.select_profile_and_start_session(w, user_id=user.id, pending_id=pid)
    assert res.event is None and res.coffee_status == onboarding.COFFEE_EXPIRED


def _run_threads(n, target):
    barrier = threading.Barrier(n)
    results, errors = [], []

    def run():
        barrier.wait()
        try:
            results.append(target())
        except Exception as exc:  # pragma: no cover - surfaced by assertions
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results, errors


def test_threaded_double_submit_registration(chair, price):
    with write_session() as db:
        pid = pending.create_pending(db, "double", "scan-thread")

    def submit():
        with write_session() as db:
            return onboarding.register_and_start_session(db, display_name="Gina", chair_id=chair.id,
                                                         pending_id=pid, registration_nonce="reg-thread")

    results, errors = _run_threads(4, submit)
    assert not errors and len(results) == 4
    assert count(User) == 1 and count(ConsumptionEvent) == 1
    assert sum(r.created for r in results) == 1
    assert {r.event.id for r in results} == {results[0].event.id}


def test_threaded_double_submit_selection(user, price):
    with write_session() as db:
        pid = pending.create_pending(db, "single", "scan-thread-sel")

    def submit():
        with write_session() as db:
            return onboarding.select_profile_and_start_session(db, user_id=user.id, pending_id=pid)

    results, errors = _run_threads(4, submit)
    assert not errors
    assert count(ConsumptionEvent) == 1
    assert sorted(r.coffee_status for r in results).count(onboarding.COFFEE_RECORDED) == 1


# ----- gate, rate limit, signing -----------------------------------------------------------------
def test_access_code_and_gate_cookie(monkeypatch):
    assert gate.check_access_code("test-access-code")
    assert gate.check_access_code(" test-access-code ")
    assert not gate.check_access_code("test-access-cod")
    assert not gate.check_access_code("") and not gate.check_access_code(None)
    now = utcnow()
    cookie = gate.make_gate_cookie(now=now)
    assert gate.verify_gate_cookie(cookie, now=now + timedelta(minutes=59))
    assert not gate.verify_gate_cookie(cookie, now=now + timedelta(minutes=61))
    assert not gate.verify_gate_cookie(cookie[:-2] + "xx", now=now)
    assert not gate.verify_gate_cookie(None)
    monkeypatch.setenv("ACCESS_CODE", "rotated-access-code")
    reload_settings()
    assert not gate.verify_gate_cookie(cookie, now=now)  # rotating the code invalidates cookies


def test_rate_limit_window():
    now = utcnow()
    with write_session() as db:
        for i in range(3):
            ratelimit.check_rate(db, "t", "1.2.3.4", 3, 60, now=now + timedelta(seconds=i))
        with pytest.raises(RateLimited):
            ratelimit.check_rate(db, "t", "1.2.3.4", 3, 60, now=now + timedelta(seconds=5))
        ratelimit.check_rate(db, "t", "5.6.7.8", 3, 60, now=now)  # other key unaffected
        ratelimit.check_rate(db, "t", "1.2.3.4", 3, 60, now=now + timedelta(seconds=61))  # window slid
        assert not ratelimit.is_limited(db, "f", "k", 1, 60, now=now)
        ratelimit.record_hit(db, "f", "k" * 500, now=now)
        assert ratelimit.is_limited(db, "f", "k" * 500, 1, 60, now=now)
    assert count(RateLimitEvent) == 6


def test_signing_purpose_tamper_expiry():
    now = utcnow()
    tok = signing.sign("a", {"x": 1}, now=now)
    assert signing.unsign("a", tok, max_age=10, now=now) == {"x": 1, "iat": int(now.timestamp())}
    assert signing.unsign("b", tok, max_age=10, now=now) is None
    assert signing.unsign("a", tok, max_age=10, now=now + timedelta(seconds=11)) is None
    assert signing.unsign("a", tok, max_age=10, now=now - timedelta(minutes=5)) is None  # from the future
    raw, sig = tok.split(".")
    forged = signing._b64e(b'{"iat":%d,"x":2}' % int(now.timestamp())) + "." + sig
    assert signing.unsign("a", forged, max_age=10, now=now) is None
    for bad in ("", "abc", "a.b.c", "é.é", None):
        assert signing.unsign("a", bad, max_age=10) is None
