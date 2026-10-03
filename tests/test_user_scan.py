"""user-web: the scan flow for browsers with a session (PROMPT §3, §12)."""

from __future__ import annotations

from datetime import timedelta
from fastapi.testclient import TestClient

from app.models import ConsumptionEvent, PendingAction
from app.services import users
from app.timeutil import utcnow
from app.web import deps, routes_user, tokens
from tests import factories
from tests.conftest import reload_settings
from tests.user_support import counts, event_id_from, events, post_scan, scan, scan_token


def test_get_writes_nothing_and_is_not_cached(client, db, user, price, login):
    before = counts(db)
    for _ in range(3):
        anonymous = client.get("/coffee/single")
        assert anonymous.status_code == 200
    assert counts(db) == before
    login(user)
    before = counts(db)
    r = client.get("/coffee/double")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    assert counts(db) == before
    assert 'action="/coffee/double"' in r.text and 'name="token"' in r.text
    assert '<button type="submit"' in r.text  # visible no-JS fallback
    assert '<script src="/static/scan.js"' in r.text and "<script>" not in r.text
    # Every GET issues a different token (different nonce).
    assert scan_token(client, "single") != scan_token(client, "single")


def test_unknown_kind_is_404(client, login, user):
    login(user)
    assert client.get("/coffee/triple").status_code == 404
    assert client.post("/coffee/triple", data={"token": "x"}).status_code == 404
    assert client.get("/coffee/done").status_code == 404


def test_single_and_double_with_session(client, db, user, price, login):
    login(user)
    first = scan(client, "single")
    second = scan(client, "double")
    event_id_from(first), event_id_from(second)
    one, two = events(db)
    assert (one.type, one.quantity, one.amount_cents, one.unit_price_cents) == ("single", 1, 50, 50)
    assert (two.type, two.quantity, two.amount_cents) == ("double", 2, 100)
    assert one.user_id == user.id and one.chair_id == user.chair_id and one.session_id is not None
    assert first.headers["cache-control"] == "no-store"


def test_replayed_token_same_user_records_once(client, db, user, price, login):
    login(user)
    token = scan_token(client, "single")
    ids = {event_id_from(post_scan(client, "single", token)) for _ in range(3)}
    assert len(ids) == 1 and len(events(db)) == 1


def test_replayed_token_other_user_records_once_and_hides_event(client, db, user, chair, price, login):
    login(user)
    token = scan_token(client, "single")
    event_id_from(post_scan(client, "single", token))
    other = factories.make_user(db, display_name="Bob", chair=chair)
    login(other)
    r = post_scan(client, "single", token)
    assert r.status_code == 409 and "/coffee/done/" not in r.text
    assert len(events(db)) == 1


def test_two_scans_two_events(client, db, user, price, login):
    login(user)
    a, b = event_id_from(scan(client)), event_id_from(scan(client))
    assert a != b and len(events(db)) == 2


def test_expired_wrong_kind_and_tampered_tokens_rejected(client, db, user, price, login):
    login(user)
    old = tokens.make_scan_token("single", now=utcnow() - timedelta(minutes=31))
    wrong_kind = tokens.make_scan_token("double")
    good = tokens.make_scan_token("single")
    for token, kind in ((old, "single"), (wrong_kind, "single"), (good[:-2] + "xx", "single"), ("", "single"),
                        (good, "double")):
        r = client.post(f"/coffee/{kind}", data={"token": token}, follow_redirects=False)
        assert r.status_code == 400 and f'href="/coffee/{kind}"' in r.text
    assert events(db) == []
    # A token just inside the validity window works.
    recent = tokens.make_scan_token("single", now=utcnow() - timedelta(minutes=29))
    assert client.post("/coffee/single", data={"token": recent}, follow_redirects=False).status_code == 303


def test_refresh_and_back_never_create_a_second_event(client, db, user, price, login):
    login(user)
    token = scan_token(client, "single")
    done = post_scan(client, "single", token).headers["location"]
    for _ in range(2):  # refresh the success page
        r = client.get(done)
        assert r.status_code == 200 and "Single recorded" in r.text
    # Back to the intermediate page and re-submit (or double tap): same event.
    assert post_scan(client, "single", token).headers["location"] == done
    assert len(events(db)) == 1


def test_no_price_records_nothing_and_shows_safe_page(client, db, user, login):
    login(user)
    r = scan(client, "single")
    assert r.status_code == 503 and "price has been configured" in r.text
    assert events(db) == []
    assert "Traceback" not in r.text


def test_deactivated_user_cannot_record(client, db, user, price, login, global_admin):
    login(user)
    token = scan_token(client, "single")  # page loaded while still active
    users.set_user_status(db, admin=global_admin, user_id=user.id, active=False)
    db.commit()
    r = post_scan(client, "single", token)
    assert r.status_code == 303 and r.headers["location"] == "/join"  # session no longer valid
    assert events(db) == []


def test_deactivated_during_the_request_is_refused_in_the_transaction(client, db, user, price, login, global_admin,
                                                                       monkeypatch):
    login(user)
    stale = deps.current_user  # resolved while the profile was still active
    ctx = stale(type("R", (), {"cookies": client.cookies, "state": type("S", (), {})()})())
    assert ctx is not None
    users.set_user_status(db, admin=global_admin, user_id=user.id, active=False)
    db.commit()
    monkeypatch.setattr(routes_user.deps, "current_user", lambda request: ctx)
    r = post_scan(client, "single")
    assert r.status_code == 403 and "no longer active" in r.text
    assert events(db) == []


def test_merged_profile_cannot_scan(client, db, user, chair, price, login, global_admin):
    target = factories.make_user(db, display_name="Target", chair=chair)
    login(user)
    users.merge_users(db, admin=global_admin, duplicate_id=user.id, target_id=target.id)
    db.commit()
    r = scan(client)
    assert r.status_code == 303 and r.headers["location"] == "/join"
    assert events(db) == []


def test_per_session_hourly_cap(client, db, user, price, login, monkeypatch):
    monkeypatch.setenv("MAX_COFFEES_PER_SESSION_PER_HOUR", "2")
    reload_settings()
    login(user)
    event_id_from(scan(client)), event_id_from(scan(client))
    assert scan(client).status_code == 429
    assert len(events(db)) == 2


def test_scan_without_session_stores_a_pending_action_only(client, db, price):
    r = scan(client, "double")
    assert r.status_code == 303 and r.headers["location"] == "/join"
    pending_cookie = next(c for c in r.headers.get_list("set-cookie") if c.startswith("coffee_pending="))
    assert "HttpOnly" in pending_cookie and "SameSite=lax" in pending_cookie and "Path=/" in pending_cookie
    db.rollback()
    row = db.query(PendingAction).one()
    assert row.kind == "double" and row.consumed_at is None
    assert timedelta(minutes=59) < row.expires_at - row.created_at <= timedelta(hours=1)
    assert pending_cookie.split(";")[0].split("=", 1)[1] == row.id
    assert events(db) == []
    # Replaying the same token without a session stores nothing new.
    token = scan_token(client, "double")
    post_scan(client, "double", token), post_scan(client, "double", token)
    db.rollback()
    assert db.query(PendingAction).count() == 2


def test_done_page_requires_owner(client, db, user, chair, price, login):
    login(user)
    done = scan(client).headers["location"]
    other = factories.make_user(db, display_name="Bob", chair=chair)
    login(other)
    assert client.get(done).status_code == 404
    client.cookies.clear()
    r = client.get(done, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/join"
    login(user)
    assert client.get("/coffee/done/not-a-uuid").status_code == 404


def test_cross_site_scan_post_is_refused(client, db, user, price, login):
    login(user)
    token = scan_token(client, "single")
    for headers in ({"Sec-Fetch-Site": "cross-site"}, {"Origin": "https://evil.example"}):
        r = client.post("/coffee/single", data={"token": token}, headers=headers, follow_redirects=False)
        assert r.status_code == 403
    assert events(db) == []
    ok = client.post("/coffee/single", data={"token": token}, headers={"Sec-Fetch-Site": "same-origin"},
                     follow_redirects=False)
    assert ok.status_code == 303 and len(events(db)) == 1
