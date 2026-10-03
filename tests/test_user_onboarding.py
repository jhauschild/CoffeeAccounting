"""user-web: access gate, registration, profile selection (PROMPT §3 steps 3-5, §5, §12)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.models import ConsumptionEvent, PendingAction, RateLimitEvent, User, UserSession
from app.services import ratelimit, sessions, users
from app.timeutil import utcnow
from app.web import tokens
from tests import factories
from tests.user_support import (ACCESS_CODE, counts, event_id_from, events, field, pass_gate, post_scan, register,
                                scan, select_profile)


def _users(db) -> list[User]:
    db.rollback()
    return list(db.scalars(select(User)))


# ----- access gate ----------------------------------------------------------------------------
@pytest.mark.parametrize("method,path", [("get", "/register"), ("get", "/profiles"), ("get", "/profiles?q=a"),
                                         ("post", "/register"), ("post", "/profiles/select")])
def test_gated_pages_need_the_code(client, db, chair, user, method, path):
    before = counts(db)
    r = getattr(client, method)(path, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/join"
    assert counts(db) == before


def test_wrong_code_is_rate_limited_and_correct_code_unlocks(client, db):
    for _ in range(10):
        r = client.post("/join", data={"code": "wrong-code"}, follow_redirects=False)
        assert r.status_code == 403 and "not correct" in r.text and "coffee_gate" not in r.headers.get("set-cookie", "")
    # The limit now also blocks the correct code until the window passes.
    r = client.post("/join", data={"code": ACCESS_CODE}, follow_redirects=False)
    assert r.status_code == 429 and "coffee_gate" not in r.headers.get("set-cookie", "")
    assert client.get("/register", follow_redirects=False).status_code == 303
    db.rollback()
    assert db.query(RateLimitEvent).filter_by(bucket="access_code").count() == 10
    db.execute(update(RateLimitEvent).values(created_at=utcnow() - timedelta(minutes=16)))
    db.commit()
    pass_gate(client)
    assert client.get("/register").status_code == 200 and client.get("/profiles").status_code == 200


def test_gate_cookie_flags_and_choice_page(client):
    r = client.post("/join", data={"code": ACCESS_CODE}, follow_redirects=False)
    cookie = next(c for c in r.headers.get_list("set-cookie") if c.startswith("coffee_gate="))
    assert "HttpOnly" in cookie and "SameSite=lax" in cookie and "Max-Age=3600" in cookie
    page = client.get("/join")
    assert 'href="/register"' in page.text and 'href="/profiles"' in page.text and 'name="code"' not in page.text


def test_browser_with_session_needs_no_code(client, db, user, price, login):
    login(user)
    assert client.get("/profiles").status_code == 200 and client.get("/register").status_code == 200
    assert event_id_from(scan(client))


# ----- registration ---------------------------------------------------------------------------
def test_registration_without_pending_coffee(client, db, chair):
    pass_gate(client)
    r = register(client, "  Erika   Mustermann ", chair)
    assert r.status_code == 303 and r.headers["location"] == "/account?notice=registered"
    (created,) = _users(db)
    assert created.display_name == "Erika Mustermann" and created.chair_id == chair.id and created.status == "active"
    assert events(db) == []
    assert "coffee_session=" in r.headers["set-cookie"]
    page = client.get(r.headers["location"])
    assert page.status_code == 200 and "Erika Mustermann" in page.text and "Your profile is ready" in page.text
    assert client.get("/account?notice=<script>").text.count("<script>") == 0


@pytest.mark.parametrize("kind,quantity,amount", [("single", 1, 50), ("double", 2, 100)])
def test_registration_after_scan_records_the_coffee_exactly_once(client, db, chair, price, kind, quantity, amount):
    scan_response = scan(client, kind)
    assert scan_response.headers["location"] == "/join"
    assert "will be recorded" in client.get("/join").text  # pending coffee announced
    pass_gate(client)
    assert "will be recorded" in client.get("/register").text
    r = register(client, "Erika", chair)
    done = r.headers["location"]
    assert done.startswith("/coffee/done/")
    (event,) = events(db)
    assert (event.type, event.quantity, event.amount_cents) == (kind, quantity, amount)
    assert done.endswith(str(event.id)) and event.user_id == _users(db)[0].id
    assert 'coffee_pending=""' in r.headers.get_list("set-cookie")[-1] or "coffee_pending=" in "".join(
        r.headers.get_list("set-cookie"))
    db.rollback()
    assert db.query(PendingAction).one().consumed_at is not None
    session_row = db.query(UserSession).one()
    assert event.session_id == session_row.id
    assert "Single recorded" in client.get(done).text or "Double recorded" in client.get(done).text
    # Undo is offered right away to the browser that registered.
    assert "Undo this coffee" in client.get(done).text
    # A later scan needs no prompt.
    assert event_id_from(scan(client, "single")) and len(events(db)) == 2


def test_double_submitted_registration_creates_one_profile_and_one_coffee(client, db, chair, price):
    scan(client, "single")
    pass_gate(client)
    page = client.get("/register")
    data = {"csrf_token": field(page.text, "csrf_token"), "registration_token": field(page.text, "registration_token"),
            "display_name": "Erika", "chair_id": str(chair.id), "privacy_ack": "1"}
    first = client.post("/register", data=data, follow_redirects=False)
    second = client.post("/register", data=data, follow_redirects=False)  # double tap / retry
    assert first.headers["location"] == second.headers["location"] and "/coffee/done/" in first.headers["location"]
    assert len(_users(db)) == 1 and len(events(db)) == 1


def test_double_submit_from_a_browser_without_the_new_cookie(client, db, chair, price):
    """The second submit arrives with the pre-registration cookies (response lost): still one of each."""
    scan(client, "double")
    pass_gate(client)
    page = client.get("/register")
    data = {"csrf_token": field(page.text, "csrf_token"), "registration_token": field(page.text, "registration_token"),
            "display_name": "Erika", "chair_id": str(chair.id), "privacy_ack": "1"}
    jar = dict(client.cookies)
    first = client.post("/register", data=data, follow_redirects=False)
    client.cookies.clear()
    client.cookies.update(jar)
    second = client.post("/register", data=data, follow_redirects=False)
    assert first.headers["location"] == second.headers["location"]
    assert len(_users(db)) == 1 and len(events(db)) == 1


def test_duplicate_name_hint_still_allows_continuing(client, db, chair, other_chair):
    existing = factories.make_user(db, display_name="Erika Mustermann", chair=chair)
    pass_gate(client)
    r = register(client, "erika  mustermann", chair)
    assert r.status_code == 200 and "already exists in this" in r.text and "Use existing profile" in r.text
    assert f'value="{existing.id}"' in r.text and len(_users(db)) == 1
    # "Continue" resubmits with confirm_duplicate and the same one-time token.
    token = field(r.text, "registration_token")
    r2 = register(client, "erika  mustermann", chair, token=token, extra={"confirm_duplicate": "1"})
    assert r2.status_code == 303 and len(_users(db)) == 2
    # Same name in another chair: no hint.
    assert register(client, "Erika Mustermann", other_chair).status_code == 303


def test_duplicate_hint_use_existing_profile(client, db, chair, price):
    existing = factories.make_user(db, display_name="Erika Mustermann", chair=chair)
    scan(client, "single")
    pass_gate(client)
    hint = register(client, "Erika Mustermann", chair)
    r = client.post("/profiles/select", data={"csrf_token": field(hint.text, "csrf_token"),
                                              "user_id": field(hint.text, "user_id")}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/coffee/done/")
    assert [e.user_id for e in events(db)] == [existing.id] and len(_users(db)) == 1


@pytest.mark.parametrize("override,error", [
    ({"privacy_ack": ""}, "confirm the privacy"),
    ({"display_name": "   "}, "Please enter a name"),
    ({"display_name": "x" * 500}, "Please enter a name"),
    ({"display_name": "bad\x00name"}, "Please enter a name"),
    ({"chair_id": "not-a-uuid"}, "Please choose"),
    ({"registration_token": "forged"}, "expired"),
])
def test_registration_validation(client, db, chair, override, error):
    pass_gate(client)
    data = {"display_name": "Erika", "chair_id": str(chair.id), "privacy_ack": "1"}
    page = client.get("/register")
    form = {"csrf_token": field(page.text, "csrf_token"), "registration_token": field(page.text, "registration_token"),
            **data, **override}
    r = client.post("/register", data=form, follow_redirects=False)
    assert r.status_code == 400 and error in r.text
    assert _users(db) == []


def test_inactive_chair_cannot_be_chosen(client, db, chair):
    dead = factories.make_chair(db, short_name="OLD", active=False)
    pass_gate(client)
    assert str(dead.id) not in client.get("/register").text
    assert register(client, "Erika", dead).status_code == 400 and _users(db) == []


def test_registration_requires_csrf(client, db, chair):
    pass_gate(client)
    page = client.get("/register")
    data = {"registration_token": field(page.text, "registration_token"), "display_name": "Erika",
            "chair_id": str(chair.id), "privacy_ack": "1"}
    assert client.post("/register", data=data, follow_redirects=False).status_code == 403
    assert client.post("/register", data={**data, "csrf_token": "forged"}, follow_redirects=False).status_code == 403
    assert _users(db) == []


def test_registration_is_rate_limited_per_ip(client, db, chair):
    pass_gate(client)
    for i in range(10):
        assert register(client, f"Person {i}", chair).status_code == 303
        client.cookies.delete("coffee_session")  # keep registering as "new browsers" behind one IP
    r = register(client, "One too many", chair)
    assert r.status_code == 429 and len(_users(db)) == 10


def test_pending_expired_or_consumed_falls_back_with_explanation(client, db, chair, price):
    scan(client, "single")
    db.execute(update(PendingAction).values(expires_at=utcnow() - timedelta(minutes=1)))
    db.commit()
    pass_gate(client)
    assert "expired or was already used" in client.get("/register").text
    r = register(client, "Erika", chair)
    assert r.headers["location"] == "/account?notice=expired" and events(db) == []
    assert "no coffee was recorded" in client.get(r.headers["location"]).text


def test_registration_with_pending_but_no_price_keeps_the_profile(client, db, chair):
    scan(client, "single")
    pass_gate(client)
    r = register(client, "Erika", chair)
    assert r.headers["location"] == "/account?notice=no_price" and len(_users(db)) == 1 and events(db) == []
    assert "no coffee price has been configured" in client.get(r.headers["location"]).text


def test_scan_token_already_used_by_someone_else_is_not_shown_after_registration(client, db, chair, user, price, login):
    token = tokens.make_scan_token("single")
    login(user)
    post_scan(client, "single", token)  # user records with this nonce
    other = TestClient(client.app)
    post_scan(other, "single", token)  # same token without a session -> pending action for the same nonce
    pass_gate(other)
    r = register(other, "Newcomer", chair)
    assert r.status_code == 303 and r.headers["location"] == "/account?notice=expired"
    assert len(events(db)) == 1 and events(db)[0].user_id == user.id


# ----- profile list and selection -------------------------------------------------------------
def test_profile_list_shows_name_and_chair_only(client, db, chair, other_chair, user, global_admin, price):
    users_ = [factories.make_user(db, display_name="Müller, Anna", chair=other_chair),
              factories.make_user(db, display_name="Gone", chair=chair, status="inactive")]
    merged = factories.make_user(db, display_name="Merged Mike", chair=chair)
    users.merge_users(db, admin=global_admin, duplicate_id=merged.id, target_id=user.id)
    db.commit()
    factories.add_events(db, user, ["single"])
    pass_gate(client)
    page = client.get("/profiles").text
    assert "Alice Example" in page and "Müller, Anna" in page and "CHA" in page and "CHB" in page
    assert "Gone" not in page and "Merged Mike" not in page
    assert "trust-based" in page and 'href="/register"' in page
    for forbidden in ("€", "balance", "Balance", "single", str(users_[0].created_at.year) + "-"):
        assert forbidden not in page
    assert "Müller, Anna" in client.get("/profiles?q=muller").text and "Alice" not in client.get("/profiles?q=mueller").text
    assert "No matching profile" in client.get("/profiles?q=zzzz").text


def test_profile_search_is_rate_limited(client, db):
    pass_gate(client)
    for _ in range(60):
        assert client.get("/profiles?q=a").status_code == 200
    assert client.get("/profiles?q=a").status_code == 429


def test_selection_on_a_new_browser_records_pending_coffee(client, db, chair, user, price):
    scan(client, "double")
    pass_gate(client)
    r = select_profile(client, user)
    assert r.status_code == 303 and r.headers["location"].startswith("/coffee/done/")
    (event,) = events(db)
    assert event.user_id == user.id and event.quantity == 2 and event.amount_cents == 100
    assert "Alice Example" in client.get("/account").text


def test_selection_without_pending_goes_to_account(client, db, user):
    pass_gate(client)
    r = select_profile(client, user)
    assert r.headers["location"] == "/account?notice=registered" and events(db) == []


def test_selection_rotates_the_session(client, db, user, chair, login):
    old_raw = login(user)
    other = factories.make_user(db, display_name="Bob", chair=chair)
    r = select_profile(client, other)
    assert r.status_code == 303
    new_raw = next(c for c in r.headers.get_list("set-cookie") if c.startswith("coffee_session=")).split(";")[0].split("=", 1)[1]
    assert new_raw and new_raw != old_raw
    db.rollback()
    with_old = sessions.resolve_session(db, old_raw, touch=False)
    with_new = sessions.resolve_session(db, new_raw, touch=False)
    assert with_old is None and with_new is not None and with_new[1].id == other.id


def test_selecting_an_inactive_or_unknown_profile_fails(client, db, chair, user):
    gone = factories.make_user(db, display_name="Gone", chair=chair, status="inactive")
    pass_gate(client)
    csrf = field(client.get("/profiles").text, "csrf_token")
    assert select_profile(client, gone, csrf=csrf).status_code == 403
    r = client.post("/profiles/select", data={"csrf_token": csrf, "user_id": "garbage"}, follow_redirects=False)
    assert r.status_code == 404
    assert "coffee_session" not in client.cookies


def test_selection_requires_csrf(client, db, user):
    pass_gate(client)
    r = client.post("/profiles/select", data={"user_id": str(user.id)}, follow_redirects=False)
    assert r.status_code == 403 and "coffee_session" not in client.cookies
