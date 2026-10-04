"""user-web: success page, undo, account, profile edit, sign-out, privacy, cookies, redirects, CSP."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import strings
from app.main import create_app
from app.models import AuditLog, ConsumptionEvent, UserSession
from app.services import ledger, sessions, users
from app.timeutil import utcnow
from app.web import tokens
from tests import factories
from tests.conftest import ROOT, reload_settings
from tests.test_platform_web import PROD_ENV
from tests.user_support import PASSWORD, event_id_from, events, field, make_account, scan, sign_in


def _csrf_for(client, raw_token: str) -> str:
    from app.db import read_session

    with read_session() as db:
        found = sessions.resolve_session(db, raw_token, touch=False)
        return tokens.csrf_token("user", str(found[0].id))


def _undo(client, event_id: str, csrf: str | None, **kw):
    data = {} if csrf is None else {"csrf_token": csrf}
    return client.post(f"/coffee/undo/{event_id}", data=data, follow_redirects=False, **kw)


# ----- success page ---------------------------------------------------------------------------
def test_done_page_content(client, db, user, price, login):
    login(user)
    page = client.get(scan(client, "double").headers["location"]).text
    for expected in ("Double recorded", "€0.50", "€1.00", "Undo this coffee", 'href="/account"', 'href="/overview"',
                     "Outstanding: €1.00", "Shots this month", "Amount paid"):
        assert expected in page
    local = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", page)
    assert local  # local timestamp
    assert "Shots consumed" in page and "Amount paid" in page


def test_done_page_shows_credit_for_negative_balance(client, db, user, global_admin, price, login):
    ledger.add_payment(db, admin=global_admin, user_id=user.id, amount_cents=500)
    db.commit()
    login(user)
    page = client.get(scan(client).headers["location"]).text
    assert "Credit: €4.50" in page and "€5.00" in page and "Outstanding" not in page


def test_total_balance_positive_when_owing(client, db, user, price, login):
    login(user)
    page = client.get(scan(client).headers["location"]).text
    assert "Credit" not in page and "Outstanding: €0.50" in page


# ----- undo -----------------------------------------------------------------------------------
def test_undo_within_window(client, db, user, price, login):
    raw = login(user)
    done = scan(client, "double").headers["location"]
    r = _undo(client, done.rsplit("/", 1)[1], _csrf_for(client, raw))
    assert r.status_code == 303 and r.headers["location"] == done
    original, reversal = events(db)
    assert reversal.type == "reversal" and reversal.reversal_of_id == original.id
    assert (reversal.quantity, reversal.amount_cents) == (-2, -100)
    page = client.get(done).text
    assert "This coffee was undone" in page and "Undo this coffee" not in page
    assert ledger.get_totals(db, user.id).balance_cents == 0


def test_undo_twice_creates_one_reversal(client, db, user, price, login):
    raw = login(user)
    event = event_id_from(scan(client))
    csrf = _csrf_for(client, raw)
    for _ in range(2):
        assert _undo(client, event, csrf).status_code == 303
    assert [e.type for e in events(db)] == ["single", "reversal"]


def test_undo_uses_original_price_after_price_change(client, db, user, global_admin, price, login):
    raw = login(user)
    event = event_id_from(scan(client))
    from app.services import prices

    prices.add_price(db, price_per_shot_cents=90, admin_id=global_admin.id)
    db.commit()
    _undo(client, event, _csrf_for(client, raw))
    assert events(db)[1].amount_cents == -50 and ledger.get_totals(db, user.id).consumed_amount_cents == 0


def test_undo_after_window_expired(client, db, user, price, login, monkeypatch):
    raw = login(user)
    event = event_id_from(scan(client))
    monkeypatch.setenv("UNDO_WINDOW_SECONDS", "0")
    reload_settings()
    r = _undo(client, event, _csrf_for(client, raw))
    assert r.status_code == 400 and "can no longer be undone" in r.text
    assert len(events(db)) == 1
    assert "Undo this coffee" not in client.get(f"/coffee/done/{event}").text


def test_undo_only_offered_for_the_latest_coffee(client, db, user, price, login):
    raw = login(user)
    first, second = event_id_from(scan(client)), event_id_from(scan(client))
    assert "Undo this coffee" not in client.get(f"/coffee/done/{first}").text
    assert "Undo this coffee" in client.get(f"/coffee/done/{second}").text
    assert _undo(client, first, _csrf_for(client, raw)).status_code == 400
    assert len(events(db)) == 2


def test_undo_of_someone_elses_event_or_other_session(client, db, user, chair, price, login):
    login(user)
    mine = event_id_from(scan(client))
    other = factories.make_user(db, display_name="Bob", chair=chair)
    raw_other = login(other)
    assert _undo(client, mine, _csrf_for(client, raw_other)).status_code in (400, 403, 404)
    # Same user, but a different browser session (e.g. after selecting the profile elsewhere).
    raw_again = login(user)
    r = _undo(client, mine, _csrf_for(client, raw_again))
    assert r.status_code == 400 and len(events(db)) == 1


def test_undo_of_a_reversal_is_refused(client, db, user, price, login):
    raw = login(user)
    event = event_id_from(scan(client))
    csrf = _csrf_for(client, raw)
    _undo(client, event, csrf)
    reversal = events(db)[1]
    assert _undo(client, str(reversal.id), csrf).status_code == 400
    assert client.get(f"/coffee/done/{reversal.id}").status_code == 404
    assert len(events(db)) == 2


def test_undo_requires_csrf(client, db, user, price, login):
    raw = login(user)
    event = event_id_from(scan(client))
    assert _undo(client, event, None).status_code == 403
    assert _undo(client, event, "forged").status_code == 403
    other = _csrf_for(client, raw)[::-1]
    assert _undo(client, event, other).status_code == 403
    assert len(events(db)) == 1


def test_undo_unknown_or_malformed_event(client, db, user, price, login):
    raw = login(user)
    csrf = _csrf_for(client, raw)
    assert _undo(client, "garbage", csrf).status_code == 404
    assert _undo(client, "00000000-0000-4000-8000-000000000000", csrf).status_code == 404


def test_concurrent_undos_produce_exactly_one_reversal(client, db, user, price, login):
    raw = login(user)
    event = event_id_from(scan(client))
    csrf = _csrf_for(client, raw)

    def attempt(_):
        with TestClient(client.app, raise_server_exceptions=False) as c:
            c.cookies.set("coffee_session", raw)
            return _undo(c, event, csrf).status_code

    with ThreadPoolExecutor(4) as pool:
        codes = list(pool.map(attempt, range(4)))
    assert all(code == 303 for code in codes), codes
    assert [e.type for e in events(db)] == ["single", "reversal"]


# ----- account --------------------------------------------------------------------------------
def test_account_page(client, db, user, global_admin, price, login):
    ledger.add_payment(db, admin=global_admin, user_id=user.id, amount_cents=125)
    factories.add_events(db, user, ["single", "double"])
    login(user)
    page = client.get("/account").text
    assert "Alice Example" in page and "CHA" in page and "€0.50" in page  # profile, chair, current price
    assert "Single" in page and "Double" in page and "Payment" in page and "€1.25" in page
    assert "Shots consumed" in page and "€1.50" in page  # 3 shots * 0.50
    assert "Credit" not in page and "Outstanding: €0.25" in page  # 1.50 consumed - 1.25 paid = 0.25 owed
    assert 'action="/logout"' in page and 'href="/account/edit"' in page


def test_account_without_price_and_history(client, db, user, login):
    login(user)
    page = client.get("/account").text
    assert "not configured yet" in page and "No coffees recorded yet" in page and "No payments recorded yet" in page


def test_account_marks_undone_coffee_and_requires_session(client, db, user, price, login):
    assert client.get("/account", follow_redirects=False).headers["location"] == "/login"
    raw = login(user)
    event = event_id_from(scan(client))
    _undo(client, event, _csrf_for(client, raw))
    page = client.get("/account").text
    assert "(undone)" in page and "Undo" in page


def test_account_follows_merges(client, db, user, chair, global_admin, price, login):
    duplicate = factories.make_user(db, display_name="Alice E.", chair=chair)
    factories.add_events(db, duplicate, ["double"])
    users.merge_users(db, admin=global_admin, duplicate_id=duplicate.id, target_id=user.id)
    db.commit()
    login(user)
    assert "€1.00" in client.get("/account").text


# ----- edit profile ---------------------------------------------------------------------------
def _edit(client, name, chair, csrf=None):
    page = client.get("/account/edit")
    data = {"csrf_token": field(page.text, "csrf_token") if csrf is None else csrf, "display_name": name,
            "chair_id": str(chair.id)}
    return client.post("/account/edit", data=data, follow_redirects=False)


def test_edit_name_and_audited_chair_change(client, db, user, chair, other_chair, login):
    login(user)
    page = client.get("/account/edit").text
    assert 'value="Alice Example"' in page and str(other_chair.id) in page
    r = _edit(client, "Alice Beispiel", other_chair)
    assert r.status_code == 303 and r.headers["location"] == "/account?notice=saved"
    db.rollback()
    db.refresh(user)
    assert user.display_name == "Alice Beispiel" and user.chair_id == other_chair.id
    assert user.normalized_name == users.normalize_name("Alice Beispiel")
    (entry,) = db.scalars(select(AuditLog).where(AuditLog.action == "user.chair_changed")).all()
    assert entry.actor_type == "user" and entry.target_id == str(user.id) and entry.actor_id == str(user.id)
    # Name-only change: no chair audit entry.
    _edit(client, "Alice B.", other_chair)
    assert db.query(AuditLog).filter_by(action="user.chair_changed").count() == 1


def test_edit_validation_and_csrf(client, db, user, chair, login):
    dead = factories.make_chair(db, short_name="OLD", active=False)
    login(user)
    assert _edit(client, "", chair).status_code == 400
    assert _edit(client, "Alice", dead).status_code == 400
    assert _edit(client, "Alice", chair, csrf="forged").status_code == 403
    db.rollback()
    db.refresh(user)
    assert user.display_name == "Alice Example" and user.chair_id == chair.id


def test_edit_keeps_inactive_current_chair_selectable(client, db, user, chair, login):
    chair.active = False
    db.commit()
    login(user)
    assert _edit(client, "Alice Renamed", chair).status_code == 303


# ----- sign out ----------------------------------------------------------------------------------
def test_logout_revokes_the_session(client, db, user, price, login):
    raw = login(user)
    csrf = _csrf_for(client, raw)
    assert client.post("/logout", data={}, follow_redirects=False).status_code == 403
    r = client.post("/logout", data={"csrf_token": csrf}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/?notice=left"
    assert 'coffee_session=""' in r.headers["set-cookie"] or "Max-Age=0" in r.headers["set-cookie"]
    db.rollback()
    assert sessions.resolve_session(db, raw, touch=False) is None
    assert db.query(UserSession).filter(UserSession.revoked_at.is_not(None)).count() == 1
    stale = TestClient(client.app)
    stale.cookies.set("coffee_session", raw)
    assert stale.get("/account", follow_redirects=False).headers["location"] == "/login"
    assert "signed out" in client.get("/?notice=left").text


def test_admin_revocation_stops_scans(client, db, user, price, login):
    login(user)
    from app.db import write_session

    with write_session() as w:
        sessions.revoke_user_sessions(w, user.id)
    assert scan(client).headers["location"] == "/login" and events(db) == []


# ----- home, privacy --------------------------------------------------------------------------
def test_home_for_guests_and_users(client, db, user, login):
    page = client.get("/").text
    assert 'href="/login"' in page and 'href="/register"' in page
    login(user)
    page = client.get("/").text
    assert "Alice Example" in page and 'href="/coffee/single"' in page and 'href="/coffee/double"' in page


def test_privacy_page(client, monkeypatch):
    monkeypatch.setenv("RETENTION_TEXT", "We keep everything for seven years.")
    monkeypatch.setenv("OPERATOR_CONTACT", "coffee-admin@example.org")
    reload_settings()
    r = TestClient(create_app()).get("/privacy")
    assert r.status_code == 200
    for expected in ("seven years", "coffee-admin@example.org", "trust-based", "audit", "session", "display name",
                     "e-mail", "hash"):
        assert expected.lower() in r.text.lower()
    assert "http://" not in r.text and "https://" not in r.text


# ----- cookies, redirects, markup -------------------------------------------------------------
def test_session_cookie_flags_in_production(monkeypatch, db):
    for key, value in PROD_ENV.items():
        monkeypatch.setenv(key, value)
    reload_settings()
    account = make_account(db, "Prod User", username="produser")
    with TestClient(create_app(), base_url="https://coffee.example.org") as c:
        page = c.get("/login")
        csrf_cookie = next(h for h in page.headers.get_list("set-cookie") if h.startswith("coffee_csrf="))
        assert {"HttpOnly", "Secure", "SameSite=lax", "Path=/"} <= {p.strip() for p in csrf_cookie.split(";")}
        r = c.post("/login", data={"csrf_token": field(page.text, "csrf_token"), "username": account.username,
                                   "password": PASSWORD}, follow_redirects=False)
        assert r.status_code == 303
        cookie = next(h for h in r.headers.get_list("set-cookie") if h.startswith("coffee_session="))
        parts = {p.strip().split("=")[0]: p.strip() for p in cookie.split(";")}
        assert {"HttpOnly", "Secure", "Path"} <= set(parts) and parts["SameSite"] == "SameSite=lax"
        assert parts["Max-Age"] == f"Max-Age={180 * 86400}"
        assert len(cookie.split(";")[0].split("=", 1)[1]) >= 40  # opaque 256-bit token
        assert "strict-transport-security" in r.headers


def test_session_cookie_flags_in_development(client, db, chair):
    account = make_account(db, "Dev User", chair)
    r = sign_in(client, account)
    cookie = next(h for h in r.headers.get_list("set-cookie") if h.startswith("coffee_session="))
    assert "HttpOnly" in cookie and "SameSite=lax" in cookie and "Path=/" in cookie and "Secure" not in cookie


EVIL = ["//evil.example", "https://evil.example", "/\\evil.example"]


@pytest.mark.parametrize("evil", EVIL)
def test_no_open_redirect_anywhere(client, db, chair, user, price, evil):
    extras = {"next": evil, "redirect": evil, "return_to": evil, "url": evil}

    def fixed(response):
        loc = response.headers.get("location")
        assert loc is None or (loc.startswith("/") and not loc.startswith("//") and "evil" not in loc), loc

    fixed(client.get("/login", params=extras, follow_redirects=False))
    account = make_account(db, "Eve", chair, username="eve")
    page = client.get("/login")
    fixed(client.post("/login", data={"csrf_token": field(page.text, "csrf_token"), "username": account.username,
                                      "password": PASSWORD, **extras}, follow_redirects=False))
    fixed(client.get("/register", params=extras, follow_redirects=False))
    token = tokens.make_scan_token("single")
    fixed(client.post("/coffee/single", data={"token": token, **extras}, follow_redirects=False))
    fixed(client.get("/account", params=extras, follow_redirects=False))
    fixed(client.get("/?notice=" + evil, follow_redirects=False))
    csrf = _csrf_for(client, client.cookies.get("coffee_session"))
    fixed(client.post("/logout", data={"csrf_token": csrf, **extras}, follow_redirects=False))
    # The unknown notice keyword is ignored, never echoed.
    assert "evil" not in client.get("/account?notice=" + evil, follow_redirects=True).text


def test_pages_have_no_inline_script_or_style_and_no_external_assets(client, db, user, price, login, chair):
    pages = ["/", "/privacy", "/login", "/login?notice=reset", "/register", "/register?kind=guest", "/forgot", "/coffee/single"]
    for path in pages:
        client.get(path)
    login(user)
    done = scan(client).headers["location"]
    pages += [done, "/account", "/account/edit", "/", "/login", "/register"]
    for path in pages:
        r = client.get(path)
        assert r.status_code == 200, path
        html = r.text
        assert not re.search(r"<script(?![^>]*\bsrc=)", html), path
        assert " style=" not in html and not re.search(r"\son[a-z]+=", html), path
        assert "<style" not in html and "javascript:" not in html, path
        assert not re.search(r"(src|href)=\"(https?:)?//", html), path
        assert r.headers["content-security-policy"].startswith("default-src 'self'")
        assert r.headers["cache-control"] == "no-store"


def test_all_string_keys_used_by_templates_and_routes_exist():
    sources = [*(ROOT / "templates" / "user").glob("*.html"), ROOT / "app" / "web" / "routes_user.py",
               ROOT / "app" / "web" / "user_views.py"]
    used: set[str] = set()
    for path in sources:
        used |= {k for k in re.findall(r'"(user\.[a-z_.]+)"', path.read_text()) if not k.endswith(("_", "."))}
    for kind in ("single", "double"):
        used |= {f"user.scan.title_{kind}", f"user.scan.button_{kind}", f"user.done.{kind}", f"user.pending.{kind}"}
    used |= {f"user.account.type_{k}" for k in ("single", "double", "reversal", "adjustment")}
    used |= {"user.pending.view_site", "user.register.error_name"}
    used |= {f"user.headline.{k}" for k in ("owes", "credit", "even")}
    used |= {f"user.account.payment_{k}" for k in ("payment", "paid_back", "bookkeeping_in", "bookkeeping_out")}
    used |= {f"user.register.error_password_{r}" for r in ("too_short", "too_long", "equals_username",
                                                         "equals_email_local")}
    used |= {f"user.register.error_username_{r}" for r in ("length", "chars")}
    used |= {f"user.register.error_email_{r}" for r in ("format", "domain")}
    used |= {f"user.register.error_sponsor_{r}" for r in ("format", "domain")}
    missing = sorted(k for k in used if not strings.has(k))
    assert not missing, missing
    assert len(used) > 60
