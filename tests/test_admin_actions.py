"""Admin actions over HTTP: payments, adjustments, reversals, merge, deactivation, session revocation,
chair change, prices, chairs, audit entries."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app.db import read_session, write_session
from app.models import (
    AuditLog, Chair, ConsumptionEvent, PaymentEvent, Price, User, UserSession,
)
from app.services import ledger, sessions
from app.timeutil import utcnow
from tests import factories
from tests.admin_support import fast_hasher, login_as, make_real_admin, new_client  # noqa: F401


@pytest.fixture
def gc(app):
    """(client, csrf) of a global admin."""
    admin_id, _ = make_real_admin(username="boss")
    c = new_client(app)
    return c, login_as(c, admin_id)


@pytest.fixture
def cc(app, chair):
    admin_id, _ = make_real_admin(role="chair", chairs=[chair], username="chairadmin")
    c = new_client(app)
    return c, login_as(c, admin_id)


def post(pair, path, **data):
    client, csrf = pair
    return client.post(path, data={"csrf_token": csrf, **data}, follow_redirects=False)


def actions():
    with read_session() as r:
        return [a.action for a in r.scalars(select(AuditLog).order_by(AuditLog.id))]


def count(model):
    with read_session() as r:
        return r.scalar(select(func.count()).select_from(model))


def totals(user_id):
    with read_session() as r:
        return ledger.get_totals(r, user_id)


@pytest.fixture
def alice(db, chair, price):
    return factories.make_user(db, "Alice Müller", chair)


# ----- payments -------------------------------------------------------------------------------
@pytest.mark.parametrize("text,cents", [("12.50", 1250), ("12,50", 1250), ("7", 700), ("-3,5", -350)])
def test_payment_money_parsing_accepts(gc, alice, text, cents):
    r = post(gc, f"/admin/users/{alice.id}/payment", amount=text, note="cash")
    assert r.status_code == 303 and "msg=payment_recorded" in r.headers["location"]
    assert totals(alice.id).paid_amount_cents == cents
    assert "payment.recorded" in actions()


@pytest.mark.parametrize("text", ["12.505", "twelve", "", "0", "1e3", "€5", "1.000,00", "-"])
def test_payment_money_parsing_rejects(gc, alice, text):
    r = post(gc, f"/admin/users/{alice.id}/payment", amount=text)
    assert r.status_code == 303 and "err=invalid_amount" in r.headers["location"]
    assert count(PaymentEvent) == 0 and "payment.recorded" not in actions()
    assert "not valid" in gc[0].get(r.headers["location"]).text  # the flash message is shown


def test_payment_correction_and_chair_admin_scope(gc, cc, alice):
    post(gc, f"/admin/users/{alice.id}/payment", amount="10")
    with read_session() as r:
        original_id = r.scalars(select(PaymentEvent)).one().id
    r = post(cc, f"/admin/users/{alice.id}/payment", amount="-2,50", correction_of=str(original_id), note="oops")
    assert "msg=payment_recorded" in r.headers["location"]
    assert totals(alice.id).paid_amount_cents == 750
    again = post(cc, f"/admin/users/{alice.id}/payment", amount="1", correction_of=str(original_id))
    assert "err=conflict" in again.headers["location"]  # each payment is corrected at most once
    assert "payment.corrected" in actions()
    page = cc[0].get(f"/admin/users/{alice.id}").text
    assert "payment correction" in page and "corrected" in page


# ----- adjustments ----------------------------------------------------------------------------
def test_adjustment_default_amount_override_and_prefill(gc, alice):
    page = gc[0].get(f"/admin/users/{alice.id}").text
    assert 'data-unit-price="0.50"' in page and 'placeholder="€0.50"' in page  # pre-fill info (price 50 cents)
    post(gc, f"/admin/users/{alice.id}/adjustment", quantity="3", amount="", note="forgot")
    t = totals(alice.id)
    assert (t.consumed_shots, t.consumed_amount_cents) == (3, 150)  # quantity x current price
    post(gc, f"/admin/users/{alice.id}/adjustment", quantity="2", amount="0,80")
    t = totals(alice.id)
    assert (t.consumed_shots, t.consumed_amount_cents) == (5, 230)  # explicit override
    post(gc, f"/admin/users/{alice.id}/adjustment", quantity="-1", amount="")
    assert totals(alice.id).consumed_amount_cents == 180  # negative quantity -> negative default amount
    with read_session() as r:
        events = list(r.scalars(select(ConsumptionEvent).order_by(ConsumptionEvent.created_at)))
        assert {e.type for e in events} == {"adjustment"} and all(e.admin_id for e in events)
        assert events[0].note == "forgot"
    assert actions().count("event.adjustment") == 3


@pytest.mark.parametrize("qty,amount", [("0", ""), ("1.5", ""), ("abc", ""), ("1", "-0,50"), ("1", "x"), ("100000", "")])
def test_adjustment_rejects_bad_input(gc, alice, qty, amount):
    r = post(gc, f"/admin/users/{alice.id}/adjustment", quantity=qty, amount=amount)
    assert "err=" in r.headers["location"] and count(ConsumptionEvent) == 0


def test_adjustment_without_price_needs_explicit_amount(gc, db, chair):
    user = factories.make_user(db, "No Price", chair)
    r = post(gc, f"/admin/users/{user.id}/adjustment", quantity="1", amount="")
    assert "err=no_price" in r.headers["location"]
    r = post(gc, f"/admin/users/{user.id}/adjustment", quantity="1", amount="0,40")
    assert "msg=adjustment_recorded" in r.headers["location"]


# ----- reversal -------------------------------------------------------------------------------
def test_reverse_event_once_only_and_not_foreign(gc, cc, db, alice, other_chair):
    events = factories.add_events(db, alice, ["single", "double"])
    other = factories.make_user(db, "Other", other_chair)
    foreign = factories.add_events(db, other, "single")[0]
    base = f"/admin/users/{alice.id}/events"
    r = post(cc, f"{base}/{events[1].id}/reverse", note="mistake")
    assert "msg=event_reversed" in r.headers["location"]
    assert totals(alice.id).consumed_shots == 1
    assert "err=already_reversed" in post(gc, f"{base}/{events[1].id}/reverse").headers["location"]
    with read_session() as r2:
        reversal_id = r2.scalars(select(ConsumptionEvent).where(ConsumptionEvent.type == "reversal")).one().id
    assert "err=conflict" in post(gc, f"{base}/{reversal_id}/reverse").headers["location"]  # a reversal cannot be reversed
    assert "err=not_found" in post(gc, f"{base}/{foreign.id}/reverse").headers["location"]  # another profile's event
    assert totals(other.id).consumed_shots == 1  # untouched
    assert post(cc, f"/admin/users/{other.id}/events/{foreign.id}/reverse").status_code == 403
    assert "event.reversed" in actions()
    page = gc[0].get(f"/admin/users/{alice.id}").text
    assert page.count(">Reverse<") == 1  # only the not-yet-reversed single is offered


def test_reversal_after_price_change_returns_original_amount(gc, db, alice):
    event = factories.add_events(db, alice, "double")[0]
    factories.set_price(db, 99, effective_from=utcnow())
    post(gc, f"/admin/users/{alice.id}/events/{event.id}/reverse")
    t = totals(alice.id)
    assert (t.consumed_shots, t.consumed_amount_cents) == (0, 0)


# ----- status, sessions, rename, chair --------------------------------------------------------
def test_deactivate_reactivate_and_user_sessions(gc, cc, db, alice):
    factories.make_session(db, alice, raw_token="token-1")
    factories.make_session(db, alice, raw_token="token-2")
    assert "2 active" in gc[0].get(f"/admin/users/{alice.id}").text
    r = post(cc, f"/admin/users/{alice.id}/sessions/revoke")
    assert "msg=user_sessions_revoked" in r.headers["location"]
    with read_session() as r2:
        assert sessions.resolve_session(r2, "token-1") is None and sessions.active_session_count(r2, alice.id) == 0
    r = post(cc, f"/admin/users/{alice.id}/status", active="0")
    assert "msg=user_deactivated" in r.headers["location"]
    with read_session() as r2:
        assert r2.get(User, alice.id).status == "inactive"
    assert "Reactivate" in gc[0].get(f"/admin/users/{alice.id}").text
    post(gc, f"/admin/users/{alice.id}/status", active="1")
    with read_session() as r2:
        assert r2.get(User, alice.id).status == "active"
    assert post(cc, f"/admin/users/{alice.id}/status", active="x").status_code == 404
    assert {"user.sessions_revoked", "user.deactivated", "user.reactivated"} <= set(actions())


def test_deactivated_user_cannot_scan(gc, db, alice, login, client):
    login(alice)
    post(gc, f"/admin/users/{alice.id}/status", active="0")
    # GET only serves the auto-submit page (no state change); the POST path is covered in test_user_scan.
    r = client.get("/coffee/single", follow_redirects=False)
    assert r.status_code == 200 and "recorded" not in r.text.lower()
    assert count(ConsumptionEvent) == 0


def test_rename_and_global_only_chair_change(gc, cc, alice, other_chair, chair):
    assert "msg=user_updated" in post(cc, f"/admin/users/{alice.id}/rename", display_name="  Alice  Q ").headers["location"]
    with read_session() as r:
        u = r.get(User, alice.id)
        assert u.display_name == "Alice Q" and u.normalized_name == "alice q"
    assert post(cc, f"/admin/users/{alice.id}/chair", chair_id=str(other_chair.id)).status_code == 403
    r = post(gc, f"/admin/users/{alice.id}/chair", chair_id=str(other_chair.id))
    assert "msg=chair_changed" in r.headers["location"]
    with read_session() as r2:
        assert r2.get(User, alice.id).chair_id == other_chair.id
        entry = r2.scalars(select(AuditLog).where(AuditLog.action == "user.chair_changed")).one()
        assert entry.actor_type == "admin" and entry.meta["to_chair_id"] == str(other_chair.id)
    assert cc[0].get(f"/admin/users/{alice.id}", follow_redirects=False).status_code == 403  # left the chair admin's scope
    assert "user.updated" in actions()
    assert "err=" in post(gc, f"/admin/users/{alice.id}/chair", chair_id="").headers["location"]


# ----- merge ----------------------------------------------------------------------------------
def test_merge_moves_nothing_but_combines_totals(gc, cc, db, alice, chair):
    dup = factories.make_user(db, "Alice Mueller", chair)
    factories.add_events(db, alice, "single")
    factories.add_events(db, dup, "double")
    factories.make_payment(db, dup, factories.make_admin(db, "global"), 100)
    page = gc[0].get(f"/admin/users/{alice.id}/merge?q=alice+mueller").text
    assert "Alice Mueller" in page
    assert post(cc, f"/admin/users/{dup.id}/merge", target_id=str(alice.id)).status_code == 403
    assert post(gc, f"/admin/users/{dup.id}/merge", target_id=str(dup.id)).headers["location"].endswith("err=invalid_input")
    r = post(gc, f"/admin/users/{dup.id}/merge", target_id=str(alice.id))
    assert r.headers["location"] == f"/admin/users/{alice.id}?msg=merged"
    t = totals(alice.id)
    assert (t.consumed_shots, t.consumed_amount_cents, t.paid_amount_cents) == (3, 150, 100)
    with read_session() as r2:
        assert r2.get(User, dup.id).status == "merged"
        assert all(e.user_id in (alice.id, dup.id) for e in r2.scalars(select(ConsumptionEvent)))  # nothing moved
        assert r2.scalar(select(func.count()).select_from(ConsumptionEvent).where(ConsumptionEvent.user_id == dup.id)) == 1
    again = gc[0].get(f"/admin/users/{dup.id}", follow_redirects=False)
    assert again.status_code == 303 and again.headers["location"] == f"/admin/users/{alice.id}"
    assert "Alice Mueller" in gc[0].get(f"/admin/users/{alice.id}").text  # listed as merged profile
    assert "Alice Mueller" not in gc[0].get("/admin/users").text
    assert "user.merged" in actions()


# ----- prices ---------------------------------------------------------------------------------
def test_add_price_now_future_and_rejections(gc, cc, price):
    assert post(cc, "/admin/prices", price="0.60").status_code == 403
    assert count(Price) == 1
    r = post(gc, "/admin/prices", price="0,60", note="new beans")
    assert "msg=price_added" in r.headers["location"]
    future = "2099-01-01T08:00"
    assert "msg=price_added" in post(gc, "/admin/prices", price="0.70", effective_from=future).headers["location"]
    for bad in ({"price": "0.505"}, {"price": "-1"}, {"price": "abc"}, {"price": "0.5", "effective_from": "2001-01-01T00:00"},
                {"price": "0.5", "effective_from": "garbage"}, {"price": "0.70", "effective_from": future}):
        assert "err=" in post(gc, "/admin/prices", **bad).headers["location"], bad
    with read_session() as r2:
        rows = list(r2.scalars(select(Price).order_by(Price.effective_from)))
        assert [p.price_per_shot_cents for p in rows] == [50, 60, 70]
        assert rows[2].effective_from.year == 2099 and rows[1].created_by_admin_id is not None
        from app.services.prices import get_price_in_effect
        assert get_price_in_effect(r2).price_per_shot_cents == 60  # the future price is not used yet
    page = gc[0].get("/admin/prices").text
    assert "€0.70" in page and "new beans" in page and "boss" in page and "command line" in page
    assert actions().count("price.added") == 2


def test_price_change_does_not_touch_old_events(gc, db, alice):
    before = factories.add_events(db, alice, "single")[0]
    post(gc, "/admin/prices", price="0.90")
    with read_session() as r:
        e = r.get(ConsumptionEvent, before.id)
        assert (e.unit_price_cents, e.amount_cents) == (50, 50)


# ----- chairs ---------------------------------------------------------------------------------
def test_chairs_crud_is_global_and_audited(gc, cc, chair):
    assert cc[0].get("/admin/chairs", follow_redirects=False).status_code == 403
    assert "msg=chair_created" in post(gc, "/admin/chairs", full_name="Chair of Beans", short_name="BEAN").headers["location"]
    assert "err=conflict" in post(gc, "/admin/chairs", full_name="Dup", short_name="BEAN").headers["location"]
    assert "err=" in post(gc, "/admin/chairs", full_name="", short_name="X").headers["location"]
    with read_session() as r:
        bean_id = r.scalars(select(Chair).where(Chair.short_name == "BEAN")).one().id
    assert "msg=chair_renamed" in post(gc, f"/admin/chairs/{bean_id}/rename", full_name="Beans", short_name="BNS").headers["location"]
    assert "msg=chair_deactivated" in post(gc, f"/admin/chairs/{bean_id}/active", active="0").headers["location"]
    with read_session() as r:
        assert not r.get(Chair, bean_id).active
    assert "msg=chair_reactivated" in post(gc, f"/admin/chairs/{bean_id}/active", active="1").headers["location"]
    assert post(gc, "/admin/chairs/not-a-uuid/active", active="1").status_code == 404
    page = gc[0].get("/admin/chairs").text
    assert "Beans" in page and "never deleted" in page
    assert {"chair.created", "chair.renamed", "chair.deactivated", "chair.reactivated"} <= set(actions())
    assert count(Chair) == 2  # nothing is ever deleted


def test_chair_label_setting_is_used(gc, monkeypatch):
    from tests.conftest import reload_settings
    monkeypatch.setenv("CHAIR_LABEL", "Coffee group")
    reload_settings()
    page = gc[0].get("/admin/chairs").text
    assert "Coffee groups" in page


# ----- audit view -----------------------------------------------------------------------------
def test_audit_view_filter_and_global_only(gc, cc, alice):
    post(gc, f"/admin/users/{alice.id}/payment", amount="5")
    page = gc[0].get("/admin/audit").text
    assert "payment.recorded" in page and "boss" in page
    only = gc[0].get("/admin/audit?action=price").text
    assert "payment.recorded" not in only
    assert cc[0].get("/admin/audit", follow_redirects=False).status_code == 403
    detail = gc[0].get(f"/admin/users/{alice.id}").text
    assert "payment.recorded" in detail  # user detail shows the profile's audit history
