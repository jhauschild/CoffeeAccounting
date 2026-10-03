"""Helpers shared by the user-web tests (owner: user-web agent)."""

from __future__ import annotations

import re

from sqlalchemy import func, select

from app.models import ConsumptionEvent, PaymentEvent, PendingAction, RateLimitEvent, User, UserSession

ACCESS_CODE = "test-access-code"
_FIELD = r'name="{name}" value="([^"]*)"'


def field(html: str, name: str) -> str:
    m = re.search(_FIELD.format(name=re.escape(name)), html)
    assert m, f"form field {name!r} not found"
    return m.group(1)


def scan_token(client, kind: str) -> str:
    r = client.get(f"/coffee/{kind}")
    assert r.status_code == 200
    return field(r.text, "token")


def post_scan(client, kind: str, token: str | None = None, **kw):
    token = scan_token(client, kind) if token is None else token
    return client.post(f"/coffee/{kind}", data={"token": token}, follow_redirects=False, **kw)


def scan(client, kind: str = "single"):
    """GET + POST a fresh scan; returns the POST response (not followed)."""
    return post_scan(client, kind)


def pass_gate(client) -> None:
    r = client.post("/join", data={"code": ACCESS_CODE}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/join"


def register(client, name: str = "New Person", chair=None, *, token: str | None = None, extra: dict | None = None):
    """Submit the registration form like a browser would (fetches the form first)."""
    page = client.get("/register")
    assert page.status_code == 200
    data = {"csrf_token": field(page.text, "csrf_token"), "registration_token": token or field(page.text, "registration_token"),
            "display_name": name, "chair_id": str(chair.id), "privacy_ack": "1"}
    data.update(extra or {})
    return client.post("/register", data=data, follow_redirects=False)


def select_profile(client, user, *, csrf: str | None = None):
    if csrf is None:
        csrf = field(client.get("/profiles").text, "csrf_token")
    return client.post("/profiles/select", data={"csrf_token": csrf, "user_id": str(user.id)}, follow_redirects=False)


def count(db, model) -> int:
    db.rollback()  # fresh snapshot
    return db.scalar(select(func.count()).select_from(model))


def counts(db) -> dict:
    return {m.__name__: count(db, m) for m in (ConsumptionEvent, PaymentEvent, PendingAction, RateLimitEvent, User,
                                               UserSession)}


def events(db) -> list[ConsumptionEvent]:
    db.rollback()
    return list(db.scalars(select(ConsumptionEvent).order_by(ConsumptionEvent.created_at)))


def event_id_from(response) -> str:
    assert response.status_code == 303, response.status_code
    loc = response.headers["location"]
    assert loc.startswith("/coffee/done/"), loc
    return loc.rsplit("/", 1)[1]
