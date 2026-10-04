"""Helpers shared by the user-web tests (owner: user-web agent)."""

from __future__ import annotations

import re

from sqlalchemy import func, select

from app.models import ConsumptionEvent, PaymentEvent, PendingAction, RateLimitEvent, User, UserSession

PASSWORD = "correct horse battery"
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


def make_account(db, name: str = "Alice Example", chair=None, username: str | None = None, password: str = PASSWORD):
    """A verified member with a real (cheap) Argon2 hash, so the sign-in form works."""
    from app.services.passwords import hash_password
    from tests import factories

    return factories.make_member(db, name, chair, username=username, password_hash=hash_password(password))


def sign_in(client, user_or_name, password: str = PASSWORD):
    """Submit the sign-in form like a browser would (fetches the form, and with it the CSRF cookie, first)."""
    username = user_or_name if isinstance(user_or_name, str) else user_or_name.username
    page = client.get("/login")
    assert page.status_code == 200
    data = {"csrf_token": field(page.text, "csrf_token"), "username": username, "password": password}
    return client.post("/login", data=data, follow_redirects=False)


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
