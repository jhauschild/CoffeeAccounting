"""core-b: app factory, middleware, deps, tokens, health, error handlers, strings."""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi import APIRouter, Depends, Form, Request
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError
from starlette.responses import Response

from app import strings
from app.db import write_session
from app.main import STATUS_KEYS, create_app
from app.services import sessions
from app.services.errors import NoPriceConfigured
from app.services.users import set_user_status
from app.timeutil import utcnow
from app.web import deps, tokens
from app.web.deps import UserContext, client_ip, csrf_token_for, form_csrf_token, require_csrf, require_user
from app.web.middleware import CSP
from app.web.templating import templates
from tests.conftest import reload_settings

PROD_ENV = {
    "ENVIRONMENT": "production",
    "PUBLIC_BASE_URL": "https://coffee.example.org",
    "SECRET_KEY": "Zq8v3mL1x9Rk2pT7wY4bN6cF0hJ5sD8gQ1aE3uI7oP",
    "MAIL_FROM": "coffee@example.org",
}


def _router() -> APIRouter:
    r = APIRouter()

    @r.get("/t/boom")
    def boom():
        raise RuntimeError("very secret detail /home/claude")

    @r.get("/t/locked")
    def locked():
        raise OperationalError("SELECT 1", {}, Exception("database is locked"))

    @r.get("/t/noprice")
    def noprice():
        raise NoPriceConfigured("internal text")

    @r.get("/t/me")
    def me(ctx: UserContext = Depends(require_user)):
        return {"user": str(ctx.user.id)}

    @r.get("/t/form")
    def form(request: Request):
        return {"csrf": csrf_token_for(request)}

    @r.get("/t/anonform")
    def anonform(request: Request):
        from app.web.templating import render

        return render(request, "user/forgot.html", {"csrf_token": form_csrf_token(request)})

    @r.post("/t/form", dependencies=[Depends(require_csrf)])
    def post(name: str = Form("")):
        return {"name": name}

    @r.post("/t/echo")
    async def echo(request: Request):
        return {"n": len(await request.body())}

    return r


@pytest.fixture
def client(app):  # overrides conftest's `client` so `login` applies to it
    app.include_router(_router())
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def prod_app(monkeypatch):
    for k, v in PROD_ENV.items():
        monkeypatch.setenv(k, v)
    reload_settings()
    return create_app()


# ----- headers, health ------------------------------------------------------------------------
def test_security_headers_and_no_store(client):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}
    h = r.headers
    assert h["content-security-policy"] == CSP and "default-src 'self'" in CSP and "frame-ancestors 'none'" in CSP
    assert "unsafe-inline" not in CSP
    assert h["x-content-type-options"] == "nosniff" and h["referrer-policy"] == "same-origin"
    assert h["cache-control"] == "no-store" and "strict-transport-security" not in h
    css = client.get("/static/app.css")
    assert css.status_code == 200 and "no-store" not in css.headers.get("cache-control", "")
    assert css.headers["content-security-policy"] == CSP
    assert "prefers-color-scheme: dark" in css.text and "http" not in css.text


def test_production_hsts_and_no_docs(monkeypatch):
    with TestClient(prod_app(monkeypatch), base_url="https://coffee.example.org") as c:
        r = c.get("/healthz")
        assert r.headers["strict-transport-security"].startswith("max-age=")
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert c.get(path).status_code == 404


@pytest.mark.parametrize("env", [
    {"PUBLIC_BASE_URL": "http://coffee.example.org"},
    {"SECRET_KEY": ""},
    {"SECRET_KEY": "short"},
    {"SECRET_KEY": "change-me-change-me-change-me-change-me"},
    {"MAIL_FROM": ""},
    {"MAIL_BACKEND": "console"},
])
def test_production_startup_refuses_insecure_config(monkeypatch, env):
    for k, v in {**PROD_ENV, **env}.items():
        monkeypatch.setenv(k, v)
    reload_settings()
    with pytest.raises(ValueError):
        create_app()


def test_readyz_ok_and_not_migrated(client, monkeypatch, tmp_path):
    assert client.get("/readyz").json() == {"status": "ok", "check": "ok"}
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'empty.db'}")
    reload_settings()
    r = client.get("/readyz")
    assert r.status_code == 503 and r.json()["check"] == "migrations"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'missing' / 'x.db'}")
    reload_settings()
    r = client.get("/readyz")
    assert r.status_code == 503 and r.json()["check"] == "database"


# ----- error handlers -------------------------------------------------------------------------
def test_error_handlers_hide_details(client):
    r = client.get("/t/boom")
    assert r.status_code == 500 and "very secret" not in r.text and "Traceback" not in r.text
    assert strings.t("error.internal") in r.text and r.headers["content-type"].startswith("text/html")
    r = client.get("/t/locked")
    assert r.status_code == 503 and strings.t("error.transient") in r.text and "locked" not in r.text
    r = client.get("/t/noprice")
    assert r.status_code == 400 and strings.t("error.no_price") in r.text and "internal text" not in r.text
    r = client.get("/nope/<script>")
    assert r.status_code == 404 and "<script>" not in r.text
    assert client.post("/healthz").status_code == 405


# ----- cross-site and size limits ---------------------------------------------------------------
def test_cross_site_posts_rejected(client):
    assert client.post("/t/echo", content=b"x").json() == {"n": 1}
    assert client.post("/t/echo", headers={"Origin": "http://testserver"}).status_code == 200
    assert client.post("/t/echo", headers={"Sec-Fetch-Site": "same-origin"}).status_code == 200
    assert client.post("/t/echo", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert client.post("/t/echo", headers={"Origin": "https://evil.example"}).status_code == 403
    assert client.post("/t/echo", headers={"Origin": "null"}).status_code == 403


def test_request_size_limit(client):
    assert client.post("/t/echo", content=b"x" * 60_000).status_code == 200
    assert client.post("/t/echo", content=b"x" * 70_000).status_code == 413

    def chunks():
        for _ in range(20):
            yield b"x" * 8192

    assert client.post("/t/echo", content=chunks()).status_code == 413


# ----- user session, CSRF ---------------------------------------------------------------
def test_require_user_and_rotation(client, login, user, db, global_admin):
    r = client.get("/t/me", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    raw = login(user)
    assert client.get("/t/me").json() == {"user": str(user.id)}
    with write_session() as w:
        set_user_status(w, admin=w.merge(global_admin), user_id=user.id, active=False)
    assert client.get("/t/me", follow_redirects=False).status_code == 303
    assert raw


def test_csrf_user_binding(client, login, user):
    assert client.post("/t/form", data={"name": "a"}).status_code == 403  # no binding at all
    login(user)
    token = client.get("/t/form").json()["csrf"]
    assert token
    assert client.post("/t/form", data={"name": "a", "csrf_token": token + "0"}).status_code == 403
    assert client.post("/t/form", data={"name": "a", "csrf_token": token}).json() == {"name": "a"}
    assert strings.t("error.csrf") in client.post("/t/form", data={}).text


def test_csrf_pre_session_cookie_binding(client, login, user):
    import re

    page = client.get("/t/anonform")
    cookie = client.cookies.get(deps.CSRF_COOKIE)
    assert cookie and "coffee_csrf=" in page.headers["set-cookie"] and "HttpOnly" in page.headers["set-cookie"]
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    assert token == tokens.csrf_token("anon", cookie)
    assert client.get("/t/anonform").text.count(token) == 1  # the same browser keeps its binding, no new cookie
    assert client.post("/t/form", data={"csrf_token": token}).json() == {"name": ""}
    assert client.post("/t/form", data={"csrf_token": token + "0"}).status_code == 403
    client.cookies.set(deps.CSRF_COOKIE, "x" * 65)  # over-long cookie values are not a binding
    assert client.post("/t/form", data={"csrf_token": tokens.csrf_token("anon", "x" * 65)}).status_code == 403
    client.cookies.set(deps.CSRF_COOKIE, cookie)
    login(user)  # a session replaces the pre-session binding
    assert client.post("/t/form", data={"csrf_token": token}).status_code == 403
    user_token = client.get("/t/form").json()["csrf"]
    assert user_token != token and client.post("/t/form", data={"csrf_token": user_token}).status_code == 200


def test_csrf_requires_binding(client):
    assert client.get("/t/form").json() == {"csrf": ""}
    assert client.post("/t/form", data={"csrf_token": ""}).status_code == 403


def test_last_seen_touched_by_request(client, user, db):
    old = utcnow() - timedelta(hours=2)
    with write_session() as w:
        s, raw = sessions.create_session(w, user.id, now=old)
    client.cookies.set(sessions.SESSION_COOKIE, raw)
    client.get("/t/me")
    db.expire_all()
    assert db.get(type(s), s.id).last_seen_at > old + timedelta(hours=1)


# ----- client IP --------------------------------------------------------------------------------
def _req(peer: str, xff: str | None = None) -> Request:
    headers = [(b"x-forwarded-for", xff.encode())] if xff else []
    return Request({"type": "http", "method": "GET", "path": "/", "headers": headers, "client": (peer, 1234),
                    "query_string": b""})


def test_client_ip_trusted_proxies(monkeypatch):
    assert client_ip(_req("203.0.113.5", "1.2.3.4")) == "203.0.113.5"  # no trusted proxies
    monkeypatch.setenv("TRUSTED_PROXY_IPS", "10.0.0.0/8, 192.168.1.1")
    reload_settings()
    assert client_ip(_req("10.1.2.3", "1.2.3.4")) == "1.2.3.4"
    assert client_ip(_req("10.1.2.3", "6.6.6.6, 1.2.3.4, 192.168.1.1")) == "1.2.3.4"  # spoofed left part ignored
    assert client_ip(_req("203.0.113.5", "1.2.3.4")) == "203.0.113.5"  # untrusted peer
    assert client_ip(_req("10.1.2.3", "garbage, 1.2.3.4")) == "1.2.3.4"
    assert client_ip(_req("10.1.2.3", "1.2.3.4, garbage")) == "10.1.2.3"
    assert client_ip(_req("10.1.2.3")) == "10.1.2.3"


# ----- cookies --------------------------------------------------------------------------------
def test_cookie_flags_production(monkeypatch):
    prod_app(monkeypatch)
    resp = Response()
    deps.set_session_cookie(resp, "tok")
    deps.set_csrf_cookie(resp, "anon")
    deps.set_pending_cookie(resp, "pid")
    cookies = resp.headers.getlist("set-cookie")
    assert len(cookies) == 3
    for c in cookies:
        low = c.lower()
        assert "httponly" in low and "secure" in low and "samesite=lax" in low and "path=/" in low
    assert "max-age=15552000" in cookies[0].lower() and "max-age=3600" in cookies[1].lower()


# ----- tokens ---------------------------------------------------------------------------------
def test_scan_token_sign_verify_expiry_tamper():
    now = utcnow()
    tok = tokens.make_scan_token("double", now=now)
    st = tokens.verify_scan_token(tok, "double", now=now + timedelta(minutes=29))
    assert st and st.kind == "double" and len(st.nonce) >= 16
    assert tokens.verify_scan_token(tok, "single", now=now) is None
    assert tokens.verify_scan_token(tok, "double", now=now + timedelta(minutes=31)) is None
    assert tokens.verify_scan_token(tok[:-1] + ("A" if tok[-1] != "A" else "B"), "double", now=now) is None
    assert tokens.make_scan_token("single") != tokens.make_scan_token("single")
    with pytest.raises(ValueError):
        tokens.make_scan_token("triple")


def test_csrf_tokens():
    tok = tokens.csrf_token("user", "abc")
    assert tokens.verify_csrf("user", "abc", tok)
    assert not tokens.verify_csrf("user", "abd", tok)
    assert not tokens.verify_csrf("admin", "abc", tok)
    assert not tokens.verify_csrf("user", None, tok) and not tokens.verify_csrf("user", "abc", None)


# ----- strings and templates --------------------------------------------------------------------
def test_strings_catalog(monkeypatch):
    for key in set(STATUS_KEYS.values()) | {"error.csrf", "error.internal", "error.no_price", "error.error"}:
        assert strings.has(key)
    monkeypatch.setenv("APP_TITLE", "Kaffeekasse")
    reload_settings()
    assert "Kaffeekasse" in strings.t("common.trust_notice")
    assert strings.t("no.such.key") == "no.such.key"

    class M:
        __name__ = "m"
        STRINGS = {"common.privacy": "x"}

    with pytest.raises(RuntimeError):
        strings._merge(strings.strings_common, M)


def test_templates_autoescape():
    assert templates.env.from_string("{{ x }}").render(x="<b>") == "&lt;b&gt;"
    assert templates.env.from_string("{{ 150|money }}").render() == "€1.50"
