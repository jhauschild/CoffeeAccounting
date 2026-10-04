"""FastAPI dependencies and request helpers shared by the user and admin routes.

Transactions: routes open writes explicitly with `with write_session() as db:` (so the
commit happens before the response is built); `get_read_db` is a dependency for reads.

Everything that resolves the browser is cached per request on `request.state`.
"""

from __future__ import annotations

import ipaddress
import logging
import secrets
import uuid
from collections.abc import Iterator
from dataclasses import dataclass

from fastapi import Request
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException
from starlette.responses import Response

from app.config import get_settings
from app.db import read_session, write_session
from app.models import User, UserSession
from app.services import pending, sessions
from app.web import tokens

log = logging.getLogger(__name__)

SESSION_COOKIE = sessions.SESSION_COOKIE
CSRF_COOKIE = "coffee_csrf"  # pre-session CSRF binding for the sign-in, registration and recovery forms
CSRF_COOKIE_MAX_AGE = 3600
MAX_CSRF_COOKIE_LENGTH = 64
PENDING_COOKIE = pending.PENDING_COOKIE
_UNSET = object()


@dataclass(frozen=True)
class UserContext:
    session: UserSession
    user: User


class Redirect(Exception):
    """Raise from a route/dependency to answer `303 See Other` to a fixed internal path."""

    def __init__(self, path: str) -> None:
        if not path.startswith("/") or path.startswith("//") or "\\" in path:
            raise ValueError("redirects must go to internal paths")
        super().__init__(path)
        self.path = path


class CSRFError(HTTPException):
    def __init__(self) -> None:
        super().__init__(status_code=403, detail="csrf")


# ----- database -------------------------------------------------------------------------------
def get_read_db() -> Iterator[Session]:
    with read_session() as db:
        yield db


# ----- client IP --------------------------------------------------------------------------------
def _is_trusted(ip: str, trusted) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in trusted)


def client_ip(request: Request) -> str:
    """Peer address; `X-Forwarded-For` is honored only when the peer is in TRUSTED_PROXY_IPS
    (the right-most address that is not itself a trusted proxy is used)."""
    peer = request.client.host if request.client else ""
    trusted = get_settings().trusted_proxies
    if not trusted or not _is_trusted(peer, trusted):
        return peer or "unknown"
    forwarded = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
    for candidate in reversed(forwarded):
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            return peer  # malformed chain: don't trust anything left of it
        if not _is_trusted(candidate, trusted):
            return candidate
    return forwarded[0] if forwarded else peer


# ----- user session ---------------------------------------------------------------------------
def current_user(request: Request) -> UserContext | None:
    """The browser's valid user session (or None). Touches `last_seen_at` at most hourly."""
    cached = getattr(request.state, "user_ctx", _UNSET)
    if cached is not _UNSET:
        return cached
    ctx = None
    raw = request.cookies.get(SESSION_COOKIE)
    if raw:
        with read_session() as db:
            found = sessions.resolve_session(db, raw, touch=False)
            db.expunge_all()  # keep the loaded objects usable after the read transaction ends
        if found is not None:
            session, user = found
            if sessions.needs_touch(session):
                try:
                    with write_session() as db:
                        sessions.touch_session(db, session.id)
                except OperationalError:  # busy database: skipping a last-seen update is harmless
                    log.info("skipped last_seen_at update (database busy)")
            ctx = UserContext(session, user)
    request.state.user_ctx = ctx
    return ctx


def require_user(request: Request) -> UserContext:
    """Dependency: a valid user session, else redirect to `/login`."""
    ctx = current_user(request)
    if ctx is None:
        raise Redirect("/login")
    return ctx


def forget_user(request: Request) -> None:
    """Drop the cached user context (after revoking/rotating the session in this request)."""
    request.state.user_ctx = None


# ----- CSRF -------------------------------------------------------------------------------------
def csrf_binding(request: Request) -> tuple[str, str] | None:
    """("user", session id) with a user session, else ("anon", pre-session cookie) if the browser holds one."""
    ctx = current_user(request)
    if ctx is not None:
        return "user", str(ctx.session.id)
    cookie = request.cookies.get(CSRF_COOKIE)
    if cookie and len(cookie) <= MAX_CSRF_COOKIE_LENGTH:
        return "anon", cookie
    return None


def csrf_token_for(request: Request) -> str:
    """Token for the hidden `csrf_token` field of forms on this page ("" if no binding)."""
    binding = csrf_binding(request)
    return tokens.csrf_token(*binding) if binding else ""


def form_csrf_token(request: Request) -> str:
    """Like `csrf_token_for`, but a browser without a binding gets a fresh random `coffee_csrf` cookie (set by
    `templating.render`) and a token for it. Use it on pages whose forms are submitted before sign-in."""
    binding = csrf_binding(request)
    if binding is None:
        value = secrets.token_urlsafe(24)
        request.state.new_csrf_cookie = value
        binding = ("anon", value)
    return tokens.csrf_token(*binding)


async def verify_csrf_form(request: Request, scope: str, key: str | None) -> None:
    """Check the form's `csrf_token` against an explicit binding (admin: ("admin", csrf_secret))."""
    form = await request.form()
    if not tokens.verify_csrf(scope, key, form.get(tokens.CSRF_FIELD)):
        raise CSRFError()


async def require_csrf(request: Request) -> None:
    """Dependency for user-side POST forms (token bound to the user session or the pre-session cookie)."""
    binding = await run_in_threadpool(csrf_binding, request)
    if binding is None:
        raise CSRFError()
    await verify_csrf_form(request, *binding)


# ----- cookies --------------------------------------------------------------------------------
def _set(response: Response, name: str, value: str, max_age: int) -> None:
    response.set_cookie(name, value, max_age=max_age, path="/", httponly=True,
                        secure=get_settings().cookie_secure, samesite="lax")


def _clear(response: Response, name: str) -> None:
    response.delete_cookie(name, path="/", httponly=True, secure=get_settings().cookie_secure, samesite="lax")


def set_session_cookie(response: Response, raw_token: str) -> None:
    _set(response, SESSION_COOKIE, raw_token, get_settings().session_lifetime_days * 86400)


def clear_session_cookie(response: Response) -> None:
    _clear(response, SESSION_COOKIE)


def set_csrf_cookie(response: Response, value: str) -> None:
    _set(response, CSRF_COOKIE, value, CSRF_COOKIE_MAX_AGE)


def set_pending_cookie(response: Response, pending_id: str) -> None:
    _set(response, PENDING_COOKIE, pending_id, int(pending.PENDING_TTL.total_seconds()))


def clear_pending_cookie(response: Response) -> None:
    _clear(response, PENDING_COOKIE)


def pending_id(request: Request) -> str | None:
    value = request.cookies.get(PENDING_COOKIE)
    return value if value and len(value) <= pending.MAX_PENDING_ID_LENGTH else None


def parse_uuid(value: str | None) -> uuid.UUID | None:
    """Parse a UUID from a path/form value; None if malformed."""
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError):
        return None
