"""Dependencies and helpers shared by all `/admin` routes (owner: admin agent).

Authorization is enforced server-side by dependencies, never by hidden UI:

* `live_admin_session`  any live admin session (also a pending, second-factor-less one)
* `pending_admin`       a live session that is *not* complete (needs TOTP or enrollment)
* `require_admin`       a complete session (password + TOTP when required); yields `AdminContext`
* `require_global_admin` complete session of a global administrator
* `admin_user_access`   `require_admin` + the `{user_id}` path parameter must be in scope
* `require_admin_csrf`  every state-changing admin form must carry the session-bound token

Normal-user sessions use another cookie (`coffee_session`, path `/`) and are never consulted here.
The test `tests/test_admin_routes_authz.py` enumerates every `/admin` route and checks that each
one carries one of these dependencies.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass

from fastapi import Depends, Request
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.exc import OperationalError
from starlette.responses import RedirectResponse, Response

from app.config import get_settings
from app.db import read_session, write_session
from app.models import AdminSession, AdminUser
from app.services import admin_auth, authz
from app.services.errors import Forbidden, NotFound, ServiceError
from app.strings import has, t
from app.timeutil import format_local
from app.web import templating, tokens
from app.web.deps import CSRFError, Redirect, parse_uuid, verify_csrf_form

log = logging.getLogger(__name__)

LOGIN_CSRF_COOKIE = "coffee_admin_login"
LOGIN_PATH = "/admin/login"
_UNSET = object()

# Jinja helpers for the admin templates (the environment is shared with the other templates).
templating.templates.env.filters["local"] = lambda dt, fmt="%Y-%m-%d %H:%M": format_local(dt, fmt) if dt else ""


@dataclass(frozen=True)
class AdminContext:
    session: AdminSession
    admin: AdminUser

    @property
    def csrf(self) -> str:
        return tokens.csrf_token("admin", self.session.csrf_secret)

    @property
    def is_global(self) -> bool:
        return self.admin.role == "global"


# ----- session resolution ---------------------------------------------------------------------
def _resolve(request: Request) -> tuple[AdminSession, AdminUser] | None:
    cached = getattr(request.state, "admin_pair", _UNSET)
    if cached is not _UNSET:
        return cached
    pair = None
    raw = request.cookies.get(admin_auth.ADMIN_COOKIE)
    if raw:
        with read_session() as db:
            found = admin_auth.resolve_session(db, raw)
            db.expunge_all()
        if found is not None:
            pair = found
            if admin_auth.needs_touch(found[0]):
                try:
                    with write_session() as db:
                        admin_auth.touch_session(db, found[0].id)
                except OperationalError:  # busy database: skipping a last-seen update is harmless
                    log.info("skipped admin last_seen update (database busy)")
    request.state.admin_pair = pair
    return pair


def forget_admin(request: Request) -> None:
    request.state.admin_pair = None


def live_admin_session(request: Request) -> tuple[AdminSession, AdminUser]:
    pair = _resolve(request)
    if pair is None:
        raise Redirect(LOGIN_PATH)
    return pair


def pending_admin(request: Request) -> tuple[AdminSession, AdminUser]:
    session, admin = live_admin_session(request)
    if admin_auth.is_complete(session, admin):
        raise Redirect("/admin")
    return session, admin


def require_admin(request: Request) -> AdminContext:
    session, admin = live_admin_session(request)
    if not admin_auth.is_complete(session, admin):
        raise Redirect(LOGIN_PATH)
    return AdminContext(session, admin)


def require_global_admin(ctx: AdminContext = Depends(require_admin)) -> AdminContext:
    authz.require_global(ctx.admin)
    return ctx


def admin_user_access(user_id: str, ctx: AdminContext = Depends(require_admin)) -> uuid.UUID:
    """The `{user_id}` path parameter, scope-checked (404 unknown/malformed, 403 out of scope)."""
    uid = parse_uuid(user_id)
    if uid is None:
        raise NotFound("user not found")
    with read_session() as db:
        authz.ensure_admin_can_access_user(db, ctx.admin, uid)
    return uid


def global_user_access(user_id: str, ctx: AdminContext = Depends(require_global_admin)) -> uuid.UUID:
    uid = parse_uuid(user_id)
    if uid is None:
        raise NotFound("user not found")
    with read_session() as db:
        authz.ensure_admin_can_access_user(db, ctx.admin, uid)
    return uid


async def require_admin_csrf(request: Request) -> None:
    """CSRF check for admin POSTs, bound to the admin session (pending sessions included)."""
    pair = await run_in_threadpool(live_admin_session, request)
    await verify_csrf_form(request, "admin", pair[0].csrf_secret)


# ----- login CSRF (before a session exists): double-submit cookie ------------------------------
def login_csrf_token(cookie_value: str) -> str:
    return tokens.csrf_token("admin-login", cookie_value)


async def verify_login_csrf(request: Request) -> None:
    cookie = request.cookies.get(LOGIN_CSRF_COOKIE)
    await verify_csrf_form(request, "admin-login", cookie)


# ----- cookies --------------------------------------------------------------------------------
def set_admin_cookie(response: Response, raw_token: str, max_age: int) -> None:
    response.set_cookie(admin_auth.ADMIN_COOKIE, raw_token, max_age=max_age, path="/admin", httponly=True,
                        secure=get_settings().cookie_secure, samesite="lax")


def clear_admin_cookie(response: Response) -> None:
    response.delete_cookie(admin_auth.ADMIN_COOKIE, path="/admin", httponly=True,
                           secure=get_settings().cookie_secure, samesite="lax")


def session_max_age(session: AdminSession) -> int:
    return max(60, int((session.expires_at - session.created_at).total_seconds()))


# ----- rendering and redirects ----------------------------------------------------------------
def page(request: Request, ctx: AdminContext | None, template: str, context: dict | None = None, *,
         status_code: int = 200):
    """Render an admin template with the standard context (csrf token, admin, flash message)."""
    data = {"admin": ctx.admin if ctx else None, "is_global": bool(ctx and ctx.is_global),
            "csrf_token": ctx.csrf if ctx else "", "show_nav": ctx is not None}
    msg = request.query_params.get("msg")
    err = request.query_params.get("err")
    data["flash_ok"] = t(f"admin.msg.{msg}") if msg and has(f"admin.msg.{msg}") else None
    data["flash_err"] = t(f"admin.err.{err}") if err and has(f"admin.err.{err}") else None
    data.update(context or {})
    return templating.render(request, template, data, status_code=status_code)


def back(path: str, *, msg: str | None = None, err: str | None = None) -> RedirectResponse:
    """303 to a fixed internal path with a whitelisted flash key (`?msg=` / `?err=`)."""
    if not path.startswith("/admin") or "\\" in path or path.startswith("//"):
        raise ValueError("admin redirects stay inside /admin")
    key, value = ("msg", msg) if msg else ("err", err)
    suffix = f"?{key}={value}" if value else ""
    return RedirectResponse(path + suffix, status_code=303)


def error_key(exc: ServiceError) -> str:
    """Flash key for a service error that is shown on the form page (authorization errors are not)."""
    if isinstance(exc, Forbidden):
        raise exc
    return exc.code if has(f"admin.err.{exc.code}") else "error"
