"""Dependencies and helpers shared by all `/admin` routes (owner: admin agent).

Authorization is enforced server-side by dependencies, never by hidden UI:

* `live_admin_session`  any live admin session (logout and the TOTP enrolment pages use this)
* `require_admin`       a live session whose admin has finished the one-time TOTP enrolment when
                        `BALANCE_TOTP_REQUIRED` demands it (otherwise redirect to the enrolment);
                        yields `AdminContext`
* `require_global_admin` complete session of a global administrator
* `admin_user_access`   `require_admin` + the `{user_id}` path parameter must be in scope
* `require_admin_csrf`  every state-changing admin form must carry the session-bound token
* `require_stepup`      the confirm POST of a balance-changing action: signed payload, one-time nonce
                        and an open step-up window or a fresh TOTP/recovery code (app/services/stepup.py);
                        yields the `StepupGrant` that `stepup.run` needs. The only route that
                        executes balance changes (`POST /admin/stepup/confirm`) declares it.

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
from fastapi.routing import APIRoute
from sqlalchemy.exc import OperationalError
from starlette.responses import RedirectResponse, Response

from app.config import get_settings
from app.db import read_session, write_session
from app.models import AdminSession, AdminUser
from app.services import admin_auth, authz, stepup
from app.services.errors import Forbidden, NotFound, ServiceError
from app.strings import has, t
from app.timeutil import format_local
from app.web import templating, tokens
from app.web.deps import Redirect, client_ip, parse_uuid, verify_csrf_form
from app.web.middleware import no_store

log = logging.getLogger(__name__)

LOGIN_CSRF_COOKIE = "coffee_admin_login"
LOGIN_PATH = "/admin/login"
ENROL_PATH = "/admin/totp/setup"
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


def require_admin(request: Request) -> AdminContext:
    session, admin = live_admin_session(request)
    if admin_auth.enrolment_required(admin):
        raise Redirect(ENROL_PATH)
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
    """CSRF check for admin POSTs, bound to the admin session."""
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


# ----- step-up (balance-changing actions) -------------------------------------------------------
class StepupResponse(Exception):
    """Raised by `require_stepup` to answer with a page (confirm page with code prompt, error page)
    instead of running the route; `StepupRoute` turns it into the response."""

    def __init__(self, response: Response):
        super().__init__("step-up response")
        self.response = response


class StepupRoute(APIRoute):
    """Route class for routers that use `require_stepup`: dependencies cannot return a response, so a
    `StepupResponse` raised from one is converted here."""

    def get_route_handler(self):
        original = super().get_route_handler()

        async def handler(request: Request) -> Response:
            try:
                return await original(request)
            except StepupResponse as exc:
                return exc.response

        return handler


def confirm_page(request: Request, ctx: AdminContext, view: stepup.ConfirmView, token: str, nonce: str, *,
                 needs_code: bool, error: str | None = None, status_code: int = 200) -> Response:
    """The read-only confirm page: what will be booked, the signed payload and nonce, and (only if the
    step-up window is closed) the code field. Reused by every step-up action."""
    return no_store(page(request, ctx, "admin/confirm.html",
                         {"view": view, "payload": token, "nonce": nonce, "needs_code": needs_code, "error": error},
                         status_code=status_code))


def needs_code(session: AdminSession) -> bool:
    """Would a confirm POST right now ask for a code (window closed and BALANCE_TOTP_REQUIRED on)?"""
    if not get_settings().balance_totp_required:
        return False
    with read_session() as db:
        fresh = db.get(AdminSession, session.id)
        return fresh is None or not admin_auth.has_open_stepup(fresh)


def preview(request: Request, ctx: AdminContext, kind: str, raw: dict, *, error_path: str):
    """Entry-form POST of a step-up action: render the confirm page, or go back to `error_path` with the
    flash key of the `ServiceError` the real action would raise. Writes nothing."""
    try:
        prepared = stepup.prepare(admin=ctx.admin, session_id=ctx.session.id, kind=kind, raw=raw,
                                  ip=client_ip(request))
    except ServiceError as exc:
        return back(error_path, err=error_key(exc))
    return confirm_page(request, ctx, prepared.view, prepared.token, prepared.nonce,
                        needs_code=needs_code(ctx.session))


async def require_stepup(request: Request, ctx: AdminContext = Depends(require_admin)) -> stepup.StepupGrant:
    """Dependency of every balance-changing POST (see module docstring and `app/services/stepup.py`).

    Reads `payload`, `nonce` and `code` from the form. Without a valid signed payload for this admin and
    session, an unspent nonce, and an open step-up window (or a correct fresh code) nothing is executed:
    the route body is never reached. Pair it with `require_admin_csrf` and `StepupRoute`.
    """
    form = await request.form()
    ip = client_ip(request)
    try:
        return await run_in_threadpool(
            stepup.authorise, admin=ctx.admin, session=ctx.session, token=form.get("payload"),
            nonce=form.get("nonce"), code=form.get("code"), ip=ip)
    except stepup.PayloadInvalid:
        raise StepupResponse(no_store(page(request, ctx, "admin/stepup_invalid.html", status_code=400))) from None
    except stepup.AlreadyExecuted as exc:
        raise StepupResponse(back(exc.back_path, msg="already_executed")) from None
    except stepup.SessionGone:
        raise Redirect(LOGIN_PATH) from None
    except stepup.CodeRequired as exc:
        try:
            view = await run_in_threadpool(stepup.view_for, admin=ctx.admin, payload=exc.payload, ip=ip)
        except ServiceError as err:
            raise StepupResponse(back(stepup.REGISTRY[exc.payload.kind].back_path(exc.payload.params),
                                      err=error_key(err))) from None
        status = {"code_required": 200, "invalid_code": 401, "rate_limited": 429}[exc.error or "code_required"]
        raise StepupResponse(confirm_page(request, ctx, view, form.get("payload"), exc.payload.nonce,
                                          needs_code=True, error=exc.error, status_code=status)) from None
