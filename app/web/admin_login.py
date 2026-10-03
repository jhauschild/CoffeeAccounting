"""Admin login (password + TOTP), enrollment, logout, own account (owner: admin agent)."""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, Form, Request
from starlette.responses import RedirectResponse

from app.db import read_session, write_session
from app.services import admin_auth, exports
from app.services.errors import InvalidInput
from app.web import admin_deps as ad
from app.web.deps import Redirect, client_ip
from app.web.middleware import no_store

router = APIRouter()


def _login_page(request: Request, *, error: str | None = None, status_code: int = 200, username: str = ""):
    cookie = request.cookies.get(ad.LOGIN_CSRF_COOKIE) or secrets.token_urlsafe(24)
    response = ad.page(request, None, "admin/login.html",
                       {"csrf_token": ad.login_csrf_token(cookie), "error": error, "username": username},
                       status_code=status_code)
    response.set_cookie(ad.LOGIN_CSRF_COOKIE, cookie, max_age=3600, path="/admin", httponly=True,
                        secure=ad.get_settings().cookie_secure, samesite="lax")
    return response


def _next_url(stage: str) -> str:
    return {"totp": "/admin/totp", "enroll": "/admin/totp/setup"}.get(stage, "/admin")


@router.get("/login")
def login_form(request: Request):
    pair = ad._resolve(request)
    if pair is not None:
        session, admin = pair
        if admin_auth.is_complete(session, admin):
            raise Redirect("/admin")
        raise Redirect("/admin/totp" if admin.totp_enabled else "/admin/totp/setup")
    return _login_page(request)


@router.post("/login", dependencies=[Depends(ad.verify_login_csrf)])
def login_submit(request: Request, username: str = Form("", max_length=200), password: str = Form("", max_length=1000)):
    ip = client_ip(request)
    # start_login manages its own short write transactions (Argon2 runs outside the write lock);
    # failures are committed (rate-limit hit + audit) before the error page.
    outcome = admin_auth.start_login(username=username, password=password, ip=ip,
                                     old_raw_token=request.cookies.get(admin_auth.ADMIN_COOKIE))
    if outcome.status == "limited":
        return _login_page(request, error="rate_limited", status_code=429, username=username)
    if outcome.status != "ok":
        return _login_page(request, error="invalid_login", status_code=401, username=username)
    response = RedirectResponse(_next_url(outcome.stage), status_code=303)
    ad.set_admin_cookie(response, outcome.raw_token, ad.session_max_age(outcome.session))
    return no_store(response)


# ----- second factor ----------------------------------------------------------------------------
@router.get("/totp")
def totp_form(request: Request, pair=Depends(ad.pending_admin)):
    session, admin = pair
    if not admin.totp_enabled:
        raise Redirect("/admin/totp/setup")
    return ad.templating.render(request, "admin/totp.html", {"csrf_token": ad.tokens.csrf_token("admin", session.csrf_secret),
                                                              "error": None, "admin": admin, "is_global": False})


@router.post("/totp", dependencies=[Depends(ad.require_admin_csrf)])
def totp_submit(request: Request, code: str = Form("", max_length=64), pair=Depends(ad.pending_admin)):
    session, admin = pair
    if not admin.totp_enabled:
        raise Redirect("/admin/totp/setup")
    with write_session() as db:
        outcome = admin_auth.verify_second_factor(db, session=session, admin=admin, code=code,
                                                  ip=client_ip(request))
        db.expunge_all()
    if outcome.status != "ok":
        limited = outcome.status == "limited"
        return ad.templating.render(
            request, "admin/totp.html",
            {"csrf_token": ad.tokens.csrf_token("admin", session.csrf_secret),
             "error": "rate_limited" if limited else "invalid_code", "admin": admin, "is_global": False},
            status_code=429 if limited else 401)
    response = RedirectResponse("/admin", status_code=303)
    ad.set_admin_cookie(response, outcome.raw_token, ad.session_max_age(outcome.session))
    return no_store(response)


@router.get("/totp/setup")
def setup_form(request: Request, pair=Depends(ad.live_admin_session)):
    session, admin = pair
    if admin.totp_enabled:
        raise Redirect("/admin")
    with write_session() as db:
        secret = admin_auth.begin_enrollment(db, admin)
    return _setup_page(request, session, admin, secret, admin_auth.totp_uri(admin, secret))


def _setup_page(request, session, admin, secret, uri, *, error=None, status_code=200):
    grouped = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
    return ad.templating.render(
        request, "admin/totp_setup.html",
        {"csrf_token": ad.tokens.csrf_token("admin", session.csrf_secret), "qr_svg": exports.qr_svg(uri, None, standalone=False),
         "secret": grouped, "error": error, "admin": admin, "is_global": False}, status_code=status_code)


@router.post("/totp/setup", dependencies=[Depends(ad.require_admin_csrf)])
def setup_submit(request: Request, code: str = Form("", max_length=64), pair=Depends(ad.live_admin_session)):
    session, admin = pair
    if admin.totp_enabled:
        raise Redirect("/admin")
    with write_session() as db:
        secret = admin_auth.begin_enrollment(db, admin)
        uri = admin_auth.totp_uri(admin, secret)
        outcome = admin_auth.complete_enrollment(db, session=session, admin=admin, code=code, ip=client_ip(request))
        db.expunge_all()
    if outcome.status != "ok":
        limited = outcome.status == "limited"
        return _setup_page(request, session, admin, secret, uri, error="rate_limited" if limited else "invalid_code",
                           status_code=429 if limited else 401)
    response = ad.templating.render(
        request, "admin/recovery_codes.html",
        {"csrf_token": ad.tokens.csrf_token("admin", outcome.session.csrf_secret), "codes": outcome.recovery_codes,
         "admin": admin, "is_global": admin.role == "global", "show_nav": False})
    if outcome.raw_token:
        ad.set_admin_cookie(response, outcome.raw_token, ad.session_max_age(outcome.session))
    return no_store(response)


# ----- logout ----------------------------------------------------------------------------------
@router.post("/logout", dependencies=[Depends(ad.require_admin_csrf)])
def logout(request: Request, pair=Depends(ad.live_admin_session)):
    session, admin = pair
    with write_session() as db:
        admin_auth.logout(db, session, admin, ip=client_ip(request))
    ad.forget_admin(request)
    response = RedirectResponse("/admin/login", status_code=303)
    ad.clear_admin_cookie(response)
    return no_store(response)


# ----- own account -----------------------------------------------------------------------------
@router.get("/account")
def account(request: Request, ctx: ad.AdminContext = Depends(ad.require_admin)):
    with read_session() as db:
        sessions = admin_auth.list_sessions(db, ctx.admin.id)
        db.expunge_all()
    return ad.page(request, ctx, "admin/account.html",
                   {"sessions": sessions, "current_session_id": ctx.session.id,
                    "min_password_length": admin_auth.MIN_PASSWORD_LENGTH})


@router.post("/account/password", dependencies=[Depends(ad.require_admin_csrf)])
def change_password(request: Request, current_password: str = Form("", max_length=1000),
                    new_password: str = Form("", max_length=1000), new_password2: str = Form("", max_length=1000),
                    ctx: ad.AdminContext = Depends(ad.require_admin)):
    ip = client_ip(request)
    if new_password != new_password2:
        return ad.back("/admin/account", err="password_mismatch")
    try:
        admin_auth.validate_password(new_password)
    except InvalidInput:
        return ad.back("/admin/account", err="password_weak")
    with write_session() as db:
        if admin_auth.change_password_limited(db, ctx.admin, ip):
            return ad.back("/admin/account", err="rate_limited")
        ok = admin_auth.change_password(db, session=ctx.session, admin=ctx.admin, current_password=current_password,
                                        new_password=new_password, ip=ip)
    return ad.back("/admin/account", msg="password_changed") if ok else ad.back("/admin/account", err="wrong_password")


@router.post("/account/sessions/revoke", dependencies=[Depends(ad.require_admin_csrf)])
def revoke_sessions(request: Request, ctx: ad.AdminContext = Depends(ad.require_admin)):
    with write_session() as db:
        admin_auth.revoke_other_sessions(db, session=ctx.session, admin=ctx.admin, ip=client_ip(request))
    return ad.back("/admin/account", msg="sessions_revoked")
