"""User-facing routes (PROMPT §3, §5, §8; PLAN-v2 section 1). Business rules live in the services; routes only
parse input, open the transaction, map errors to safe pages and choose the redirect.

All redirects go to fixed internal paths (the only variable parts are an event UUID created by the server
and a whitelisted notice keyword). Nothing about a pending action travels in a URL. Forms submitted before
sign-in (login, register, verify, forgot, reset) carry a CSRF token bound to the `coffee_csrf` cookie; GETs
write nothing (a mail scanner prefetching a link changes no state).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, BackgroundTasks, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import read_session, write_session
from app.models import COFFEE_KINDS, DISPLAY_NAME_MAX, Chair, ConsumptionEvent
from app.services import ledger, login, onboarding, pending, prices, recovery, registration, sessions, users
from app.services.errors import (AlreadyReversed, Conflict, InvalidCredentials, InvalidInput, InvalidPassword,
                                 InvalidToken, NoPriceConfigured, NotFound, RateLimited, UserInactive)
from app.services.mail import send_in_background
from app.web import deps, tokens, user_views
from app.web.deps import UserContext
from app.web.middleware import no_store
from app.web.templating import render

log = logging.getLogger(__name__)
router = APIRouter()

FORM_TEXT_MAX = 200
PASSWORD_FORM_MAX = 1000


def _redirect(path: str) -> RedirectResponse:
    return no_store(RedirectResponse(path, status_code=303))


def _kind(kind: str) -> str:
    if kind not in COFFEE_KINDS:
        raise NotFound("unknown coffee kind")
    return kind


def _message(request: Request, title: str, body: str, *, status: int = 200, tone: str = "warn",
             link: tuple[str, str] | None = None) -> Response:
    return render(request, "user/message.html", {"title": title, "body": body, "tone": tone, "link": link},
                  status_code=status)


def _rate_limited(request: Request) -> Response:
    return _message(request, "user.limited.title", "user.limited.body", status=429, tone="error")


def _invalid_link(request: Request) -> Response:
    return _message(request, "user.link.invalid_title", "user.link.invalid_body", status=400,
                    link=("/login", "user.login.title"))


# ----- home -----------------------------------------------------------------------------------
@router.api_route("/", methods=["GET", "HEAD"])
def home(request: Request, notice: str = ""):
    ctx = deps.current_user(request)
    return render(request, "user/home.html", {"ctx": ctx, "left": notice == "left"})


# ----- scan -----------------------------------------------------------------------------------
@router.get("/coffee/{kind}")
def scan_page(request: Request, kind: str):
    """Writes nothing: only issues a signed token (PROMPT §3)."""
    _kind(kind)
    return render(request, "user/scan.html", {"kind": kind, "scan_token": tokens.make_scan_token(kind)},
                  headers={"Cache-Control": "no-store"})


@router.post("/coffee/{kind}")
def scan_submit(request: Request, kind: str, token: str = Form("")):
    _kind(kind)
    scan = tokens.verify_scan_token(token, kind)
    if scan is None:
        return _message(request, "user.scan.expired_title", "user.scan.expired_body", status=400,
                        link=(f"/coffee/{kind}", "user.scan.rescan"))
    ctx = deps.current_user(request)
    if ctx is None:
        with write_session() as db:
            pending_id = pending.create_pending(db, kind, scan.nonce)
        response = _redirect("/login")
        deps.set_pending_cookie(response, pending_id)
        return response
    try:
        with write_session() as db:
            result = ledger.record_coffee(db, user_id=ctx.user.id, kind=kind, nonce=scan.nonce,
                                          session_id=ctx.session.id)
            owner_id, event_id = result.event.user_id, result.event.id
    except UserInactive:
        return _message(request, "user.scan.inactive_title", "user.scan.inactive_body", status=403, tone="error")
    except NoPriceConfigured:
        return _message(request, "user.scan.no_price_title", "user.scan.no_price_body", status=503)
    if owner_id != ctx.user.id:  # the token was used by someone else: never reveal their event
        return _message(request, "user.scan.used_title", "user.scan.used_body", status=409,
                        link=(f"/coffee/{kind}", "user.scan.rescan"))
    return _redirect(f"/coffee/done/{event_id}")


@router.get("/coffee/done/{event_id}")
def done_page(request: Request, event_id: str, ctx: UserContext = Depends(deps.require_user),
              db: Session = Depends(deps.get_read_db)):
    eid = deps.parse_uuid(event_id)
    event = db.get(ConsumptionEvent, eid) if eid else None
    if event is None or event.user_id != ctx.user.id or event.type not in COFFEE_KINDS:
        raise NotFound("event not found")
    undoable = ledger.latest_undoable_event(db, user_id=ctx.user.id, session_id=ctx.session.id)
    view = {
        "id": str(event.id), "kind": event.type, "quantity": event.quantity, "unit_price_cents": event.unit_price_cents,
        "amount_cents": event.amount_cents, "time": user_views.local_time(event.created_at),
        "reversed": ledger.is_reversed(db, event.id), "can_undo": undoable is not None and undoable.id == event.id,
    }
    return render(request, "user/done.html", {"event": view, "totals": ledger.get_totals(db, ctx.user.id)})


@router.post("/coffee/undo/{event_id}", dependencies=[Depends(deps.require_csrf)])
def undo(request: Request, event_id: str, ctx: UserContext = Depends(deps.require_user)):
    eid = deps.parse_uuid(event_id)
    if eid is None:
        raise NotFound("event not found")
    try:
        with write_session() as db:
            ledger.undo_coffee(db, user_id=ctx.user.id, session_id=ctx.session.id, event_id=eid)
    except AlreadyReversed:  # double tap: show the (already undone) coffee
        pass
    return _redirect(f"/coffee/done/{eid}")


# ----- sign in --------------------------------------------------------------------------------
def _signed_in(request: Request, result: onboarding.OnboardResult, *, default: str = "/account") -> Response:
    """Cookie, redirect target and cleanup after a sign-in (login or verification) in this browser."""
    if result.event is not None:
        target = f"/coffee/done/{result.event.id}"
    elif result.coffee_status == onboarding.COFFEE_VIEW_SITE:
        target = "/overview"
    elif result.coffee_status == onboarding.COFFEE_EXPIRED:
        target = "/account?notice=expired"
    elif result.coffee_status == onboarding.COFFEE_NO_PRICE:
        target = "/account?notice=no_price"
    else:
        target = default
    response = _redirect(target)
    deps.set_session_cookie(response, result.raw_token)
    deps.clear_pending_cookie(response)
    deps.forget_user(request)
    return response


def _old_session_id(request: Request):
    ctx = deps.current_user(request)
    return ctx.session.id if ctx else None


def _login_page(request: Request, *, username: str = "", error: bool = False, status: int = 200,
                notice: str | None = None) -> Response:
    with read_session() as db:
        pending_notice = user_views.pending_notice(request, db)
    return render(request, "user/login.html", {
        "csrf_token": deps.form_csrf_token(request), "username": username[:FORM_TEXT_MAX], "error": error,
        "notice": user_views.login_notice_key(notice), "pending_notice": pending_notice}, status_code=status)


@router.get("/login")
def login_page(request: Request, notice: str = ""):
    return _login_page(request, notice=notice)


@router.post("/login", dependencies=[Depends(deps.require_csrf)])
def login_submit(request: Request, username: str = Form("", max_length=FORM_TEXT_MAX),
                 password: str = Form("", max_length=PASSWORD_FORM_MAX)):
    result = None
    try:
        with write_session() as db:
            try:
                result = login.sign_in(db, username=username, password=password, ip=deps.client_ip(request),
                                       pending_id=deps.pending_id(request), old_session_id=_old_session_id(request))
            except InvalidCredentials:
                pass  # caught inside the block: the recorded failure is committed
    except RateLimited:
        return _rate_limited(request)
    if result is None:
        return _login_page(request, username=username, error=True, status=401)
    return _signed_in(request, result)


@router.post("/logout", dependencies=[Depends(deps.require_csrf)])
def logout(request: Request, ctx: UserContext = Depends(deps.require_user)):
    with write_session() as db:
        sessions.revoke_session(db, ctx.session.id)
    response = _redirect("/?notice=left")
    deps.clear_session_cookie(response)
    deps.forget_user(request)
    return response


# ----- registration and verification ----------------------------------------------------------
def _register_page(request: Request, *, values: dict, errors: dict | None = None, status: int = 200) -> Response:
    with read_session() as db:  # render inside the block: the chairs expire when the read transaction ends
        return render(request, "user/register.html", {
            "csrf_token": deps.form_csrf_token(request), "chairs": user_views.active_chairs(db), "values": values,
            "errors": errors or {}, "name_max": DISPLAY_NAME_MAX,
            "min_password_length": get_settings().password_min_length,
            "pending_notice": user_views.pending_notice(request, db)}, status_code=status)


def _register_errors(exc: InvalidInput | Conflict) -> dict[str, str]:
    """{form field: string key} for a validation error of `registration.begin_member`."""
    ctx = exc.context
    if isinstance(exc, InvalidPassword):
        return {"password": f"user.register.error_password_{ctx.get('reason')}"}
    if isinstance(exc, Conflict):
        return {"username": "user.register.error_username_taken"}
    field = ctx.get("field")
    if field == "username":
        return {"username": f"user.register.error_username_{ctx.get('reason', 'chars')}"}
    if field == "email":
        return {"email": f"user.register.error_email_{ctx.get('reason', 'format')}"}
    if field == "display_name":
        return {"display_name": "user.register.error_name"}
    if field == "chair":
        return {"chair": "user.register.error_chair"}
    if field == "privacy":
        return {"privacy": "user.register.error_ack"}
    return {"form": "user.register.error_form"}


@router.get("/register")
def register_page(request: Request):
    return _register_page(request, values={})


@router.post("/register", dependencies=[Depends(deps.require_csrf)])
def register_submit(request: Request, background_tasks: BackgroundTasks,
                    username: str = Form("", max_length=FORM_TEXT_MAX),
                    display_name: str = Form("", max_length=FORM_TEXT_MAX),
                    chair_id: str = Form("", max_length=64), email: str = Form("", max_length=FORM_TEXT_MAX),
                    password: str = Form("", max_length=PASSWORD_FORM_MAX),
                    password2: str = Form("", max_length=PASSWORD_FORM_MAX), privacy_ack: str = Form("")):
    values = {"username": username, "display_name": display_name, "chair_id": chair_id[:64], "email": email}
    if password != password2:
        return _register_page(request, values=values, errors={"password2": "user.register.error_password_mismatch"},
                              status=400)
    try:
        with write_session() as db:
            result = registration.begin_member(
                db, username=username, display_name=display_name, chair_id=deps.parse_uuid(chair_id), email=email,
                password=password, privacy_ack=bool(privacy_ack), ip=deps.client_ip(request))
            message = registration.mail_for_registration(result)
    except RateLimited:
        return _rate_limited(request)
    except (InvalidInput, Conflict) as exc:
        return _register_page(request, values=values, errors=_register_errors(exc), status=400)
    background_tasks.add_task(send_in_background, message, result.email)
    # The same page whether or not the address already has an account.
    return render(request, "user/register_sent.html", {})


@router.get("/verify/{token}")
def verify_page(request: Request, token: str):
    """Shows what will be created; writes nothing (mail scanners prefetch links)."""
    with read_session() as db:
        view = registration.peek_pending(db, token)
    if view is None:
        return _invalid_link(request)
    return render(request, "user/verify.html", {"view": view, "csrf_token": deps.form_csrf_token(request),
                                                "token": token})


@router.post("/verify/{token}", dependencies=[Depends(deps.require_csrf)])
def verify_submit(request: Request, token: str):
    try:
        with write_session() as db:
            result = registration.confirm_member(
                db, token, pending_id=deps.pending_id(request), old_session_id=_old_session_id(request),
                ip=deps.client_ip(request))
    except InvalidToken:
        if deps.current_user(request) is not None:  # double tap: the first submit already signed this browser in
            return _redirect("/account")
        return _invalid_link(request)
    except Conflict as exc:
        key = ("user.verify.taken_email_body" if exc.context.get("reason") == registration.REASON_EMAIL_TAKEN
               else "user.verify.taken_username_body")
        return _message(request, "user.verify.taken_title", key, status=409, link=("/login", "user.login.title"))
    except InvalidInput:
        return _message(request, "user.verify.failed_title", "user.verify.failed_body", status=400)
    return _signed_in(request, result, default="/account?notice=registered")


# ----- password recovery ----------------------------------------------------------------------
@router.get("/forgot")
def forgot_page(request: Request):
    return render(request, "user/forgot.html", {"csrf_token": deps.form_csrf_token(request)})


@router.post("/forgot", dependencies=[Depends(deps.require_csrf)])
def forgot_submit(request: Request, background_tasks: BackgroundTasks,
                  username: str = Form("", max_length=FORM_TEXT_MAX)):
    try:
        with write_session() as db:
            outcome = recovery.request_reset(db, username, deps.client_ip(request))
    except RateLimited:
        return _rate_limited(request)
    if outcome.message is not None:
        background_tasks.add_task(send_in_background, outcome.message, outcome.recipient)
    # The same page for an unknown account, a known one and a capped recipient.
    return render(request, "user/forgot_sent.html", {})


def _reset_page(request: Request, token: str, view, *, error: str | None = None, status: int = 200) -> Response:
    return render(request, "user/reset.html", {"view": view, "token": token, "error": error,
                                               "csrf_token": deps.form_csrf_token(request),
                                               "min_password_length": get_settings().password_min_length},
                  status_code=status)


@router.get("/reset/{token}")
def reset_page(request: Request, token: str):
    """Shows the form; writes nothing."""
    with read_session() as db:
        view = recovery.peek_reset(db, token)
    if view is None:
        return _invalid_link(request)
    return _reset_page(request, token, view)


@router.post("/reset/{token}", dependencies=[Depends(deps.require_csrf)])
def reset_submit(request: Request, token: str, password: str = Form("", max_length=PASSWORD_FORM_MAX),
                 password2: str = Form("", max_length=PASSWORD_FORM_MAX)):
    with read_session() as db:
        view = recovery.peek_reset(db, token)
    if view is None:
        return _invalid_link(request)
    if password != password2:
        return _reset_page(request, token, view, error="user.register.error_password_mismatch", status=400)
    try:
        with write_session() as db:
            recovery.reset_password(db, token, password, ip=deps.client_ip(request))
    except InvalidToken:
        return _invalid_link(request)
    except InvalidPassword as exc:
        return _reset_page(request, token, view, error=f"user.register.error_password_{exc.context.get('reason')}",
                           status=400)
    return _redirect("/login?notice=reset")


def _check_profile_form(display_name: str, chair_id: str, chair_ids: set):
    """-> (clean name | None, chair uuid | None, {field: string key})."""
    errors: dict[str, str] = {}
    name = None
    try:
        name = users.clean_display_name(display_name)
    except InvalidInput:
        errors["name"] = "user.register.error_name"
    cid = deps.parse_uuid(chair_id)
    if cid is None or cid not in chair_ids:
        errors["chair"] = "user.register.error_chair"
        cid = None
    return name, cid, errors


# ----- account --------------------------------------------------------------------------------
@router.get("/account")
def account_page(request: Request, notice: str = "", ctx: UserContext = Depends(deps.require_user),
                 db: Session = Depends(deps.get_read_db)):
    uid = ctx.user.id
    price = prices.get_price_in_effect(db)
    return render(request, "user/account.html", {
        "user": ctx.user, "chair": db.get(Chair, ctx.user.chair_id), "totals": ledger.get_totals(db, uid),
        "price_cents": price.price_per_shot_cents if price else None,
        "events": user_views.event_rows(db, ledger.recent_consumption(db, uid, 20)),
        "payments": user_views.payment_rows(ledger.recent_payments(db, uid, 20)),
        "notice": user_views.notice_key(notice)})


def _edit_page(request: Request, db: Session, ctx: UserContext, values: dict, errors: dict | None = None,
               status: int = 200) -> Response:
    current = db.get(Chair, ctx.user.chair_id)
    return render(request, "user/edit.html", {
        "chairs": user_views.active_chairs(db, include=current), "values": values, "errors": errors or {},
        "name_max": DISPLAY_NAME_MAX}, status_code=status)


@router.get("/account/edit")
def edit_page(request: Request, ctx: UserContext = Depends(deps.require_user),
              db: Session = Depends(deps.get_read_db)):
    return _edit_page(request, db, ctx, {"display_name": ctx.user.display_name, "chair_id": str(ctx.user.chair_id)})


@router.post("/account/edit", dependencies=[Depends(deps.require_csrf)])
def edit_submit(request: Request, display_name: str = Form(""), chair_id: str = Form(""),
                ctx: UserContext = Depends(deps.require_user)):
    values = {"display_name": display_name[:DISPLAY_NAME_MAX * 2], "chair_id": chair_id[:64]}
    with read_session() as db:
        allowed = {c.id for c in user_views.active_chairs(db, include=db.get(Chair, ctx.user.chair_id))}
        name, cid, errors = _check_profile_form(display_name, chair_id, allowed)
        if errors:
            return _edit_page(request, db, ctx, values, errors, status=400)
    with write_session() as db:
        users.update_profile(db, user_id=ctx.user.id, display_name=name, chair_id=cid, actor_type="user",
                             ip=deps.client_ip(request))
    return _redirect("/account?notice=saved")


# ----- privacy --------------------------------------------------------------------------------
@router.get("/privacy")
def privacy(request: Request):
    settings = get_settings()
    return render(request, "user/privacy.html", {"retention": settings.retention_text,
                                                 "contact": settings.operator_contact})
