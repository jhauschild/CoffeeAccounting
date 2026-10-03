"""User-facing routes (PROMPT §3, §5, §8). Business rules live in the services; routes only
parse input, open the transaction, map errors to safe pages and choose the redirect.

All redirects go to fixed internal paths (the only variable parts are an event UUID created by
the server and a whitelisted notice keyword). Nothing about a pending coffee travels in a URL.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Form, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import read_session, write_session
from app.models import COFFEE_KINDS, DISPLAY_NAME_MAX, Chair, ConsumptionEvent, User
from app.services import gate, ledger, onboarding, pending, prices, ratelimit, sessions, users
from app.services.errors import AlreadyReversed, InvalidInput, NoPriceConfigured, NotFound, RateLimited, UserInactive
from app.web import deps, tokens, user_views
from app.web.deps import UserContext
from app.web.middleware import no_store
from app.web.templating import render

router = APIRouter()

PROFILE_LIST_LIMIT = 50
SEARCH_MAX_LENGTH = 100


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
        response = _redirect("/join")
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


# ----- access gate ----------------------------------------------------------------------------
@router.get("/join")
def join_page(request: Request, db: Session = Depends(deps.get_read_db)):
    return render(request, "user/join.html", {"gate_passed": deps.has_gate(request), "error": False,
                                              "pending_notice": user_views.pending_notice(request, db)})


@router.post("/join")
def join_submit(request: Request, code: str = Form("")):
    ip = ratelimit.ip_key(deps.client_ip(request))
    bucket, limit, window = ratelimit.ACCESS_CODE_FAILURES
    # Check and count in ONE write transaction: the guess is counted as a failure before it is
    # evaluated, so parallel guesses cannot exceed the budget; a correct code releases it again.
    with write_session() as db:
        if ratelimit.is_limited(db, bucket, ip, limit, window):
            raise RateLimited("too many access code attempts")
        hit_id = ratelimit.record_hit(db, bucket, ip)
    if gate.check_access_code(code):
        with write_session() as db:
            ratelimit.release_hits(db, [hit_id])
        response = _redirect("/join")
        deps.set_gate_cookie(response)
        return response
    with read_session() as db:
        notice = user_views.pending_notice(request, db)
    return render(request, "user/join.html", {"gate_passed": False, "error": True, "pending_notice": notice},
                  status_code=403)


# ----- onboarding -----------------------------------------------------------------------------
def _registration_coffee_id(user: User) -> uuid.UUID | None:
    """A repeated registration submit arrives without the (already cleared) pending cookie; the
    coffee recorded by the first submit has exactly the profile's creation timestamp."""
    with read_session() as db:
        return db.scalars(select(ConsumptionEvent.id).where(
            ConsumptionEvent.user_id == user.id, ConsumptionEvent.type.in_(COFFEE_KINDS),
            ConsumptionEvent.created_at == user.created_at)).first()


def _finish_onboarding(request: Request, result: onboarding.OnboardResult, *, registration: bool = False) -> Response:
    event_id = result.event.id if result.event is not None else None
    if event_id is None and registration and not result.created:
        event_id = _registration_coffee_id(result.user)
    if event_id is not None:
        target = f"/coffee/done/{event_id}"
    elif result.coffee_status == onboarding.COFFEE_EXPIRED:
        target = "/account?notice=expired"
    elif result.coffee_status == onboarding.COFFEE_NO_PRICE:
        target = "/account?notice=no_price"
    else:
        target = "/account?notice=registered"
    response = _redirect(target)
    deps.set_session_cookie(response, result.raw_token)
    deps.clear_pending_cookie(response)
    deps.forget_user(request)
    return response


async def _csrf_onboarding(request: Request) -> None:
    """CSRF for /register and /profiles/select: a token bound to the user session or to the gate
    cookie is accepted, so re-submitting a form after the session was created (Back, double tap)
    reaches the idempotent handler instead of failing."""
    ctx = await run_in_threadpool(deps.current_user, request)
    form = await request.form()
    token = form.get(tokens.CSRF_FIELD)
    candidates = []
    if ctx is not None:
        candidates.append(("user", str(ctx.session.id)))
    gate_cookie = request.cookies.get(deps.GATE_COOKIE)
    if gate_cookie and gate.verify_gate_cookie(gate_cookie):
        candidates.append(("gate", gate_cookie))
    if not any(tokens.verify_csrf(scope, key, token) for scope, key in candidates):
        raise deps.CSRFError()


def _old_session_id(request: Request) -> uuid.UUID | None:
    ctx = deps.current_user(request)
    return ctx.session.id if ctx else None


def _check_profile_form(display_name: str, chair_id: str, chair_ids: set[uuid.UUID]):
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


def _register_page(request: Request, db: Session, *, token: str, values: dict, errors: dict | None = None,
                   duplicates=None, status: int = 200) -> Response:
    ctx = {"chairs": user_views.active_chairs(db), "registration_token": token, "values": values,
           "errors": errors or {}, "duplicates": duplicates or [], "name_max": DISPLAY_NAME_MAX,
           "pending_notice": user_views.pending_notice(request, db)}
    return render(request, "user/register.html", ctx, status_code=status)


@router.get("/register", dependencies=[Depends(deps.require_gate)])
def register_page(request: Request, db: Session = Depends(deps.get_read_db)):
    return _register_page(request, db, token=tokens.make_registration_token(), values={})


@router.post("/register", dependencies=[Depends(deps.require_gate), Depends(_csrf_onboarding)])
def register_submit(request: Request, display_name: str = Form(""), chair_id: str = Form(""),
                    privacy_ack: str = Form(""), registration_token: str = Form(""),
                    confirm_duplicate: str = Form("")):
    nonce = tokens.verify_registration_token(registration_token)
    values = {"display_name": display_name[:DISPLAY_NAME_MAX * 2], "chair_id": chair_id[:64]}
    with read_session() as db:
        chair_ids = {c.id for c in user_views.active_chairs(db)}
        name, cid, errors = _check_profile_form(display_name, chair_id, chair_ids)
        if not privacy_ack:
            errors["ack"] = "user.register.error_ack"
        if nonce is None:
            errors["token"] = "user.register.error_token"
        token = registration_token if nonce is not None else tokens.make_registration_token()
        if errors:
            return _register_page(request, db, token=token, values=values, errors=errors, status=400)
        already_created = db.get(User, onboarding.registration_user_id(nonce)) is not None
        if not confirm_duplicate and not already_created:
            duplicates = users.find_same_name(db, display_name=name, chair_id=cid)
            if duplicates:
                return _register_page(request, db, token=token, values=values, duplicates=duplicates)
    ip = ratelimit.ip_key(deps.client_ip(request))
    try:
        with write_session() as db:
            bucket, limit, window = ratelimit.REGISTRATION
            ratelimit.check_rate(db, bucket, ip, limit, window)
            result = onboarding.register_and_start_session(
                db, display_name=name, chair_id=cid, pending_id=deps.pending_id(request),
                registration_nonce=nonce, old_session_id=_old_session_id(request))
    except InvalidInput:
        with read_session() as db:
            return _register_page(request, db, token=token, values=values,
                                  errors={"name": "user.register.error_name"}, status=400)
    return _finish_onboarding(request, result, registration=True)


@router.get("/profiles", dependencies=[Depends(deps.require_gate)])
def profiles_page(request: Request, q: str = ""):
    q = q.strip()[:SEARCH_MAX_LENGTH]
    bucket, limit, window = ratelimit.PROFILE_SEARCH
    with write_session() as db:
        ratelimit.check_rate(db, bucket, ratelimit.ip_key(deps.client_ip(request)), limit, window)
        found = users.search_profiles(db, q, limit=PROFILE_LIST_LIMIT + 1)
        notice = user_views.pending_notice(request, db)
    return render(request, "user/profiles.html", {
        "profiles": found[:PROFILE_LIST_LIMIT], "more": len(found) > PROFILE_LIST_LIMIT, "limit": PROFILE_LIST_LIMIT,
        "q": q, "pending_notice": notice})


@router.post("/profiles/select", dependencies=[Depends(deps.require_gate), Depends(_csrf_onboarding)])
def profiles_select(request: Request, user_id: str = Form("")):
    uid = deps.parse_uuid(user_id)
    if uid is None:
        raise NotFound("profile not found")
    with write_session() as db:
        result = onboarding.select_profile_and_start_session(
            db, user_id=uid, pending_id=deps.pending_id(request), old_session_id=_old_session_id(request))
    return _finish_onboarding(request, result)


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


@router.post("/account/leave", dependencies=[Depends(deps.require_csrf)])
def leave(request: Request, ctx: UserContext = Depends(deps.require_user)):
    with write_session() as db:
        sessions.revoke_session(db, ctx.session.id)
    response = _redirect("/?notice=left")
    deps.clear_session_cookie(response)
    deps.forget_user(request)
    return response


# ----- privacy --------------------------------------------------------------------------------
@router.get("/privacy")
def privacy(request: Request):
    settings = get_settings()
    return render(request, "user/privacy.html", {"retention": settings.retention_text,
                                                 "contact": settings.operator_contact})
