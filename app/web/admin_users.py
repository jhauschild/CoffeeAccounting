"""Admin dashboard, user table, user detail and user actions, CSV exports (owner: admin agent)."""

from __future__ import annotations

import re
import uuid
from datetime import date

from fastapi import APIRouter, Depends, Form, Query, Request
from starlette.responses import Response

from app.db import read_session, write_session
from app.models import NOTE_MAX, ConsumptionEvent
from app.money import format_amount, parse_money
from app.services import authz, exports, ledger, sessions, stats, users
from app.services import audit
from app.services.errors import InvalidAmount, InvalidInput, NotFound, ServiceError
from app.services.users import effective_user_id
from app.web import admin_deps as ad
from app.web.deps import Redirect, client_ip, parse_uuid
from app.web.middleware import no_store

router = APIRouter()

_INT_RE = re.compile(r"^[+-]?[0-9]{1,4}$")


def _optional_uuid(value: str | None) -> uuid.UUID | None:
    value = (value or "").strip()
    if not value:
        return None
    parsed = parse_uuid(value)
    if parsed is None:
        raise InvalidInput("invalid identifier")
    return parsed


def _optional_date(value: str | None) -> date | None:
    value = (value or "").strip()
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise InvalidInput("invalid date") from None


def _filters(q: str, chair: str, status: str, sort: str, direction: str) -> dict:
    return {"q": q.strip()[:80] or None, "chair_id": _optional_uuid(chair), "status": status or None,
            "sort": sort, "direction": direction or None}


# ----- dashboard --------------------------------------------------------------------------------
@router.get("")
def dashboard(request: Request, ctx: ad.AdminContext = Depends(ad.require_admin)):
    with read_session() as db:
        data = stats.dashboard(db, ctx.admin)
        return ad.page(request, ctx, "admin/dashboard.html", {"d": data})


# ----- user table -------------------------------------------------------------------------------
@router.get("/users")
def user_list(request: Request, q: str = Query("", max_length=80), chair: str = Query("", max_length=40),
              status: str = Query("", max_length=10), sort: str = Query("balance", max_length=20),
              dir: str = Query("", max_length=4), page: int = Query(1, ge=1, le=100000),
              ctx: ad.AdminContext = Depends(ad.require_admin)):
    with read_session() as db:
        try:
            f = _filters(q, chair, status, sort, dir)
        except InvalidInput:
            raise NotFound("unknown chair") from None
        result = stats.list_users(db, ctx.admin, page=page, **f)
        chairs = stats.visible_chairs(db, ctx.admin)
        query = {k: v for k, v in {"q": f["q"], "chair": chair or None, "status": f["status"], "sort": result.sort,
                                   "dir": result.direction}.items() if v}
        return ad.page(request, ctx, "admin/users.html",
                       {"result": result, "chairs": chairs, "q": q, "chair": chair, "status": status,
                        "sort": result.sort, "dir": result.direction, "query": query})


@router.get("/users/export.csv")
def users_export(request: Request, q: str = Query("", max_length=80), chair: str = Query("", max_length=40),
                 status: str = Query("", max_length=10), sort: str = Query("balance", max_length=20),
                 dir: str = Query("", max_length=4), ctx: ad.AdminContext = Depends(ad.require_admin)):
    f = _filters(q, chair, status, sort, dir)
    with write_session() as db:  # the export is audited
        data = exports.users_csv(db, ctx.admin, ip=client_ip(request), **f)
    return _csv_response(data, exports.csv_filename("users"))


def _csv_response(data: bytes, filename: str) -> Response:
    response = Response(data, media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="{filename}"'})
    return no_store(response)


# ----- ledger export ----------------------------------------------------------------------------
@router.get("/exports")
def exports_page(request: Request, ctx: ad.AdminContext = Depends(ad.require_admin)):
    with read_session() as db:
        return ad.page(request, ctx, "admin/exports.html", {"chairs": stats.visible_chairs(db, ctx.admin)})


@router.get("/exports/ledger.csv")
def ledger_export(request: Request, date_from: str = Query("", alias="from", max_length=10),
                  date_to: str = Query("", alias="to", max_length=10), chair: str = Query("", max_length=40),
                  ctx: ad.AdminContext = Depends(ad.require_admin)):
    try:
        d_from, d_to, chair_id = _optional_date(date_from), _optional_date(date_to), _optional_uuid(chair)
    except InvalidInput:
        return ad.back("/admin/exports", err="invalid_input")
    if d_from and d_to and d_from > d_to:
        return ad.back("/admin/exports", err="invalid_input")
    with write_session() as db:
        data = exports.ledger_csv(db, ctx.admin, date_from=d_from, date_to=d_to, chair_id=chair_id,
                                  ip=client_ip(request))
    return _csv_response(data, exports.csv_filename("ledger"))


# ----- user detail ------------------------------------------------------------------------------
def _detail_path(user_id: uuid.UUID) -> str:
    return f"/admin/users/{user_id}"


@router.get("/users/{user_id}")
def user_detail(request: Request, uid: uuid.UUID = Depends(ad.admin_user_access),
                ctx: ad.AdminContext = Depends(ad.require_admin)):
    with read_session() as db:
        target = stats.effective_target(db, uid)
        if target != uid:  # a merged profile: its history lives on the profile it was merged into
            try:
                authz.ensure_admin_can_access_user(db, ctx.admin, target)
            except ServiceError:
                raise NotFound("profile has been merged") from None
            raise Redirect(_detail_path(target))
        detail = stats.user_detail(db, ctx.admin, uid)
        chairs = [c for c in stats.visible_chairs(db, ctx.admin)] if not ctx.is_global else \
            [c for c in stats.visible_chairs(db, ctx.admin) if c.active]
        unit = ledger.adjustment_default_amount(db, 1)  # current price per shot (None: no price yet)
        uncorrected = [p for p in detail.payments if not p.corrected]
        return ad.page(request, ctx, "admin/user_detail.html",
                       {"detail": detail, "chairs": chairs, "unit_cents": unit, "note_max": NOTE_MAX,
                        "unit_price_plain": format_amount(unit) if unit is not None else "",
                        "uncorrected": uncorrected})


def _act(request: Request, uid: uuid.UUID, ctx: ad.AdminContext, action, *, ok: str, path: str | None = None):
    """Run `action(db)` in one write transaction; show errors on the detail page (authorization errors stay 403)."""
    target = path or _detail_path(uid)
    try:
        with write_session() as db:
            action(db)
    except ServiceError as exc:
        return ad.back(target, err=ad.error_key(exc))
    return ad.back(target, msg=ok)


@router.post("/users/{user_id}/payment", dependencies=[Depends(ad.require_admin_csrf)])
def record_payment(request: Request, amount: str = Form("", max_length=20), note: str = Form("", max_length=NOTE_MAX),
                   correction_of: str = Form("", max_length=40), uid: uuid.UUID = Depends(ad.admin_user_access),
                   ctx: ad.AdminContext = Depends(ad.require_admin)):
    def run(db):
        cents = parse_money(amount, allow_negative=True, allow_zero=False)
        ledger.add_payment(db, admin=ctx.admin, user_id=uid, amount_cents=cents, note=note or None,
                           correction_of_id=_optional_uuid(correction_of), ip=client_ip(request))

    return _act(request, uid, ctx, run, ok="payment_recorded")


@router.post("/users/{user_id}/adjustment", dependencies=[Depends(ad.require_admin_csrf)])
def record_adjustment(request: Request, quantity: str = Form("", max_length=8),
                      amount: str = Form("", max_length=20), note: str = Form("", max_length=NOTE_MAX),
                      uid: uuid.UUID = Depends(ad.admin_user_access),
                      ctx: ad.AdminContext = Depends(ad.require_admin)):
    def run(db):
        if not _INT_RE.match(quantity.strip()):
            raise InvalidAmount("quantity must be a whole number")
        qty = int(quantity)
        # An empty amount means "quantity x current price"; anything else is an explicit override.
        cents = parse_money(amount, allow_negative=True, allow_zero=True) if amount.strip() else None
        ledger.add_adjustment(db, admin=ctx.admin, user_id=uid, quantity=qty, amount_cents=cents,
                              note=note or None, ip=client_ip(request))

    return _act(request, uid, ctx, run, ok="adjustment_recorded")


@router.post("/users/{user_id}/events/{event_id}/reverse", dependencies=[Depends(ad.require_admin_csrf)])
def reverse_event(request: Request, event_id: str, note: str = Form("", max_length=NOTE_MAX),
                  uid: uuid.UUID = Depends(ad.admin_user_access), ctx: ad.AdminContext = Depends(ad.require_admin)):
    eid = parse_uuid(event_id)
    if eid is None:
        raise NotFound("event not found")

    def run(db):
        event = db.get(ConsumptionEvent, eid)
        if event is None or effective_user_id(db, event.user_id) != uid:
            raise NotFound("event not found")  # the event must belong to the profile in the URL
        ledger.admin_reverse_event(db, admin=ctx.admin, event_id=eid, note=note or None, ip=client_ip(request))

    return _act(request, uid, ctx, run, ok="event_reversed")


@router.post("/users/{user_id}/rename", dependencies=[Depends(ad.require_admin_csrf)])
def rename_user(request: Request, display_name: str = Form("", max_length=200),
                uid: uuid.UUID = Depends(ad.admin_user_access), ctx: ad.AdminContext = Depends(ad.require_admin)):
    def run(db):
        users.update_profile(db, user_id=uid, display_name=display_name, actor_type="admin", actor_id=ctx.admin.id,
                             ip=client_ip(request))

    return _act(request, uid, ctx, run, ok="user_updated")


@router.post("/users/{user_id}/chair", dependencies=[Depends(ad.require_admin_csrf)])
def change_chair(request: Request, chair_id: str = Form("", max_length=40),
                 uid: uuid.UUID = Depends(ad.global_user_access), ctx: ad.AdminContext = Depends(ad.require_global_admin)):
    def run(db):
        cid = _optional_uuid(chair_id)
        if cid is None:
            raise InvalidInput("chair required")
        users.update_profile(db, user_id=uid, chair_id=cid, actor_type="admin", actor_id=ctx.admin.id,
                             ip=client_ip(request))

    return _act(request, uid, ctx, run, ok="chair_changed")


@router.post("/users/{user_id}/status", dependencies=[Depends(ad.require_admin_csrf)])
def change_status(request: Request, active: str = Form("", max_length=1),
                  uid: uuid.UUID = Depends(ad.admin_user_access), ctx: ad.AdminContext = Depends(ad.require_admin)):
    if active not in ("0", "1"):
        raise NotFound("unknown action")

    def run(db):
        users.set_user_status(db, admin=ctx.admin, user_id=uid, active=active == "1", ip=client_ip(request))

    return _act(request, uid, ctx, run, ok="user_reactivated" if active == "1" else "user_deactivated")


@router.post("/users/{user_id}/sessions/revoke", dependencies=[Depends(ad.require_admin_csrf)])
def revoke_user_sessions(request: Request, uid: uuid.UUID = Depends(ad.admin_user_access),
                         ctx: ad.AdminContext = Depends(ad.require_admin)):
    def run(db):
        authz.ensure_admin_can_access_user(db, ctx.admin, uid)
        count = sessions.revoke_user_sessions(db, uid)
        audit.log(db, actor_type="admin", actor_id=ctx.admin.id, action="user.sessions_revoked",
                  target_type="user", target_id=uid, metadata={"sessions_revoked": count}, ip=client_ip(request))

    return _act(request, uid, ctx, run, ok="user_sessions_revoked")


# ----- merge (global only) ----------------------------------------------------------------------
@router.get("/users/{user_id}/merge")
def merge_form(request: Request, q: str = Query("", max_length=80), uid: uuid.UUID = Depends(ad.global_user_access),
               ctx: ad.AdminContext = Depends(ad.require_global_admin)):
    with read_session() as db:
        detail = stats.user_detail(db, ctx.admin, uid)
        candidates = stats.merge_candidates(db, uid, q) if q.strip() else []
        return ad.page(request, ctx, "admin/merge.html", {"detail": detail, "q": q, "candidates": candidates})


@router.post("/users/{user_id}/merge", dependencies=[Depends(ad.require_admin_csrf)])
def merge_submit(request: Request, target_id: str = Form("", max_length=40),
                 uid: uuid.UUID = Depends(ad.global_user_access), ctx: ad.AdminContext = Depends(ad.require_global_admin)):
    target = parse_uuid(target_id)
    if target is None:
        return ad.back(f"/admin/users/{uid}/merge", err="invalid_input")
    try:
        with write_session() as db:
            users.merge_users(db, admin=ctx.admin, duplicate_id=uid, target_id=target, ip=client_ip(request))
    except ServiceError as exc:
        return ad.back(f"/admin/users/{uid}/merge", err=ad.error_key(exc))
    return ad.back(_detail_path(target), msg="merged")
