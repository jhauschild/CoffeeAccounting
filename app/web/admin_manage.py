"""Admin chairs, prices, QR, audit and config view (owner: admin agent). Global administrators only,
except the QR page which every administrator may print."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Form, Query, Request
from starlette.responses import Response
from sqlalchemy import func, select

from app.config import get_settings, public_config_rows
from app.db import read_session, write_session
from app.models import AdminUser, ConsumptionEvent, User
from app.money import parse_money
from app.services import chairs as chair_service
from app.services import exports, prices, stats
from app.services.authz import admin_label
from app.services.errors import InvalidInput, NotFound, ServiceError
from app.timeutil import parse_iso_datetime
from app.web import admin_deps as ad
from app.web.deps import client_ip, parse_uuid
from app.web.middleware import no_store

router = APIRouter()


# ----- chairs -----------------------------------------------------------------------------------
@router.get("/chairs")
def chairs_page(request: Request, ctx: ad.AdminContext = Depends(ad.require_global_admin)):
    with read_session() as db:
        user_counts = dict(db.execute(select(User.chair_id, func.count()).where(User.status != "merged")
                                      .group_by(User.chair_id)).all())
        event_chairs = set(db.scalars(select(ConsumptionEvent.chair_id).distinct()))
        rows = [{"chair": c, "users": user_counts.get(c.id, 0), "has_events": c.id in event_chairs}
                for c in chair_service.list_chairs(db)]
        return ad.page(request, ctx, "admin/chairs.html", {"rows": rows})


@router.post("/chairs", dependencies=[Depends(ad.require_admin_csrf)])
def create_chair(request: Request, full_name: str = Form("", max_length=200), short_name: str = Form("", max_length=60),
                 ctx: ad.AdminContext = Depends(ad.require_global_admin)):
    try:
        with write_session() as db:
            chair_service.create_chair(db, admin=ctx.admin, full_name=full_name, short_name=short_name,
                                       ip=client_ip(request))
    except ServiceError as exc:
        return ad.back("/admin/chairs", err=ad.error_key(exc))
    return ad.back("/admin/chairs", msg="chair_created")


def _chair_id(value: str) -> uuid.UUID:
    cid = parse_uuid(value)
    if cid is None:
        raise NotFound("chair not found")
    return cid


@router.post("/chairs/{chair_id}/rename", dependencies=[Depends(ad.require_admin_csrf)])
def rename_chair(request: Request, chair_id: str, full_name: str = Form("", max_length=200),
                 short_name: str = Form("", max_length=60), ctx: ad.AdminContext = Depends(ad.require_global_admin)):
    cid = _chair_id(chair_id)
    try:
        with write_session() as db:
            chair_service.rename_chair(db, admin=ctx.admin, chair_id=cid, full_name=full_name, short_name=short_name,
                                       ip=client_ip(request))
    except ServiceError as exc:
        return ad.back("/admin/chairs", err=ad.error_key(exc))
    return ad.back("/admin/chairs", msg="chair_renamed")


@router.post("/chairs/{chair_id}/active", dependencies=[Depends(ad.require_admin_csrf)])
def chair_active(request: Request, chair_id: str, active: str = Form("", max_length=1),
                 ctx: ad.AdminContext = Depends(ad.require_global_admin)):
    cid = _chair_id(chair_id)
    if active not in ("0", "1"):
        raise NotFound("unknown action")
    try:
        with write_session() as db:
            chair_service.set_chair_active(db, admin=ctx.admin, chair_id=cid, active=active == "1",
                                           ip=client_ip(request))
    except ServiceError as exc:
        return ad.back("/admin/chairs", err=ad.error_key(exc))
    return ad.back("/admin/chairs", msg="chair_reactivated" if active == "1" else "chair_deactivated")


# ----- prices -----------------------------------------------------------------------------------
@router.get("/prices")
def prices_page(request: Request, ctx: ad.AdminContext = Depends(ad.require_global_admin)):
    with read_session() as db:
        history = prices.list_prices(db)
        names = {a.id: admin_label(a) for a in db.scalars(select(AdminUser))}
        return ad.page(request, ctx, "admin/prices.html",
                       {"current": prices.get_price_in_effect(db), "history": history, "names": names})


@router.post("/prices", dependencies=[Depends(ad.require_admin_csrf)])
def add_price(request: Request, price: str = Form("", max_length=20), effective_from: str = Form("", max_length=40),
              note: str = Form("", max_length=500), ctx: ad.AdminContext = Depends(ad.require_global_admin)):
    try:
        cents = parse_money(price, allow_negative=False, allow_zero=True)
        when = None
        if effective_from.strip():
            try:
                when = parse_iso_datetime(effective_from)  # local time (datetime-local input)
            except ValueError:
                raise InvalidInput("invalid date/time") from None
        with write_session() as db:
            prices.add_price(db, price_per_shot_cents=cents, effective_from=when, admin_id=ctx.admin.id,
                             note=note or None, ip=client_ip(request))
    except ServiceError as exc:
        return ad.back("/admin/prices", err=ad.error_key(exc))
    return ad.back("/admin/prices", msg="price_added")


# ----- QR page ----------------------------------------------------------------------------------
def _qr_page(request: Request, ctx: ad.AdminContext, line: str = ""):
    with read_session() as db:
        price = prices.get_price_in_effect(db)
        db.expunge_all()
    urls = exports.qr_urls()
    codes = [{"kind": kind, "url": url, "label": ad.t(f"admin.qr.label_{kind}"),
              "svg": exports.qr_svg(url, None, standalone=False),
              "show_price": kind in exports.QR_PRICE_KINDS} for kind, url in urls.items()]
    return ad.page(request, ctx, "admin/qr.html", {"codes": codes, "price": price, "line": line})


@router.get("/qr")
def qr_page(request: Request, ctx: ad.AdminContext = Depends(ad.require_admin)):
    return _qr_page(request, ctx)


@router.post("/qr", dependencies=[Depends(ad.require_admin_csrf)])
def qr_preview(request: Request, line: str = Form("", max_length=200), ctx: ad.AdminContext = Depends(ad.require_admin)):
    """Echo the optional free-text line (e.g. a short notice) into the printable page. Never stored or logged."""
    return _qr_page(request, ctx, " ".join(line.split()))


@router.get("/qr/{kind}.svg")
def qr_download(kind: str, ctx: ad.AdminContext = Depends(ad.require_admin)):
    """The labeled standalone SVG of one code (same file as `python -m app.cli qr`)."""
    urls = exports.qr_urls()
    if kind not in urls:
        raise NotFound("unknown code")
    svg = exports.qr_svg(urls[kind], ad.t(f"admin.qr.label_{kind}"))
    return no_store(Response(svg, media_type="image/svg+xml",
                             headers={"Content-Disposition": f'attachment; filename="coffee-{kind}.svg"'}))


# ----- audit view -------------------------------------------------------------------------------
@router.get("/audit")
def audit_view(request: Request, action: str = Query("", max_length=64), page: int = Query(1, ge=1, le=100000),
               ctx: ad.AdminContext = Depends(ad.require_global_admin)):
    with read_session() as db:
        result = stats.audit_page(db, ctx.admin, action=action, page=page)
        return ad.page(request, ctx, "admin/audit.html", {"result": result, "action": action})


# ----- config overview --------------------------------------------------------------------------
@router.get("/config")
def config_page(request: Request, ctx: ad.AdminContext = Depends(ad.require_global_admin)):
    return ad.page(request, ctx, "admin/config.html", {"rows": public_config_rows(get_settings())})
