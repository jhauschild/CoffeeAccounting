"""Head admin: group-admin role button, `/admin/admins` (role holders) and sponsor reassignment for guests
(owner: admin agent). Group admins get 403 on every route here.

Role changes and sponsor changes are not balance-changing, so there is no step-up (they are on the allow-list
of non-balance POSTs in tests/test_admin_routes_authz.py).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Form, Query, Request

from app.db import read_session, write_session
from app.services import registration, roles, stats
from app.services.errors import Forbidden, NotFound, ServiceError
from app.web import admin_deps as ad
from app.web.deps import client_ip, parse_uuid

router = APIRouter()

ADMINS_PATH = "/admin/admins"

# Forbidden/Conflict reasons that are shown as a message on the detail page (any other Forbidden stays a 403).
_REASON_KEYS = {"not_member": "not_member", "self": "role_self", "last_global_admin": "last_global_admin",
                "already_group_admin": "already_group_admin", "already_removed": "already_removed",
                "username_taken": "username_taken"}


def _detail_path(uid: uuid.UUID) -> str:
    return f"/admin/users/{uid}"


def _role_error(exc: ServiceError) -> str:
    reason = exc.context.get("reason")
    if reason in _REASON_KEYS:
        return _REASON_KEYS[reason]
    return ad.error_key(exc)  # re-raises Forbidden (403)


@router.get("/admins")
def admins_page(request: Request, ctx: ad.AdminContext = Depends(ad.require_global_admin)):
    with read_session() as db:
        holders = roles.list_role_holders(db, ctx.admin)
        return ad.page(request, ctx, "admin/admins.html", {"holders": holders})


@router.post("/users/{user_id}/group-admin/promote", dependencies=[Depends(ad.require_admin_csrf)])
def promote(request: Request, uid: uuid.UUID = Depends(ad.global_user_access),
            ctx: ad.AdminContext = Depends(ad.require_global_admin)):
    try:
        with write_session() as db:
            roles.promote_group_admin(db, head_admin=ctx.admin, user_id=uid, ip=client_ip(request))
    except ServiceError as exc:
        return ad.back(_detail_path(uid), err=_role_error(exc))
    return ad.back(_detail_path(uid), msg="group_admin_added")


@router.post("/users/{user_id}/group-admin/demote", dependencies=[Depends(ad.require_admin_csrf)])
def demote(request: Request, uid: uuid.UUID = Depends(ad.global_user_access),
           ctx: ad.AdminContext = Depends(ad.require_global_admin)):
    try:
        with write_session() as db:
            held = roles.demote_group_admin(db, head_admin=ctx.admin, user_id=uid, ip=client_ip(request))
    except ServiceError as exc:
        return ad.back(_detail_path(uid), err=_role_error(exc))
    return ad.back(_detail_path(uid), msg="group_admin_removed_held" if held else "group_admin_removed")


# ----- sponsor reassignment (guests) ------------------------------------------------------------
@router.get("/users/{user_id}/sponsor")
def sponsor_form(request: Request, q: str = Query("", max_length=80),
                 uid: uuid.UUID = Depends(ad.global_user_access),
                 ctx: ad.AdminContext = Depends(ad.require_global_admin)):
    with read_session() as db:
        target = stats.effective_target(db, uid)
        if target != uid:
            raise NotFound("profile has been merged")
        detail = stats.user_detail(db, ctx.admin, uid)
        info = roles.role_info(db, detail.user)
        if info.kind != "guest":
            return ad.back(_detail_path(uid), err="not_a_guest")
        candidates = roles.sponsor_candidates(db, ctx.admin, q, exclude=info.sponsor.id if info.sponsor else None)
        return ad.page(request, ctx, "admin/sponsor.html",
                       {"detail": detail, "info": info, "q": q, "candidates": candidates})


@router.post("/users/{user_id}/sponsor", dependencies=[Depends(ad.require_admin_csrf)])
def sponsor_change(request: Request, sponsor_id: str = Form("", max_length=40),
                   uid: uuid.UUID = Depends(ad.global_user_access),
                   ctx: ad.AdminContext = Depends(ad.require_global_admin)):
    new_sponsor = parse_uuid(sponsor_id)
    if new_sponsor is None:
        return ad.back(f"{_detail_path(uid)}/sponsor", err="invalid_input")
    try:
        with write_session() as db:
            registration.reassign_sponsor(db, head_admin=ctx.admin, guest_id=uid, new_sponsor_id=new_sponsor,
                                          ip=client_ip(request))
    except Forbidden:
        raise
    except ServiceError as exc:
        return ad.back(f"{_detail_path(uid)}/sponsor", err=ad.error_key(exc))
    return ad.back(_detail_path(uid), msg="sponsor_changed")
