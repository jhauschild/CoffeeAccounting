"""Head admin: group balances, remittances (money received from group admins) and the group balance CSV
(owner: admin agent). Group admins get 403 on every route here.

The two POST routes only PREVIEW (a rolled-back dry run rendering the confirm page); the booking happens in
`POST /admin/stepup/confirm` through the registered actions `remittance` and `remittance_correction`
(app/services/stepup.py).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from starlette.responses import Response

from app.db import read_session, write_session
from app.models import NOTE_MAX
from app.services import exports, group_report, groups
from app.services.errors import NotFound
from app.web import admin_deps as ad
from app.web.deps import client_ip, parse_uuid
from app.web.middleware import no_store

router = APIRouter()

GROUPS_PATH = "/admin/groups"


@router.get("/groups")
def groups_page(request: Request, ctx: ad.AdminContext = Depends(ad.require_global_admin)):
    with read_session() as db:
        balances = groups.list_group_balances(db)
        rollup = groups.chair_rollup(db)
        entries = group_report.remittance_rows(db)
        return ad.page(request, ctx, "admin/groups.html",
                       {"balances": balances, "rollup": rollup, "entries": entries, "note_max": NOTE_MAX,
                        "flagged": groups.over_credit_paybacks(db),
                        "total_held_cents": sum(b.held_cents for b in balances)})


@router.post("/groups/remittances", dependencies=[Depends(ad.require_admin_csrf)])
def remittance_preview(request: Request, group_admin_id: str = Form("", max_length=40),
                       amount: str = Form("", max_length=20), note: str = Form("", max_length=NOTE_MAX),
                       ctx: ad.AdminContext = Depends(ad.require_global_admin)):
    return ad.preview(request, ctx, "remittance",
                      {"group_admin_id": group_admin_id, "amount": amount, "note": note}, error_path=GROUPS_PATH)


@router.post("/groups/remittances/{remittance_id}/correct", dependencies=[Depends(ad.require_admin_csrf)])
def remittance_correction_preview(request: Request, remittance_id: str, corrected_to: str = Form("", max_length=20),
                                  note: str = Form("", max_length=NOTE_MAX),
                                  ctx: ad.AdminContext = Depends(ad.require_global_admin)):
    rid = parse_uuid(remittance_id)
    if rid is None:
        raise NotFound("remittance not found")
    return ad.preview(request, ctx, "remittance_correction",
                      {"correction_of": str(rid), "corrected_to": corrected_to, "note": note},
                      error_path=GROUPS_PATH)


@router.get("/exports/group-balances.csv")
def group_balances_export(request: Request, ctx: ad.AdminContext = Depends(ad.require_global_admin)):
    with write_session() as db:  # the export is audited
        data = exports.group_balances_csv(db, ctx.admin, ip=client_ip(request))
    response = Response(data, media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition":
                                 f'attachment; filename="{exports.csv_filename("group-balances")}"'})
    return no_store(response)
