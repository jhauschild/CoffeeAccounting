"""Open site: `/overview*` (PLAN-v2 section 3, A10/A11; tasks 5.1 and 5.2).

Read-only and server-rendered; every number comes from `app.services.overview`. A valid user session is
required. An anonymous visitor gets a `view_site` pending action (no redirect parameter; the target is fixed in
the login code) and is sent to `/login`. Every response is `Cache-Control: private, no-store`.

Query parameters are validated here: an unknown `sort` falls back to `name`, `page` is parsed and clamped by the
service, `q` is length-limited, `chair` must be a UUID of a listed chair (anything else means "all chairs").
Displayed shot counts and amounts are floored at 0 (a reversal booked in a later month than its coffee can make a
month figure negative; the site never shows a minus sign).
"""

from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.orm import Session

from app.db import read_session, write_session
from app.services import overview, pending, ratelimit
from app.services.errors import NotFound
from app.strings import t
from app.timeutil import format_local, utcnow
from app.web import deps
from app.web.templating import render

router = APIRouter()

PAGE_SIZE = overview.DEFAULT_PER_PAGE
Q_MAX = overview.MAX_QUERY_LENGTH
PAGE_MAX_DIGITS = 6
CACHE_CONTROL = "private, no-store"

NAV_ITEMS = (
    ("overview", "/overview"),
    ("people", "/overview/people"),
    ("chairs", "/overview/chairs"),
    ("prices", "/overview/prices"),
    ("account", "/account"),
)

PEOPLE_COLUMNS = (
    ("name", "site.people.col_name"),
    (None, "site.people.col_chair"),
    ("shots_month", "site.people.col_month"),
    ("shots_total", "site.people.col_total"),
    ("balance", "site.people.col_balance"),
)

# Trend chart geometry (SVG user units; the SVG scales with its container).
CHART_WIDTH, CHART_HEIGHT = 360, 150
CHART_BASE, CHART_TOP, CHART_LABEL_Y = 124, 8, 142
CHART_SLOT, CHART_BAR = 30, 22


def _nn(value: int) -> int:
    return max(0, int(value))


def _redirect(path: str) -> RedirectResponse:
    response = RedirectResponse(path, status_code=303)
    response.headers["Cache-Control"] = CACHE_CONTROL
    return response


def _page(request: Request, template: str, context: dict, nav_current: str) -> Response:
    response = render(request, template, {**context, "nav_items": NAV_ITEMS, "nav_current": nav_current})
    response.headers["Cache-Control"] = CACHE_CONTROL
    return response


def _anonymous(request: Request) -> Response:
    """Park the visit as a `view_site` pending action (unless this browser already holds a live pending
    action, which is left alone so a waiting coffee is not displaced) and send the visitor to `/login`.

    Rows are capped per client address (`ratelimit.OVERVIEW_ANON`, 30 per 10 minutes, IPv6 by /64): over the
    cap the visitor is still redirected to `/login`, but no row and no cookie are created. The common
    cases (live pending action, over the cap) only read; the write transaction starts when a row is created."""
    response = _redirect("/login")
    pid = deps.pending_id(request)
    bucket, limit, window = ratelimit.OVERVIEW_ANON
    key = ratelimit.ip_key(deps.client_ip(request))
    with read_session() as db:
        if pid is not None and pending.get_pending(db, pid) is not None:
            return response
        if ratelimit.is_limited(db, bucket, key, limit, window):
            return response
    with write_session() as db:
        if ratelimit.is_limited(db, bucket, key, limit, window):  # re-check under the write lock
            return response
        ratelimit.record_hit(db, bucket, key)
        new_id = pending.create_view_site_pending(db)
    deps.set_pending_cookie(response, new_id)
    return response


def _trend_chart(trend) -> dict:
    values = [_nn(p.shots) for p in trend]
    peak = max(values) or 1
    room = CHART_BASE - CHART_TOP
    bars = []
    for i, (point, shots) in enumerate(zip(trend, values, strict=True)):
        height = 0 if shots == 0 else max(2, round(room * shots / peak))
        x = i * CHART_SLOT + (CHART_SLOT - CHART_BAR) // 2
        bars.append({
            "label": point.label, "short": point.label[5:7], "shots": shots, "amount_cents": _nn(point.amount_cents),
            "x": x, "cx": x + CHART_BAR // 2, "y": CHART_BASE - height, "height": height,
        })
    return {"bars": bars, "width": CHART_WIDTH, "height": CHART_HEIGHT, "base": CHART_BASE,
            "label_y": CHART_LABEL_Y, "bar_width": CHART_BAR}


@router.get("/overview")
def overview_page(request: Request, db: Session = Depends(deps.get_read_db)):
    if deps.current_user(request) is None:
        return _anonymous(request)
    site = overview.site_totals(db)
    totals = {
        "total_shots": _nn(site.total_shots), "consumed_cents": _nn(site.consumed_cents),
        "paid_cents": _nn(site.paid_cents), "owed_total_cents": _nn(site.owed_total_cents),
        "credit_total_cents": _nn(site.credit_total_cents), "current_price_cents": site.current_price_cents,
        "month_shots": _nn(site.month_shots), "month_amount_cents": _nn(site.month_amount_cents),
    }
    chairs = [{"id": c.chair_id, "name": c.name, "members": c.members, "shots": _nn(c.shots),
               "owed_cents": _nn(c.owed_cents), "credit_cents": _nn(c.credit_cents)} for c in site.chairs]
    return _page(request, "site/overview.html",
                 {"totals": totals, "chairs": chairs, "chart": _trend_chart(site.trend)}, "overview")


def _parse_page(value: str | None) -> int:
    value = (value or "").strip()
    if not value.isascii() or not value.isdigit() or len(value) > PAGE_MAX_DIGITS:
        return 1
    return max(1, int(value))


def _people_url(*, q: str, chair: str, sort: str, page: int = 1) -> str:
    params: dict[str, str] = {}
    if q:
        params["q"] = q
    if chair:
        params["chair"] = chair
    if sort != "name":
        params["sort"] = sort
    if page > 1:
        params["page"] = str(page)
    return "/overview/people" + ("?" + urlencode(params) if params else "")


@router.get("/overview/people")
def people_page(request: Request, q: str = "", chair: str = "", sort: str = "name", page: str = "1",
                db: Session = Depends(deps.get_read_db)):
    if deps.current_user(request) is None:
        return _anonymous(request)
    q = " ".join(q.split())[:Q_MAX]  # collapse whitespace/control characters, limit the length
    sort = sort if sort in overview.PEOPLE_SORTS else "name"
    options = overview.chair_choices(db)
    chair_id = deps.parse_uuid(chair)
    if chair_id is not None and all(chair_id != cid for cid, _ in options):
        chair_id = None
    chair_value = str(chair_id) if chair_id else ""

    result = overview.people(db, query=q, chair_id=chair_id, sort=sort, page=_parse_page(page), per_page=PAGE_SIZE)
    rows = [{"id": r.id, "name": r.display_name, "chair": r.chair_name, "shots_month": _nn(r.shots_month),
             "shots_total": _nn(r.shots_total), "label": r.balance_label, "inactive": r.inactive}
            for r in result.rows]
    base = {"q": q, "chair": chair_value}
    context = {
        "rows": rows, "total": result.total, "page": result.page, "pages": result.pages, "sort": result.sort,
        "q": q, "q_max": Q_MAX, "chair": chair_value, "chair_options": options, "sorts": overview.PEOPLE_SORTS,
        "columns": PEOPLE_COLUMNS,
        "sort_links": {key: _people_url(**base, sort=key) for key in overview.PEOPLE_SORTS},
        "prev_link": _people_url(**base, sort=result.sort, page=result.page - 1) if result.page > 1 else None,
        "next_link": (_people_url(**base, sort=result.sort, page=result.page + 1)
                      if result.page < result.pages else None),
    }
    return _page(request, "site/people.html", context, "people")


# ----- task 5.2: person, chairs, prices ---------------------------------------------------------------
DATE_FORMAT = "%Y-%m-%d %H:%M"


def _not_found(request: Request) -> Response:
    """Plain 404 (same page for unknown, malformed, merged and hidden ids), never cached."""
    response = render(request, "error.html", {"status_code": 404, "message": t("error.not_found"), "csrf_token": ""},
                      status_code=404)
    response.headers["Cache-Control"] = CACHE_CONTROL
    return response


@router.get("/overview/people/{person_id}")
def person_page(request: Request, person_id: str, db: Session = Depends(deps.get_read_db)):
    ctx = deps.current_user(request)
    if ctx is None:
        return _anonymous(request)
    pid = deps.parse_uuid(person_id)
    if pid is None:
        return _not_found(request)
    try:
        person = overview.person_history(db, pid)
    except NotFound:
        return _not_found(request)
    if person.id != pid:  # an id that was merged into another profile is not a person of its own
        return _not_found(request)
    # Reversals and paid-back money are shown as words with absolute amounts: no minus sign on the site.
    consumption = [{
        "date": format_local(c.date, DATE_FORMAT), "shots": abs(c.shots), "price_cents": c.unit_price_cents,
        "amount_cents": abs(c.amount_cents),
        "kind": "reversal" if c.is_reversal else ("reversed" if c.is_reversed else "coffee"),
    } for c in person.consumption]
    # A head admin's balance correction (bookkeeping) moved no money: neutral "Balance adjustment", never "Paid back".
    payments = [{"date": format_local(p.date, DATE_FORMAT), "amount_cents": abs(p.amount_cents),
                 "kind": "adjustment" if p.is_bookkeeping else ("payback" if p.amount_cents < 0 else "payment")}
                for p in person.payments]
    context = {
        "person": {"id": person.id, "name": person.display_name, "chair": person.chair_name,
                   "inactive": person.inactive, "label": person.balance_label,
                   "shots_month": _nn(person.shots_month), "shots_total": _nn(person.shots_total)},
        "consumption": consumption, "payments": payments,
        "has_adjustment": any(p["kind"] == "adjustment" for p in payments),
        "has_payback": any(p["kind"] == "payback" for p in payments),
        "can_edit": overview.can_edit_balance(db, ctx.user.id, person),
    }
    return _page(request, "site/person.html", context, "people")


@router.get("/overview/chairs")
def chairs_page(request: Request, db: Session = Depends(deps.get_read_db)):
    if deps.current_user(request) is None:
        return _anonymous(request)
    chairs = [{
        "id": c.chair_id, "name": c.name, "full_name": c.full_name, "members": c.members,
        "admins": list(c.group_admins), "owed_cents": _nn(c.owed_cents), "credit_cents": _nn(c.credit_cents),
        "collected_cents": c.collected_cents, "handed_over_cents": c.handed_over_cents, "held_cents": c.held_cents,
    } for c in overview.chairs_overview(db)]
    return _page(request, "site/chairs.html", {"chairs": chairs}, "chairs")


@router.get("/overview/prices")
def prices_page(request: Request, db: Session = Depends(deps.get_read_db)):
    if deps.current_user(request) is None:
        return _anonymous(request)
    now = utcnow()
    points = overview.price_history(db)  # newest first
    current = next((p for p in points if p.effective_from <= now), None)
    rows = [{"from": format_local(p.effective_from, DATE_FORMAT), "price_cents": p.price_per_shot_cents,
             "state": "scheduled" if p.effective_from > now else ("current" if p is current else "")}
            for p in points]
    return _page(request, "site/prices.html", {"rows": rows}, "prices")
