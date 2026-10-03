"""Shared Jinja2 environment (autoescape on) and the `render()` helper for all routes.

Every template gets: `request`, `settings`, `t` (string catalog) and `csrf_token` (for the
hidden `csrf_token` field of user-side forms; admin templates pass their own). Use plain
paths for assets (`/static/...`), never absolute URLs.
"""

from __future__ import annotations

from pathlib import Path

import jinja2
from fastapi import Request
from fastapi.templating import Jinja2Templates
from starlette.responses import HTMLResponse

from app.config import get_settings
from app.money import format_money
from app.strings import t

ROOT = Path(__file__).resolve().parent.parent.parent
TEMPLATE_DIR = ROOT / "templates"

_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=True,
    trim_blocks=True,
    lstrip_blocks=True,
)
_env.globals["t"] = t
_env.filters["money"] = format_money
templates = Jinja2Templates(env=_env)


def render(request: Request, name: str, context: dict | None = None, *, status_code: int = 200,
           headers: dict | None = None) -> HTMLResponse:
    from app.web.deps import csrf_token_for  # local import: deps imports services only

    ctx = {"settings": get_settings()}
    if context is None or "csrf_token" not in context:
        ctx["csrf_token"] = csrf_token_for(request)
    ctx.update(context or {})
    return templates.TemplateResponse(request, name, ctx, status_code=status_code, headers=headers)
