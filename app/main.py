"""Application factory. Run with `uvicorn app.main:app` (single process; see README).

`create_app()` validates the settings (production refuses insecure configuration and
fails at startup), installs the security middleware, the static mount, the routers and
safe error handlers (no stack traces or exception details are ever sent to clients;
FastAPI's docs/OpenAPI are disabled in production).
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.exc import OperationalError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import PlainTextResponse, Response

from app.config import Settings, get_settings
from app.services.errors import ServiceError
from app.strings import has, t
from app.web import health, routes_admin, routes_overview, routes_user
from app.web.accesslog import AccessLogMiddleware, redact_path
from app.web.deps import CSRFError, Redirect
from app.web.middleware import SecurityMiddleware
from app.web.templating import ROOT, render

log = logging.getLogger("app")

STATUS_KEYS = {
    400: "error.bad_request",
    403: "error.forbidden",
    404: "error.not_found",
    405: "error.method_not_allowed",
    413: "error.too_large",
    422: "error.bad_request",
    429: "error.rate_limited",
    503: "error.transient",
}
SERVICE_ERROR_STATUS = {"not_found": 404, "forbidden": 403, "user_inactive": 403, "rate_limited": 429,
                        "conflict": 409}


def error_page(request: Request, status_code: int, message_key: str, headers: dict | None = None) -> Response:
    """Safe HTML error page; falls back to plain text if rendering itself fails."""
    try:
        return render(request, "error.html", {"status_code": status_code, "message": t(message_key),
                                              "csrf_token": ""}, status_code=status_code, headers=headers)
    except Exception:  # noqa: BLE001
        log.exception("rendering the error page failed")
        return PlainTextResponse(t(message_key), status_code=status_code, headers=headers)


def _install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(Redirect)
    async def _redirect(request: Request, exc: Redirect) -> Response:
        return RedirectResponse(exc.path, status_code=303)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> Response:
        key = "error.csrf" if isinstance(exc, CSRFError) else STATUS_KEYS.get(exc.status_code, "error.internal"
                                                                            if exc.status_code >= 500
                                                                            else "error.bad_request")
        return error_page(request, exc.status_code, key, getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> Response:
        return error_page(request, 400, "error.bad_request")

    @app.exception_handler(ServiceError)
    async def _service(request: Request, exc: ServiceError) -> Response:
        key = f"error.{exc.code}"
        status = SERVICE_ERROR_STATUS.get(exc.code, 400)
        return error_page(request, status, key if has(key) else "error.error")

    @app.exception_handler(OperationalError)
    async def _transient(request: Request, exc: OperationalError) -> Response:
        log.warning("database operational error: %s", exc.__class__.__name__, exc_info=True)
        return error_page(request, 503, "error.transient", {"Retry-After": "2"})

    @app.exception_handler(PoolTimeoutError)
    async def _pool_timeout(request: Request, exc: PoolTimeoutError) -> Response:
        return error_page(request, 503, "error.transient", {"Retry-After": "2"})

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception) -> Response:
        log.error("unhandled error on %s %s", request.method, redact_path(request.url.path), exc_info=exc)
        return error_page(request, 500, "error.internal")


def _configure_logging(level: str) -> None:
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(level=level.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    else:
        root.setLevel(level.upper())


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    _configure_logging(settings.log_level)
    production = settings.is_production
    app = FastAPI(
        title=settings.app_title,
        debug=False,
        docs_url=None,
        redoc_url=None,
        openapi_url=None if production else "/openapi.json",
    )
    app.add_middleware(SecurityMiddleware, public_base_url=settings.public_base_url, production=production)
    app.add_middleware(AccessLogMiddleware)  # outermost: sees the final status; never logs token paths
    app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")
    app.include_router(health.router)
    app.include_router(routes_user.router)
    app.include_router(routes_overview.router)
    app.include_router(routes_admin.router)
    _install_error_handlers(app)
    return app


app = create_app()
