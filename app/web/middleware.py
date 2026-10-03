"""Security middleware (pure ASGI) and the `no_store` helper (PROMPT §9).

For every HTTP response:
* strict CSP (`default-src 'self'`, no inline scripts/styles, `frame-ancestors 'none'`),
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, `X-Frame-Options: DENY`,
  `Cross-Origin-Opener-Policy`, `Permissions-Policy`; HSTS in production;
* `Cache-Control: no-store` unless the response set its own (static files excluded).

For every unsafe request (POST, PUT, PATCH, DELETE):
* cross-site requests are rejected with 403 (`Sec-Fetch-Site: cross-site`, or an `Origin`
  that is neither `PUBLIC_BASE_URL`'s origin nor the request's own host);
* bodies larger than `MAX_BODY_BYTES` are rejected with 413 (declared or streamed size).
"""

from __future__ import annotations

from urllib.parse import urlsplit

from starlette.datastructures import Headers
from starlette.exceptions import HTTPException
from starlette.responses import PlainTextResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

MAX_BODY_BYTES = 64 * 1024
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})

CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])
HSTS = "max-age=31536000"

BASE_HEADERS = {
    "content-security-policy": CSP,
    "x-content-type-options": "nosniff",
    "referrer-policy": "same-origin",
    "x-frame-options": "DENY",
    "cross-origin-opener-policy": "same-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
}


def no_store(response: Response) -> Response:
    """Mark a response as not cacheable (also the default for all non-static responses)."""
    response.headers["Cache-Control"] = "no-store"
    return response


def _origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}".lower()


class RequestTooLarge(HTTPException):
    def __init__(self) -> None:
        super().__init__(status_code=413)


class SecurityMiddleware:
    def __init__(self, app: ASGIApp, *, public_base_url: str, production: bool,
                 max_body_bytes: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.allowed_origin = _origin_of(public_base_url)
        self.max_body = max_body_bytes
        self.headers = dict(BASE_HEADERS)
        if production:
            self.headers["strict-transport-security"] = HSTS

    def _cross_site(self, headers: Headers) -> bool:
        if headers.get("sec-fetch-site", "").lower() == "cross-site":
            return True
        origin = headers.get("origin")
        if origin is None:
            return False
        origin = origin.strip().lower()
        if origin == self.allowed_origin:
            return False
        host = headers.get("host", "").lower()
        return not host or urlsplit(origin).netloc != host

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        is_static = scope.get("path", "").startswith("/static/")
        started = False

        async def send_wrapper(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                raw = [(k, v) for k, v in message.get("headers", []) if k.decode("latin-1").lower() not in self.headers]
                has_cache = any(k.lower() == b"cache-control" for k, _ in raw)
                raw += [(k.encode("latin-1"), v.encode("latin-1")) for k, v in self.headers.items()]
                if not has_cache and not is_static:
                    raw.append((b"cache-control", b"no-store"))
                message = {**message, "headers": raw}
            await send(message)

        headers = Headers(scope=scope)
        if scope["method"] not in SAFE_METHODS:
            if self._cross_site(headers):
                await PlainTextResponse("Cross-site request rejected.", status_code=403)(scope, receive, send_wrapper)
                return
            declared = headers.get("content-length")
            if declared is not None and (not declared.isdigit() or int(declared) > self.max_body):
                await PlainTextResponse("Request too large.", status_code=413)(scope, receive, send_wrapper)
                return

        received = 0

        async def receive_wrapper() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body:
                    raise RequestTooLarge()
            return message

        try:
            await self.app(scope, receive_wrapper, send_wrapper)
        except RequestTooLarge:
            if started:
                raise
            await PlainTextResponse("Request too large.", status_code=413)(scope, receive, send_wrapper)
