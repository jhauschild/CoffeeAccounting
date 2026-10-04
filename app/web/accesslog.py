"""Application-level access log that never records one-time tokens.

`/verify/<token>` and `/reset/<token>` carry single-use secrets in the path. uvicorn's own access log
(which prints the full request line) is switched off in `scripts/run.sh` (`--no-access-log`); this
middleware logs one line per request instead: method, status and the path, with the segment after
`/verify/` and `/reset/` replaced by `<redacted>`. The query string is never logged. The reverse proxy
must redact the same two prefixes (see deploy/README.md).
"""

from __future__ import annotations

import logging

from starlette.types import ASGIApp, Message, Receive, Scope, Send

log = logging.getLogger("app.access")

SECRET_PREFIXES = ("/verify/", "/reset/")


def redact_path(path: str) -> str:
    """The path with the secret segment of `/verify/...` and `/reset/...` removed."""
    for prefix in SECRET_PREFIXES:
        if path.startswith(prefix):
            return f"{prefix}<redacted>"
    return path


class AccessLogMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        status = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            log.info("%s %s -> %s", scope.get("method", "-"), redact_path(scope.get("path", "")), status)
