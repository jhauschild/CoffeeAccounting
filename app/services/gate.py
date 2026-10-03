"""Department access gate (PROMPT §5).

`ACCESS_CODE` is compared in constant time. A correct code yields a signed `coffee_gate`
cookie valid for one hour. The cookie's signing key is bound to the current access code,
so rotating `ACCESS_CODE` (and restarting) also invalidates outstanding gate cookies.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime

from app.config import get_settings
from app.services import signing

GATE_COOKIE = "coffee_gate"
GATE_MAX_AGE = 3600
MAX_CODE_LENGTH = 200
_PURPOSE = "gate"


def _code_binding() -> str:
    return hashlib.sha256(get_settings().access_code.encode("utf-8")).hexdigest()


def check_access_code(code: str | None) -> bool:
    if not code or not isinstance(code, str) or len(code) > MAX_CODE_LENGTH:
        return False
    given = hashlib.sha256(code.strip().encode("utf-8")).digest()
    expected = hashlib.sha256(get_settings().access_code.strip().encode("utf-8")).digest()
    return hmac.compare_digest(given, expected)


def make_gate_cookie(now: datetime | None = None) -> str:
    return signing.sign(_PURPOSE, {"g": 1}, now=now, extra=_code_binding())


def verify_gate_cookie(value: str | None, now: datetime | None = None) -> bool:
    payload = signing.unsign(_PURPOSE, value, max_age=GATE_MAX_AGE, now=now, extra=_code_binding())
    return payload is not None and payload.get("g") == 1
