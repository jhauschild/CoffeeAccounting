"""Small HMAC-SHA256 signer for short, self-contained tokens (scan tokens,
registration tokens, CSRF tokens).

Format: ``base64url(json payload) "." base64url(hmac)``. Every token has a *purpose*; the
HMAC key is derived with HKDF (``keys.derive_key``, label ``signing:<purpose>:<extra>``) from ``SECRET_KEY``,
so a token minted for one purpose never verifies for another. The payload always carries
``iat`` (issued-at, integer UNIX seconds). Verification uses a constant-time comparison.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime

from app.services import keys
from app.timeutil import utcnow

# Tokens issued slightly "in the future" (clock skew between workers) are tolerated.
CLOCK_SKEW_SECONDS = 60
MAX_TOKEN_LENGTH = 2048


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _key(purpose: str, extra: str = "") -> bytes:
    """HKDF key (`keys.derive_key`) with its own label per purpose (and extra key material)."""
    return keys.derive_key(f"signing:{purpose}:{extra}")


def mac(purpose: str, message: str, extra: str = "") -> str:
    """Deterministic keyed MAC of `message` (hex), e.g. for CSRF tokens bound to a session."""
    return hmac.new(_key(purpose, extra), message.encode("utf-8"), hashlib.sha256).hexdigest()


def _ts(now: datetime | None) -> int:
    return int((now or utcnow()).timestamp())


def sign(purpose: str, payload: dict, *, now: datetime | None = None, extra: str = "") -> str:
    body = dict(payload)
    body["iat"] = _ts(now)
    raw = _b64e(json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    sig = _b64e(hmac.new(_key(purpose, extra), raw.encode("ascii"), hashlib.sha256).digest())
    return f"{raw}.{sig}"


def unsign(purpose: str, token: str | None, *, max_age: int, now: datetime | None = None,
           extra: str = "") -> dict | None:
    """Return the payload if the signature is valid and the token is not expired, else None."""
    if not token or not isinstance(token, str) or len(token) > MAX_TOKEN_LENGTH or token.count(".") != 1:
        return None
    raw, sig = token.split(".", 1)
    try:
        expected = _b64e(hmac.new(_key(purpose, extra), raw.encode("ascii"), hashlib.sha256).digest())
    except UnicodeEncodeError:
        return None
    if not hmac.compare_digest(expected.encode("utf-8"), sig.encode("utf-8")):
        return None
    try:
        payload = json.loads(_b64d(raw))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("iat"), int):
        return None
    age = _ts(now) - payload["iat"]
    if age > max_age or age < -CLOCK_SKEW_SECONDS:
        return None
    return payload
