"""Signed tokens used by the web layer (HMAC with SECRET_KEY, see `app.services.signing`).

* Scan token (PROMPT §3): kind + random nonce + issued-at, valid 30 minutes. Issuing it
  writes nothing to the database.
* Registration token: one-time token for the registration form (see
  `app.services.onboarding` for how single use is enforced), valid 1 hour.
* CSRF tokens: deterministic MAC bound to a scope and a per-session key, so they need no
  storage and die with the session. Scopes: "user" (user session id), "gate" (gate cookie
  value, for pre-session forms), "admin" (admin session's `csrf_secret`).
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

from app.models import COFFEE_KINDS
from app.services import signing

SCAN_TOKEN_MAX_AGE = 30 * 60
REGISTRATION_TOKEN_MAX_AGE = 60 * 60
CSRF_FIELD = "csrf_token"
SCAN_TOKEN_FIELD = "token"
REGISTRATION_TOKEN_FIELD = "registration_token"


@dataclass(frozen=True)
class ScanToken:
    kind: str
    nonce: str
    issued_at: datetime


def make_scan_token(kind: str, now: datetime | None = None) -> str:
    if kind not in COFFEE_KINDS:
        raise ValueError("invalid coffee kind")
    return signing.sign("scan", {"k": kind, "n": secrets.token_urlsafe(24)}, now=now)


def verify_scan_token(token: str | None, kind: str, now: datetime | None = None) -> ScanToken | None:
    """Valid signature, matching kind, not older than 30 minutes -> ScanToken, else None."""
    payload = signing.unsign("scan", token, max_age=SCAN_TOKEN_MAX_AGE, now=now)
    if payload is None or payload.get("k") != kind or kind not in COFFEE_KINDS:
        return None
    nonce = payload.get("n")
    if not isinstance(nonce, str) or not 16 <= len(nonce) <= 64:
        return None
    return ScanToken(kind, nonce, datetime.fromtimestamp(payload["iat"], timezone.utc))


def make_registration_token(now: datetime | None = None) -> str:
    return signing.sign("register", {"n": secrets.token_urlsafe(24)}, now=now)


def verify_registration_token(token: str | None, now: datetime | None = None) -> str | None:
    """Return the token's nonce (pass it to `register_and_start_session`) or None."""
    payload = signing.unsign("register", token, max_age=REGISTRATION_TOKEN_MAX_AGE, now=now)
    nonce = payload.get("n") if payload else None
    return nonce if isinstance(nonce, str) and 16 <= len(nonce) <= 64 else None


def csrf_token(scope: str, key: str) -> str:
    return signing.mac("csrf", f"{scope}:{key}")


def verify_csrf(scope: str, key: str | None, token: str | None) -> bool:
    if not key or not token or not isinstance(token, str) or len(token) > 128:
        return False
    return hmac.compare_digest(csrf_token(scope, key), token)
