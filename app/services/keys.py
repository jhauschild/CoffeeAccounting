"""Key derivation from SECRET_KEY (HKDF-SHA256).

Each purpose uses its own label, so a leak of one derived key says nothing about another. Labels are
passed as HKDF `info`; there is no salt (SECRET_KEY is already high-entropy random). Derivation is
deterministic: the same SECRET_KEY and label always give the same key.

Not migrated yet: v1 HMAC/CSRF token signing (`app/services/signing.py`, `app/web`) keeps its own
derivation; moving it onto `derive_key` with distinct labels is a later task.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config import get_settings

MAX_KEY_LENGTH = 255 * 32  # HKDF-SHA256 limit


def derive_key(label: str, length: int = 32) -> bytes:
    if not isinstance(label, str) or not label:
        raise ValueError("label must be a non-empty string")
    if not isinstance(length, int) or not 1 <= length <= MAX_KEY_LENGTH:
        raise ValueError("length out of range")
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=label.encode("utf-8")).derive(
        get_settings().secret_key.encode("utf-8")
    )


def fernet_key(label: str) -> bytes:
    """32 derived bytes, urlsafe-base64 encoded, as `cryptography.fernet.Fernet` expects."""
    return base64.urlsafe_b64encode(derive_key(label, 32))
