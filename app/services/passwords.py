"""Password hashing and policy for v2 accounts (Argon2id).

The Argon2 cost comes from settings (`ARGON2_*`); the defaults are the argon2-cffi values that
`admin_auth` also uses, so hashes are interchangeable. Tests lower the cost in `tests/conftest.py`.
`verify_password(hash, password)` keeps the argument order of `admin_auth.verify_password`.
"""

from __future__ import annotations

import secrets
from functools import lru_cache

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from app.config import get_settings
from app.services.errors import InvalidPassword

MAX_PASSWORD_LENGTH = 128

_dummy_hash: dict[tuple[int, int, int], str] = {}


@lru_cache
def _hasher_for(time_cost: int, memory_cost: int, parallelism: int) -> PasswordHasher:
    return PasswordHasher(time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism)


def get_hasher() -> PasswordHasher:
    s = get_settings()
    return _hasher_for(s.argon2_time_cost, s.argon2_memory_cost_kib, s.argon2_parallelism)


def hash_password(password: str) -> str:
    """Argon2id hash. Applies no policy (see `validate_policy`); only refuses non-strings and over-long input."""
    if not isinstance(password, str) or len(password) > MAX_PASSWORD_LENGTH:
        raise InvalidPassword("password has an invalid length", reason="too_long")
    return get_hasher().hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """False for a wrong password, over-long input and non-Argon2 hashes (e.g. a disabled "!")."""
    if not isinstance(password, str) or len(password) > MAX_PASSWORD_LENGTH:
        return False
    try:
        return get_hasher().verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """True when the stored hash uses weaker parameters than the current settings."""
    try:
        return get_hasher().check_needs_rehash(password_hash)
    except (VerificationError, InvalidHashError):
        return True


def verify_and_rehash(password_hash: str, password: str) -> tuple[bool, str | None]:
    """(ok, new_hash). `new_hash` is set only when the password is right and the hash is outdated."""
    if not verify_password(password_hash, password):
        return False, None
    return True, (hash_password(password) if needs_rehash(password_hash) else None)


def hash_if_acceptable_length(password: str) -> str | None:
    """Argon2id hash for a caller that must hash BEFORE it opens its write transaction (registration, reset,
    password change): None when the length is outside `PASSWORD_MIN_LENGTH..128`, because the service then
    refuses the password before it would hash anyway (a refused password must not cost an Argon2 run)."""
    if not isinstance(password, str) or not (get_settings().password_min_length <= len(password) <= MAX_PASSWORD_LENGTH):
        return None
    return get_hasher().hash(password)


def verify_dummy(password: str) -> None:
    """Burn comparable time for unknown usernames so timing does not reveal them."""
    s = get_settings()
    key = (s.argon2_time_cost, s.argon2_memory_cost_kib, s.argon2_parallelism)
    if key not in _dummy_hash:
        _dummy_hash[key] = get_hasher().hash(secrets.token_urlsafe(16))
    verify_password(_dummy_hash[key], password)


def validate_policy(password: str, username: str, email: str | None = None) -> None:
    """Raise `InvalidPassword` unless the password has PASSWORD_MIN_LENGTH..128 characters and equals
    neither the username nor the email local part (case-insensitive)."""
    if not isinstance(password, str) or len(password) < get_settings().password_min_length:
        raise InvalidPassword("password is too short", reason="too_short",
                              min_length=get_settings().password_min_length)
    if len(password) > MAX_PASSWORD_LENGTH:
        raise InvalidPassword("password is too long", reason="too_long", max_length=MAX_PASSWORD_LENGTH)
    folded = password.casefold()
    if username and folded == " ".join(username.split()).casefold():
        raise InvalidPassword("password must not equal the username", reason="equals_username")
    if email and "@" in email and folded == email.rsplit("@", 1)[0].strip().casefold():
        raise InvalidPassword("password must not equal the email address", reason="equals_email_local")
