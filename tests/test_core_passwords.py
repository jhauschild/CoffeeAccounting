import argon2
import pytest

from app.config import Settings, get_settings
from app.services import passwords
from app.services.errors import InvalidInput, InvalidPassword
from tests.conftest import reload_settings


def test_hash_verify_roundtrip():
    h = passwords.hash_password("correct horse battery")
    assert h.startswith("$argon2id$") and h != passwords.hash_password("correct horse battery")
    assert passwords.verify_password(h, "correct horse battery")
    assert not passwords.verify_password(h, "wrong horse battery")
    assert not passwords.verify_password("!", "correct horse battery")
    assert not passwords.verify_password(h, "x" * 129)


def test_hash_refuses_overlong_without_echo():
    with pytest.raises(InvalidPassword) as exc:
        passwords.hash_password("p" * 129)
    assert "ppp" not in str(exc.value)


def test_needs_rehash_after_parameters_change(monkeypatch):
    old = passwords.hash_password("correct horse battery")
    assert not passwords.needs_rehash(old)
    assert passwords.verify_and_rehash(old, "correct horse battery") == (True, None)
    monkeypatch.setenv("ARGON2_TIME_COST", "2")
    reload_settings()
    assert passwords.needs_rehash(old) and passwords.needs_rehash("!")
    ok, new = passwords.verify_and_rehash(old, "correct horse battery")
    assert ok and new and new != old and not passwords.needs_rehash(new)
    assert passwords.verify_and_rehash(old, "nope nope nope") == (False, None)


def test_cheap_parameters_in_tests_and_production_defaults_unchanged(monkeypatch):
    s = get_settings()
    assert (s.argon2_time_cost, s.argon2_memory_cost_kib, s.argon2_parallelism) == (1, 8, 1)  # conftest
    for var in ("ARGON2_TIME_COST", "ARGON2_MEMORY_COST_KIB", "ARGON2_PARALLELISM"):
        monkeypatch.delenv(var)
    reload_settings()
    d = Settings(_env_file=None)
    assert (d.argon2_time_cost, d.argon2_memory_cost_kib, d.argon2_parallelism) == (3, 65536, 4)
    assert (3, 65536, 4) == (argon2.DEFAULT_TIME_COST, argon2.DEFAULT_MEMORY_COST, argon2.DEFAULT_PARALLELISM)
    assert passwords.hash_password("correct horse battery").startswith("$argon2id$v=19$m=65536,t=3,p=4$")


@pytest.mark.parametrize("pw,username,email,reason", [
    ("abc", "ann", None, "too_short"),
    ("x" * 9, "ann", None, "too_short"),
    ("x" * 129, "ann", None, "too_long"),
    ("Annabelle01", "annabelle01", None, "equals_username"),
    ("anna.mueller", "Ann", "Anna.Mueller@tum.de", "equals_email_local"),
])
def test_policy_rejects(pw, username, email, reason):
    with pytest.raises(InvalidPassword) as exc:
        passwords.validate_policy(pw, username, email)
    assert exc.value.context["reason"] == reason and exc.value.code == "invalid_password"
    assert isinstance(exc.value, InvalidInput) and pw not in str(exc.value)


def test_policy_accepts_boundaries():
    passwords.validate_policy("x" * 10, "ann")
    passwords.validate_policy("x" * 128, "ann", "ann@tum.de")
    passwords.validate_policy("anna.mueller.extra", "Ann", "anna.mueller@tum.de")


def test_policy_follows_configured_minimum(monkeypatch):
    monkeypatch.setenv("PASSWORD_MIN_LENGTH", "14")
    reload_settings()
    with pytest.raises(InvalidPassword):
        passwords.validate_policy("x" * 13, "ann")
    passwords.validate_policy("x" * 14, "ann")
