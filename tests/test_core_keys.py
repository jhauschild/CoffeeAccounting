import base64

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config import get_settings
from app.services import keys
from tests.conftest import reload_settings


def test_matches_reference_hkdf_and_is_deterministic():
    expect = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"mail-login").derive(
        get_settings().secret_key.encode())
    assert keys.derive_key("mail-login") == expect == keys.derive_key("mail-login")


def test_labels_and_lengths():
    assert keys.derive_key("a") != keys.derive_key("b")
    assert len(keys.derive_key("a", 64)) == 64 and len(keys.derive_key("a", 16)) == 16
    assert keys.derive_key("a", 16) == keys.derive_key("a", 64)[:16]  # HKDF-Expand is a prefix code


def test_depends_on_secret_key(monkeypatch):
    before = keys.derive_key("a")
    monkeypatch.setenv("SECRET_KEY", "another-secret-key-0123456789abcdef0123456789")
    reload_settings()
    assert keys.derive_key("a") != before


def test_fernet_key_is_usable():
    k = keys.fernet_key("mail-login")
    assert base64.urlsafe_b64decode(k) == keys.derive_key("mail-login")
    f = Fernet(k)
    assert f.decrypt(f.encrypt(b"x")) == b"x"
    assert keys.fernet_key("other") != k


@pytest.mark.parametrize("label,length", [("", 32), (None, 32), ("a", 0), ("a", 255 * 32 + 1)])
def test_rejects_bad_arguments(label, length):
    with pytest.raises(ValueError):
        keys.derive_key(label, length)
