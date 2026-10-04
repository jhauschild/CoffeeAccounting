"""Encrypted store for the mail (SMTP) login (PLAN-v2 section 1 "Mail login: asked for during admin setup").

One file in `settings.secrets_dir`: the directory is mode 0700, the file mode 0600, written atomically (temp
file in the same directory, fsync, `os.replace`, directory fsync; modes set with `fchmod`/`chmod`, so the
process umask does not matter). Content is a Fernet token whose key is `keys.fernet_key("mail-credentials")`
(HKDF of SECRET_KEY). Changing SECRET_KEY, or a damaged file, makes the login unreadable: `MailLoginUnreadable`
with the fixed message `UNREADABLE_MESSAGE`; the `cryptography` exception text is never surfaced.

The password never reaches logs, `repr`/`str` of any object (`MailCredentials` hides it), exceptions or
`status()`. This module does not log at all. There is no settings field for it.

API: `save_credentials(username, password)`, `load_credentials()`, `clear_credentials()`, `status()`.
Callers: the SMTP backend (per send), the CLI (`setup-mail`, `mail-status`, `clear-mail`) and the admin page.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings
from app.services import keys
from app.services.errors import InvalidInput
from app.services.mail import MailError

KEY_LABEL = "mail-credentials"
FILE_NAME = "mail-login.enc"
DIR_MODE = 0o700
FILE_MODE = 0o600
MAX_USERNAME_LENGTH = 254
MAX_PASSWORD_LENGTH = 1024
UNREADABLE_MESSAGE = "mail login unreadable: re-run setup-mail"


class MailLoginUnreadable(MailError):
    """The stored login cannot be decrypted (SECRET_KEY changed) or is damaged. Category `not_configured`
    (mail cannot be sent until `setup-mail` is run again); the message is fixed and carries no detail."""

    def __init__(self):
        super().__init__("not_configured", reason="unreadable")
        self.args = (UNREADABLE_MESSAGE,)

    def __str__(self) -> str:
        return UNREADABLE_MESSAGE


@dataclass(frozen=True)
class MailCredentials:
    username: str
    password: str = field(repr=False)

    def __repr__(self) -> str:
        return f"MailCredentials(username={self.username!r}, password=<hidden>)"

    __str__ = __repr__

    def __reduce__(self):  # never serialised by accident
        raise TypeError("MailCredentials cannot be serialised")


@dataclass(frozen=True)
class MailLoginStatus:
    configured: bool  # a readable login is stored
    masked_username: str | None = None  # e.g. "c***@lrz.de"
    unreadable: bool = False  # a file exists but cannot be decrypted (wrong SECRET_KEY or damaged)


def mask_username(username: str) -> str:
    """`coffee@lrz.de` -> `c***@lrz.de`; a name without a domain -> `c***`."""
    local, at, domain = username.partition("@")
    head = local[:1]
    return f"{head}***{at}{domain}" if at else f"{head}***"


def secrets_dir() -> Path:
    return Path(get_settings().secrets_dir)


def credentials_path() -> Path:
    return secrets_dir() / FILE_NAME


def _fernet() -> Fernet:
    return Fernet(keys.fernet_key(KEY_LABEL))


def _ensure_dir() -> Path:
    directory = secrets_dir()
    directory.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
    os.chmod(directory, DIR_MODE)  # fixes a pre-existing directory and ignores the umask
    return directory


def _validate(username: str, password: str) -> tuple[str, str]:
    username = (username or "").strip()
    if not username or len(username) > MAX_USERNAME_LENGTH or any(ord(c) < 32 or ord(c) == 127 for c in username):
        raise InvalidInput("invalid mail username", field="username")
    if not password or len(password) > MAX_PASSWORD_LENGTH:  # message never contains the value
        raise InvalidInput("invalid mail password", field="password")
    return username, password


def _fsync_dir(directory: Path) -> None:
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def save_credentials(username: str, password: str) -> None:
    """Encrypt and store the login, replacing an earlier one atomically. Raises `InvalidInput` for an empty or
    absurd value (the message never contains the password)."""
    username, password = _validate(username, password)
    token = _fernet().encrypt(json.dumps({"username": username, "password": password}).encode("utf-8"))
    directory = _ensure_dir()
    target = directory / FILE_NAME
    temp = directory / f".{FILE_NAME}.{os.getpid()}.{os.urandom(4).hex()}.tmp"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE)
    try:
        try:
            os.fchmod(fd, FILE_MODE)
            with os.fdopen(fd, "wb") as fh:
                fd = -1  # now owned by the file object
                fh.write(token)
                fh.flush()
                os.fsync(fh.fileno())
        finally:
            if fd != -1:
                os.close(fd)
        os.replace(temp, target)
    except BaseException:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise
    _fsync_dir(directory)


def load_credentials() -> MailCredentials:
    """The stored login. `MailError("not_configured")` if none was saved; `MailLoginUnreadable` if the file
    cannot be decrypted or parsed."""
    try:
        token = credentials_path().read_bytes()
    except FileNotFoundError:
        raise MailError("not_configured") from None
    except OSError:
        raise MailLoginUnreadable() from None
    try:
        data = json.loads(_fernet().decrypt(token))
        username, password = data["username"], data["password"]
        if not isinstance(username, str) or not isinstance(password, str) or not username or not password:
            raise ValueError
    except (InvalidToken, ValueError, KeyError, TypeError):
        raise MailLoginUnreadable() from None
    return MailCredentials(username=username, password=password)


def clear_credentials() -> bool:
    """Delete the stored login. Returns True if a file was removed."""
    try:
        credentials_path().unlink()
    except FileNotFoundError:
        return False
    except OSError:
        raise MailError("other") from None
    _fsync_dir(secrets_dir())
    return True


def status() -> MailLoginStatus:
    """Whether a readable login is stored and its masked username; never the password."""
    try:
        creds = load_credentials()
    except MailLoginUnreadable:
        return MailLoginStatus(configured=False, unreadable=True)
    except MailError:
        return MailLoginStatus(configured=False)
    return MailLoginStatus(configured=True, masked_username=mask_username(creds.username))
