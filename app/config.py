"""Application settings, read from environment variables (and an optional `.env`).

All variables from PROMPT §11 are supported. In production (`ENVIRONMENT=production`)
startup refuses insecure configuration (PROMPT §9): a non-https `PUBLIC_BASE_URL`,
a missing/short/placeholder `SECRET_KEY`, a mail backend other than `smtp`, bad SMTP settings or a
missing `MAIL_FROM`. Development mode refuses the published `DEV_SECRET_KEY` unless `PUBLIC_BASE_URL` is a
local http:// address. Error messages never echo configuration values.

`get_settings()` is cached; tests that change the environment call
`get_settings.cache_clear()`.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit
from functools import lru_cache
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from argon2 import DEFAULT_MEMORY_COST, DEFAULT_PARALLELISM, DEFAULT_TIME_COST
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEV_SECRET_KEY = "dev-insecure-secret-key-not-for-production-use"

MIN_SECRET_KEY_LENGTH = 32

# Exact values (case-insensitive) that must never be used in production.
_PLACEHOLDER_VALUES = {
    DEV_SECRET_KEY,
    "secret",
    "password",
    "changeme",
    "12345678",
    "coffee",
    "coffeecoffee",
}
# Substrings that mark a value as a template placeholder (e.g. from .env.example).
_PLACEHOLDER_MARKERS = ("change-me", "changeme", "change_me", "replace-me", "replace_me", "placeholder", "example", "insecure")

_CURRENCY_SYMBOLS = {"EUR": "€", "USD": "$", "GBP": "£", "CHF": "CHF"}


def is_placeholder(value: str) -> bool:
    v = value.strip().lower()
    return v in _PLACEHOLDER_VALUES or any(m in v for m in _PLACEHOLDER_MARKERS)


def _is_local_host(url: str) -> bool:
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore",
                                      hide_input_in_errors=True)

    environment: Literal["development", "production"] = "development"
    public_base_url: str = "http://localhost:8000"
    database_url: str = "sqlite:///./data/coffee.db"
    secret_key: str = DEV_SECRET_KEY

    session_lifetime_days: int = 180
    admin_session_hours: int = 12

    local_timezone: str = "Europe/Berlin"
    app_title: str = "Coffee Ledger"
    operator_contact: str = ""
    retention_text: str = (
        "Ledger entries are kept as long as the coffee ledger is operated, because balances are "
        "derived from the complete history. Expired browser sessions are purged regularly."
    )
    chair_label: str = "Chair"
    # "EUR" or "EUR:€" (code, optionally followed by ':' and the display symbol).
    currency: str = "EUR"

    undo_window_seconds: int = 300
    max_coffees_per_session_per_hour: int = 30
    # Comma-separated IPs or CIDR networks of reverse proxies whose X-Forwarded-For is trusted.
    trusted_proxy_ips: str = ""

    csv_delimiter: str = ";"
    csv_decimal_separator: str = ","

    admin_bootstrap_username: str | None = None
    admin_bootstrap_password: str | None = None

    log_level: str = "INFO"

    # ----- v2: mail ---------------------------------------------------------------
    # None = default by environment (console in development, smtp in production); resolved in `_validate`.
    # The SMTP login is NOT a setting: it lives in the encrypted store under SECRETS_DIR (`setup-mail`).
    mail_backend: Literal["smtp", "console", "memory", "file"] | None = None
    smtp_host: str = "postout.lrz.de"
    smtp_port: int = 587
    smtp_security: Literal["starttls", "ssl"] = "starttls"
    mail_from: str = ""
    mail_file_dir: str = ""
    secrets_dir: str = "/secrets"
    mail_max_per_hour: int = 30

    # ----- v2: accounts -----------------------------------------------------------
    # Comma-separated; "tum.de" matches exactly, "*.tum.de" matches subdomains only.
    allowed_email_domains: str = "tum.de,mytum.de,*.tum.de"
    verification_ttl_hours: int = 24
    guest_approval_ttl_days: int = 7
    reset_ttl_minutes: int = 60
    password_min_length: int = 10
    stepup_window_seconds: int = 300
    # None = default by environment (true in production, false otherwise); resolved in `_validate`.
    balance_totp_required: bool | None = None

    # Argon2id cost. Defaults are the argon2-cffi (RFC 9106 low-memory) values and must not be
    # lowered in production; tests set cheap values in tests/conftest.py only.
    argon2_time_cost: int = DEFAULT_TIME_COST
    argon2_memory_cost_kib: int = DEFAULT_MEMORY_COST
    argon2_parallelism: int = DEFAULT_PARALLELISM

    # ----- derived values -------------------------------------------------
    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def currency_code(self) -> str:
        return self.currency.split(":", 1)[0].strip().upper()

    @property
    def currency_symbol(self) -> str:
        if ":" in self.currency:
            return self.currency.split(":", 1)[1].strip()
        return _CURRENCY_SYMBOLS.get(self.currency_code, self.currency_code)

    @property
    def tz(self) -> ZoneInfo:
        return ZoneInfo(self.local_timezone)

    @property
    def trusted_proxies(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        items = [p.strip() for p in self.trusted_proxy_ips.split(",") if p.strip()]
        return [ipaddress.ip_network(p, strict=False) for p in items]

    @property
    def allowed_email_domain_list(self) -> list[str]:
        return [d.strip().lower() for d in self.allowed_email_domains.split(",") if d.strip()]

    @property
    def cookie_secure(self) -> bool:
        """Secure cookies are mandatory in production; in development only over https."""
        return self.is_production or self.public_base_url.startswith("https://")

    # ----- validation -----------------------------------------------------
    @model_validator(mode="after")
    def _validate(self) -> "Settings":
        errors: list[str] = []
        base = self.public_base_url.strip()
        if not base.startswith(("http://", "https://")):
            errors.append("PUBLIC_BASE_URL must start with http:// or https://")
        self.public_base_url = base.rstrip("/")
        try:
            ZoneInfo(self.local_timezone)
        except (ZoneInfoNotFoundError, ValueError):
            errors.append(f"LOCAL_TIMEZONE is not a known time zone: {self.local_timezone!r}")
        try:
            self.trusted_proxies
        except ValueError:
            errors.append("TRUSTED_PROXY_IPS must be a comma-separated list of IPs or networks")
        if len(self.csv_delimiter) != 1:
            errors.append("CSV_DELIMITER must be a single character")
        if self.csv_decimal_separator not in (".", ","):
            errors.append("CSV_DECIMAL_SEPARATOR must be '.' or ','")
        if self.csv_delimiter == self.csv_decimal_separator:
            errors.append("CSV_DELIMITER and CSV_DECIMAL_SEPARATOR must differ")
        if not self.currency_code.isalpha() or len(self.currency_code) != 3:
            errors.append("CURRENCY must start with a 3-letter code, e.g. EUR or EUR:€")
        for name in ("session_lifetime_days", "admin_session_hours", "max_coffees_per_session_per_hour"):
            if getattr(self, name) < 1:
                errors.append(f"{name.upper()} must be at least 1")
        if self.undo_window_seconds < 0:
            errors.append("UNDO_WINDOW_SECONDS must not be negative")
        errors.extend(self._validate_v2())

        if not self.is_production and self.secret_key == DEV_SECRET_KEY:
            if self.public_base_url.startswith("https://") or not _is_local_host(self.public_base_url):
                errors.append(
                    "development mode with the published DEV_SECRET_KEY is only allowed for a local "
                    "http:// PUBLIC_BASE_URL (localhost); this looks like a public deployment, so set "
                    "ENVIRONMENT=production together with a random SECRET_KEY"
                )
        if self.is_production:
            if not self.public_base_url.startswith("https://"):
                errors.append("PUBLIC_BASE_URL must use https:// in production")
            if len(self.secret_key) < MIN_SECRET_KEY_LENGTH or is_placeholder(self.secret_key):
                errors.append(
                    f"SECRET_KEY must be set to a random value of at least {MIN_SECRET_KEY_LENGTH} characters in production"
                )
        if errors:
            raise ValueError("Invalid configuration: " + "; ".join(errors))
        return self


    def _validate_v2(self) -> list[str]:
        """Mail, account and Argon2 settings. Messages name the variable, never its value."""
        errors: list[str] = []
        # Resolved defaults, so callers always see concrete values.
        if self.mail_backend is None:
            self.mail_backend = "smtp" if self.is_production else "console"
        if self.balance_totp_required is None:
            self.balance_totp_required = self.is_production

        if not 1 <= self.smtp_port <= 65535:
            errors.append("SMTP_PORT must be between 1 and 65535")
        if self.mail_backend == "file" and not self.mail_file_dir.strip():
            errors.append("MAIL_FILE_DIR must be set when MAIL_BACKEND=file")
        if not self.secrets_dir.strip():
            errors.append("SECRETS_DIR must not be empty")
        if not self.allowed_email_domain_list:
            errors.append("ALLOWED_EMAIL_DOMAINS must list at least one domain")
        for d in self.allowed_email_domain_list:
            host = d[2:] if d.startswith("*.") else d
            if "." not in host or "@" in host or "*" in host or any(c.isspace() for c in host):
                errors.append("ALLOWED_EMAIL_DOMAINS entries must be domains such as tum.de or *.tum.de")
                break
        for name in ("mail_max_per_hour", "verification_ttl_hours", "guest_approval_ttl_days", "reset_ttl_minutes",
                     "stepup_window_seconds", "argon2_time_cost", "argon2_parallelism"):
            if getattr(self, name) < 1:
                errors.append(f"{name.upper()} must be at least 1")
        if self.argon2_memory_cost_kib < 8 * max(self.argon2_parallelism, 1):
            errors.append("ARGON2_MEMORY_COST_KIB must be at least 8 per lane (ARGON2_PARALLELISM)")
        if not 1 <= self.password_min_length <= 128:
            errors.append("PASSWORD_MIN_LENGTH must be between 1 and 128")

        if self.is_production:
            if self.mail_backend != "smtp":
                errors.append("MAIL_BACKEND must be smtp in production")
            if not self.smtp_host.strip():
                errors.append("SMTP_HOST must be set in production")
            if (self.smtp_security, self.smtp_port) in (("ssl", 587), ("starttls", 465)):
                errors.append("SMTP_SECURITY and SMTP_PORT do not match (ssl uses 465, starttls uses 587)")
            if not _valid_sender(self.mail_from):
                errors.append("MAIL_FROM must be set to a real sender address such as "
                              "'Coffee Ledger <coffee@example.org>' in production")
            if self.password_min_length < 8:
                errors.append("PASSWORD_MIN_LENGTH must be at least 8 in production")
        return errors


def _valid_sender(mail_from: str) -> bool:
    """A plain address (optionally with a display name) whose domain has a dot and is not localhost."""
    from email.utils import parseaddr

    from app.services.mail import normalize_address
    from app.services.errors import InvalidInput

    address = parseaddr((mail_from or "").strip())[1]
    try:
        address = normalize_address(address)
    except InvalidInput:
        return False
    domain = address.rsplit("@", 1)[1]
    return "." in domain and domain != "localhost" and not domain.endswith(".localhost")


@lru_cache
def get_settings() -> Settings:
    return Settings()
