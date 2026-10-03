"""Application settings, read from environment variables (and an optional `.env`).

All variables from PROMPT §11 are supported. In production (`ENVIRONMENT=production`)
startup refuses insecure configuration (PROMPT §9): a non-https `PUBLIC_BASE_URL`,
a missing/short/placeholder `SECRET_KEY`, or a missing/short/placeholder `ACCESS_CODE`. Development mode refuses the published
`DEV_SECRET_KEY`/`DEV_ACCESS_CODE` unless `PUBLIC_BASE_URL` is a local http:// address.

`get_settings()` is cached; tests that change the environment call
`get_settings.cache_clear()`.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit
from functools import lru_cache
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEV_SECRET_KEY = "dev-insecure-secret-key-not-for-production-use"
DEV_ACCESS_CODE = "dev-access-code"

MIN_SECRET_KEY_LENGTH = 32
MIN_ACCESS_CODE_LENGTH = 8

# Exact values (case-insensitive) that must never be used in production.
_PLACEHOLDER_VALUES = {
    DEV_SECRET_KEY,
    DEV_ACCESS_CODE,
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
    access_code: str = DEV_ACCESS_CODE

    session_lifetime_days: int = 180
    admin_session_hours: int = 12
    admin_totp_required: bool = True

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

        if not self.is_production and (self.secret_key == DEV_SECRET_KEY or self.access_code == DEV_ACCESS_CODE):
            if self.public_base_url.startswith("https://") or not _is_local_host(self.public_base_url):
                errors.append(
                    "development mode with the published DEV_SECRET_KEY / DEV_ACCESS_CODE is only allowed for a local "
                    "http:// PUBLIC_BASE_URL (localhost); this looks like a public deployment, so set "
                    "ENVIRONMENT=production together with a random SECRET_KEY and ACCESS_CODE"
                )
        if self.is_production:
            if not self.public_base_url.startswith("https://"):
                errors.append("PUBLIC_BASE_URL must use https:// in production")
            if len(self.secret_key) < MIN_SECRET_KEY_LENGTH or is_placeholder(self.secret_key):
                errors.append(
                    f"SECRET_KEY must be set to a random value of at least {MIN_SECRET_KEY_LENGTH} characters in production"
                )
            if len(self.access_code) < MIN_ACCESS_CODE_LENGTH or is_placeholder(self.access_code):
                errors.append(
                    f"ACCESS_CODE must be set to a non-placeholder value of at least {MIN_ACCESS_CODE_LENGTH} characters in production"
                )
        if errors:
            raise ValueError("Invalid configuration: " + "; ".join(errors))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
