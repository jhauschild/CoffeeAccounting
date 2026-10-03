"""Money helpers. All amounts are integer minor units (cents); floats are never used."""

from __future__ import annotations

import re

from app.config import get_settings
from app.services.errors import InvalidAmount

MAX_INPUT_LENGTH = 16
_MONEY_RE = re.compile(r"^([+-]?)(\d{1,9})(?:[.,](\d{1,2}))?$")


def parse_money(text: str, *, allow_negative: bool = True, allow_zero: bool = False) -> int:
    """Parse a decimal amount such as `12.50`, `12,50`, `12`, `-3.5` into cents.

    At most two decimals; no thousands separators, exponents or currency symbols.
    Raises `InvalidAmount` on anything else.
    """
    if not isinstance(text, str):
        raise InvalidAmount("amount must be text")
    s = text.strip()
    if not s or len(s) > MAX_INPUT_LENGTH:
        raise InvalidAmount("invalid amount")
    m = _MONEY_RE.match(s)
    if not m:
        raise InvalidAmount("invalid amount")
    sign, whole, frac = m.groups()
    cents = int(whole) * 100 + int((frac or "0").ljust(2, "0"))
    if sign == "-":
        cents = -cents
    if cents < 0 and not allow_negative:
        raise InvalidAmount("amount must not be negative")
    if cents == 0 and not allow_zero:
        raise InvalidAmount("amount must not be zero")
    return cents


def format_amount(cents: int, *, decimal_separator: str = ".") -> str:
    """Plain number with two decimals, e.g. `-3,50` (no symbol; used in CSV)."""
    cents = int(cents)
    sign = "-" if cents < 0 else ""
    whole, frac = divmod(abs(cents), 100)
    return f"{sign}{whole}{decimal_separator}{frac:02d}"


def format_money(cents: int, *, symbol: str | None = None, decimal_separator: str = ".") -> str:
    """Display form, e.g. `€1.50` or `−€3.00` (uses the configured currency symbol)."""
    if symbol is None:
        symbol = get_settings().currency_symbol
    cents = int(cents)
    body = format_amount(abs(cents), decimal_separator=decimal_separator)
    return f"−{symbol}{body}" if cents < 0 else f"{symbol}{body}"
