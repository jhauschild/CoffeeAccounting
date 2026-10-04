"""Money parsing/formatting, local period boundaries (DST), and settings validation."""

from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.money import format_amount, format_money, parse_money
from app.services.errors import InvalidAmount
from app.timeutil import (
    local_day_bounds,
    local_month_bounds,
    local_week_bounds,
    parse_iso_datetime,
    to_local,
)

BERLIN = ZoneInfo("Europe/Berlin")


@pytest.mark.parametrize(
    "text,cents",
    [("12.50", 1250), ("12,50", 1250), ("12", 1200), ("0.5", 50), ("0,05", 5), (" 3.10 ", 310), ("-2,5", -250),
     ("+1.00", 100)],
)
def test_parse_money_accepts(text, cents):
    assert parse_money(text) == cents


@pytest.mark.parametrize("text", ["12.505", "abc", "", "  ", "1e3", "12.", ".5", "1.000,00", "1,000.00", "€5",
                                  "12..5", "--1", "1 000", "nan", "12345678901234567"])
def test_parse_money_rejects(text):
    with pytest.raises(InvalidAmount):
        parse_money(text)


def test_parse_money_sign_and_zero_rules():
    with pytest.raises(InvalidAmount):
        parse_money("-1.00", allow_negative=False)
    with pytest.raises(InvalidAmount):
        parse_money("0")
    assert parse_money("0,00", allow_zero=True) == 0


def test_format_money():
    assert format_money(150) == "€1.50"
    assert format_money(-305) == "−€3.05"
    assert format_money(0) == "€0.00"
    assert format_amount(-1250, decimal_separator=",") == "-12,50"
    assert format_amount(7) == "0.07"
    assert format_money(1999, symbol="CHF ", decimal_separator=",") == "CHF 19,99"


def _utc(*args):
    return datetime(*args, tzinfo=UTC)


def test_day_bounds_late_evening_is_next_local_day():
    # 22:30 UTC on 3 Oct 2026 is 00:30 on 4 Oct in Berlin (CEST, UTC+2).
    start, end = local_day_bounds(_utc(2026, 10, 3, 22, 30), BERLIN)
    assert (start, end) == (_utc(2026, 10, 3, 22), _utc(2026, 10, 4, 22))


def test_day_bounds_across_dst():
    start, end = local_day_bounds(_utc(2026, 3, 29, 12), BERLIN)  # spring forward: 23 h day
    assert (start, end) == (_utc(2026, 3, 28, 23), _utc(2026, 3, 29, 22))
    start, end = local_day_bounds(_utc(2026, 10, 25, 12), BERLIN)  # fall back: 25 h day
    assert (start, end) == (_utc(2026, 10, 24, 22), _utc(2026, 10, 25, 23))
    assert (end - start).total_seconds() == 25 * 3600


def test_week_is_monday_to_sunday_and_dst_safe():
    # Sunday 29 March 2026 (DST starts that night) belongs to the week starting Monday 23 March.
    start, end = local_week_bounds(_utc(2026, 3, 29, 20), BERLIN)
    assert (start, end) == (_utc(2026, 3, 22, 23), _utc(2026, 3, 29, 22))
    assert to_local(start, BERLIN).weekday() == 0
    # Monday 00:30 local is already the next week.
    start2, _ = local_week_bounds(_utc(2026, 3, 29, 22, 30), BERLIN)
    assert start2 == _utc(2026, 3, 29, 22)


def test_month_bounds():
    assert local_month_bounds(_utc(2026, 3, 15), BERLIN) == (_utc(2026, 2, 28, 23), _utc(2026, 3, 31, 22))
    assert local_month_bounds(_utc(2026, 12, 31, 23, 30), BERLIN) == (_utc(2026, 12, 31, 23), _utc(2027, 1, 31, 23))


def test_parse_iso_datetime_uses_local_zone_without_offset():
    assert parse_iso_datetime("2026-07-01T12:00", BERLIN) == _utc(2026, 7, 1, 10)
    assert parse_iso_datetime("2026-07-01T12:00+00:00", BERLIN) == _utc(2026, 7, 1, 12)


# ----- settings ------------------------------------------------------------------------------
GOOD_PROD = dict(
    _env_file=None,
    environment="production",
    public_base_url="https://coffee.example.org/",
    secret_key="Zq3v8K1mR7tXw2pL9sD4fG6hJ0kN5bVc",
    mail_from="Coffee Ledger <coffee@example.org>",
)


def test_production_settings_valid():
    s = Settings(**GOOD_PROD)
    assert s.public_base_url == "https://coffee.example.org"
    assert s.is_production and s.cookie_secure


@pytest.mark.parametrize(
    "override",
    [
        dict(public_base_url="http://coffee.example.org"),
        dict(secret_key=""),
        dict(secret_key="short"),
        dict(secret_key="change-me-change-me-change-me-change-me"),
        dict(secret_key="dev-insecure-secret-key-not-for-production-use"),
    ],
)
def test_production_settings_refuse_insecure_values(override):
    with pytest.raises(ValidationError):
        Settings(**{**GOOD_PROD, **override})


def test_development_allows_http_and_dev_defaults():
    s = Settings(_env_file=None, environment="development", public_base_url="http://localhost:8000",
                 secret_key="dev-insecure-secret-key-not-for-production-use")
    assert not s.cookie_secure


@pytest.mark.parametrize(
    "override",
    [dict(local_timezone="Mars/Olympus"), dict(csv_delimiter=";;"), dict(csv_decimal_separator=";"),
     dict(csv_delimiter=",", csv_decimal_separator=","), dict(trusted_proxy_ips="not-an-ip"), dict(currency="EURO")],
)
def test_settings_reject_invalid_values(override):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **override)


def test_settings_derived_values():
    s = Settings(_env_file=None, currency="GBP", trusted_proxy_ips="10.0.0.1, 172.16.0.0/12")
    assert (s.currency_code, s.currency_symbol) == ("GBP", "£")
    assert Settings(_env_file=None, currency="EUR:EUR ").currency_symbol == "EUR"
    assert [str(n) for n in s.trusted_proxies] == ["10.0.0.1/32", "172.16.0.0/12"]
