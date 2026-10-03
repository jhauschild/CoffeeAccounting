"""Time helpers. Internally all timestamps are timezone-aware UTC; display uses LOCAL_TIMEZONE.

Period bounds are computed from local calendar dates and converted to UTC, so they
stay correct across DST changes (a local day may be 23 or 25 hours long).
Weeks run Monday–Sunday. Bounds are half-open: `start <= t < end`.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo

from app.config import get_settings


def utcnow() -> datetime:
    return datetime.now(UTC)


def local_tz() -> ZoneInfo:
    return get_settings().tz


def ensure_utc(dt: datetime) -> datetime:
    """Return `dt` as aware UTC; naive values are assumed to already be UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def to_local(dt: datetime, tz: ZoneInfo | None = None) -> datetime:
    return ensure_utc(dt).astimezone(tz or local_tz())


def format_local(dt: datetime, fmt: str = "%Y-%m-%d %H:%M", tz: ZoneInfo | None = None) -> str:
    return to_local(dt, tz).strftime(fmt)


def local_date(now: datetime | None = None, tz: ZoneInfo | None = None) -> date:
    return to_local(now or utcnow(), tz).date()


def _local_midnight_utc(d: date, tz: ZoneInfo) -> datetime:
    return datetime.combine(d, time.min, tzinfo=tz).astimezone(UTC)


def local_day_bounds(now: datetime | None = None, tz: ZoneInfo | None = None) -> tuple[datetime, datetime]:
    tz = tz or local_tz()
    d = local_date(now, tz)
    return _local_midnight_utc(d, tz), _local_midnight_utc(d + timedelta(days=1), tz)


def local_week_bounds(now: datetime | None = None, tz: ZoneInfo | None = None) -> tuple[datetime, datetime]:
    tz = tz or local_tz()
    d = local_date(now, tz)
    monday = d - timedelta(days=d.weekday())
    return _local_midnight_utc(monday, tz), _local_midnight_utc(monday + timedelta(days=7), tz)


def local_month_bounds(now: datetime | None = None, tz: ZoneInfo | None = None) -> tuple[datetime, datetime]:
    tz = tz or local_tz()
    d = local_date(now, tz)
    first = d.replace(day=1)
    nxt = first.replace(year=first.year + 1, month=1) if first.month == 12 else first.replace(month=first.month + 1)
    return _local_midnight_utc(first, tz), _local_midnight_utc(nxt, tz)


def parse_iso_datetime(text: str, tz: ZoneInfo | None = None) -> datetime:
    """Parse ISO 8601; a value without offset is interpreted in LOCAL_TIMEZONE. Returns UTC."""
    dt = datetime.fromisoformat(text.strip())
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tz or local_tz())
    return dt.astimezone(UTC)
