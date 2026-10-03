"""Dashboard numbers, user table queries, CSV exports and QR generation (service level)."""

from __future__ import annotations

import csv
import io
import re
from datetime import UTC, date, datetime, timedelta

import pytest

from app.db import read_session, write_session
from app.models import AuditLog
from app.services import exports, ledger, stats
from app.services.errors import Forbidden
from app.timeutil import utcnow
from tests import factories
from tests.admin_support import fast_hasher  # noqa: F401

# A fixed "now": Wednesday 2026-03-11 12:00 Berlin (CET, UTC+1) = 11:00 UTC.
NOW = datetime(2026, 3, 11, 11, 0, tzinfo=UTC)


def at(y, m, d, h=12, mi=0):
    """Berlin local time -> UTC (March 11 is CET; the DST switch is on 29 March)."""
    return datetime(y, m, d, h, mi, tzinfo=UTC) - timedelta(hours=1)


@pytest.fixture
def world(db, chair, other_chair, global_admin):
    """Hand-computed fixture. Price 50c from 2026-01-01, 60c from 2026-03-01.

    Alice (CHA): Mon 9 Mar single, Wed 11 Mar double (price 60) -> shots 3, 60+120=180, paid 100
    Bob (CHB):   Mar 1 00:30 local single (= Feb 28 23:30 UTC, still price 50), Feb 28 single (50c) -> shots 2, 100
    Cleo (CHA):  Wed 11 Mar 00:30 local double today; pays 50 on Sunday 8 Mar (previous week)
    """
    factories.set_price(db, 50, effective_from=datetime(2026, 1, 1, tzinfo=UTC))
    factories.set_price(db, 60, effective_from=datetime(2026, 3, 1, tzinfo=UTC))
    alice = factories.make_user(db, "Alice Müller", chair)
    bob = factories.make_user(db, "Bob", other_chair)
    cleo = factories.make_user(db, "Cleo", chair)
    factories.add_events(db, alice, "single", at=at(2026, 3, 9, 8))
    factories.add_events(db, alice, "double", at=at(2026, 3, 11, 9))
    factories.make_payment(db, alice, global_admin, 100, at=at(2026, 3, 10, 10))
    factories.add_events(db, bob, "single", at=at(2026, 3, 1, 0, 30))
    factories.add_events(db, bob, "single", at=at(2026, 2, 28, 12))
    factories.add_events(db, cleo, "double", at=at(2026, 3, 11, 0, 30))
    factories.make_payment(db, cleo, global_admin, 50, at=at(2026, 3, 8, 12))
    return alice, bob, cleo


def test_dashboard_numbers_match_hand_computation(db, world, global_admin, chair, other_chair):
    with read_session() as r:
        d = stats.dashboard(r, global_admin, now=NOW)
        r.expunge_all()
    # consumption: alice 60 + 120, bob 50 + 50, cleo 120 = 400 cents over 1+2+1+1+2 = 7 shots
    assert (d.totals.consumed_shots, d.totals.consumed_amount_cents) == (7, 400)
    assert d.totals.paid_amount_cents == 150 and d.totals.balance_cents == 250
    # today (Wed 11): alice double 120 + cleo double 120
    assert d.today == stats.PeriodTotals(4, 240, 0)
    # week Mon 9 - Sun 15: alice single 60 + double 120 + cleo double 120; payment alice 100
    assert d.week == stats.PeriodTotals(5, 300, 100)
    # month March (local): everything except bob's Feb 28 single (50c); payments 100 + 50
    assert d.month == stats.PeriodTotals(6, 350, 150)
    by = {c.short_name: c for c in d.per_chair}
    assert (by["CHA"].shots, by["CHA"].consumed_cents, by["CHA"].paid_cents) == (5, 300, 150)
    assert by["CHA"].balance_cents == 150
    assert (by["CHB"].shots, by["CHB"].consumed_cents, by["CHB"].paid_cents) == (2, 100, 0)
    assert d.current_price.price_per_shot_cents == 60 and len(d.prices) == 2
    assert len(d.recent_consumption) == 5 and len(d.recent_payments) == 2
    assert d.recent_consumption[0].user_name == "Alice Müller"  # newest first (Wed 09:00 local)


def test_dashboard_uses_local_day_boundary(db, global_admin, chair):
    factories.set_price(db, 100, effective_from=datetime(2026, 1, 1, tzinfo=UTC))
    u = factories.make_user(db, "Night Owl", chair)
    factories.add_events(db, u, "single", at=datetime(2026, 3, 10, 23, 30, tzinfo=UTC))  # 00:30 local on the 11th
    factories.add_events(db, u, "single", at=datetime(2026, 3, 10, 22, 59, tzinfo=UTC))  # 23:59 local on the 10th
    with read_session() as r:
        d = stats.dashboard(r, global_admin, now=NOW)
    assert d.today.shots == 1 and d.week.shots == 2


def test_dashboard_scope_for_chair_admin(db, world, chair_admin):
    with read_session() as r:
        d = stats.dashboard(r, chair_admin, now=NOW)
    assert d.totals.consumed_amount_cents == 300 and d.totals.paid_amount_cents == 150
    assert [c.short_name for c in d.per_chair] == ["CHA"]
    assert {e.user_name for e in d.recent_consumption} == {"Alice Müller", "Cleo"}


def test_totals_follow_merged_profiles_and_scope(db, world, global_admin, chair, other_chair):
    alice, bob, cleo = world
    with write_session() as w:
        from app.services import users
        users.merge_users(w, admin=global_admin, duplicate_id=bob.id, target_id=alice.id)
    with read_session() as r:
        page = stats.list_users(r, global_admin, sort="name")
        row = {x.display_name: x for x in page.rows}
        assert "Bob" not in row  # merged profiles are not listed
        assert row["Alice Müller"].shots == 5 and row["Alice Müller"].consumed_cents == 280
        assert row["Alice Müller"].paid_cents == 100 and row["Alice Müller"].balance_cents == 180


def test_user_table_search_filter_sort_pagination(db, world, global_admin, chair, other_chair):
    with read_session() as r:
        names = lambda **kw: [x.display_name for x in stats.list_users(r, global_admin, **kw).rows]  # noqa: E731
        assert names(q="muller") == ["Alice Müller"] and names(q="mueller") == ["Alice Müller"]
        assert set(names(chair_id=chair.id)) == {"Alice Müller", "Cleo"}
        assert names(sort="name") == ["Alice Müller", "Bob", "Cleo"]
        assert names(sort="name", direction="desc") == ["Cleo", "Bob", "Alice Müller"]
        # balances: alice 80, bob 100, cleo 120-50=70
        assert names(sort="balance") == ["Bob", "Alice Müller", "Cleo"]
        assert names(sort="consumption") == ["Alice Müller", "Cleo", "Bob"]
        page = stats.list_users(r, global_admin, sort="name", page_size=2, page=2)
        assert [x.display_name for x in page.rows] == ["Cleo"] and page.total == 3 and page.pages == 2
        assert stats.list_users(r, global_admin, sort="name", page_size=2, page=99).page == 2  # clamped


def test_user_table_activity_sort_puts_unknown_last(db, global_admin, chair):
    a = factories.make_user(db, "A", chair)
    b = factories.make_user(db, "B", chair)
    c = factories.make_user(db, "C", chair)
    a.last_activity_at, b.last_activity_at, c.last_activity_at = at(2026, 3, 1), None, at(2026, 3, 5)
    db.commit()
    with read_session() as r:
        for direction, expected in (("desc", ["C", "A", "B"]), ("asc", ["A", "C", "B"])):
            page = stats.list_users(r, global_admin, sort="activity", direction=direction)
            assert [x.display_name for x in page.rows] == expected


def test_chair_admin_sees_only_own_chair(db, world, chair_admin, other_chair):
    with read_session() as r:
        assert {x.display_name for x in stats.list_users(r, chair_admin).rows} == {"Alice Müller", "Cleo"}
        with pytest.raises(Forbidden):
            stats.list_users(r, chair_admin, chair_id=other_chair.id)


# ----- CSV ------------------------------------------------------------------------------------
def parse(data: bytes, delimiter=";"):
    assert data.startswith(b"\xef\xbb\xbf")
    return list(csv.reader(io.StringIO(data.decode("utf-8-sig")), delimiter=delimiter))


def test_users_csv_format_filters_and_audit(db, world, global_admin, chair):
    with write_session() as w:
        data = exports.users_csv(w, global_admin, chair_id=chair.id, sort="name")
    rows = parse(data)
    assert rows[0] == ["Name", "Chair", "Shots", "Consumed", "Paid", "Balance", "Last activity", "Status"]
    assert [r[0] for r in rows[1:]] == ["Alice Müller", "Cleo"]
    alice = rows[1]
    assert alice[2:6] == ["3", "1,80", "1,00", "0,80"]  # decimal comma by default
    with read_session() as r:
        entry = r.query(AuditLog).filter_by(action="export.users_csv").one()
        assert entry.meta["rows"] == 2 and entry.actor_type == "admin"


def test_csv_decimal_separator_and_delimiter_configurable(db, world, global_admin, monkeypatch):
    from tests.conftest import reload_settings
    monkeypatch.setenv("CSV_DELIMITER", ",")
    monkeypatch.setenv("CSV_DECIMAL_SEPARATOR", ".")
    reload_settings()
    with write_session() as w:
        data = exports.users_csv(w, global_admin, sort="name")
    rows = parse(data, ",")
    assert rows[1][2:6] == ["3", "1.80", "1.00", "0.80"]


def test_csv_neutralizes_formula_injection_and_quotes(db, global_admin, chair):
    factories.set_price(db, 50)
    evil = ['=cmd|" /C calc"!A0', "+1+1", "-2+3", "@SUM(A1)", "\tTab", "\rCR", 'Semi;colon "quoted"', " =lead"]
    for name in evil:
        factories.make_user(db, name, chair)
    with write_session() as w:
        data = exports.users_csv(w, global_admin, sort="name")
    names = {r[0] for r in parse(data)[1:]}
    assert "'=cmd|\" /C calc\"!A0" in names and "'+1+1" in names and "'-2+3" in names and "'@SUM(A1)" in names
    assert "'\tTab" in names and "'\rCR" in names and "'" + " =lead" in names
    assert 'Semi;colon "quoted"' in names  # untouched but correctly quoted/round-trips
    assert not any(n.startswith(("=", "+", "-", "@", "\t", "\r")) for n in names)
    assert csv.reader  # round trip above proves quoting


def test_ledger_csv_range_chair_scope_and_audit(db, world, global_admin, chair_admin, chair, other_chair):
    with write_session() as w:
        data = exports.ledger_csv(w, global_admin, date_from=date(2026, 3, 9), date_to=date(2026, 3, 10))
    rows = parse(data)
    assert rows[0][:3] == ["Date", "Type", "Name"]
    types = [(r[1], r[2]) for r in rows[1:]]
    assert types == [("single", "Alice Müller"), ("payment", "Alice Müller")]  # Mar 9 08:00, Mar 10 10:00
    assert rows[1][4:7] == ["1", "0,60", "0,60"]  # quantity, unit price, amount
    with write_session() as w:
        everything = parse(exports.ledger_csv(w, global_admin, chair_id=other_chair.id))
    assert {r[2] for r in everything[1:]} == {"Bob"} and len(everything) == 3
    with write_session() as w:
        scoped = parse(exports.ledger_csv(w, chair_admin))
        assert {r[2] for r in scoped[1:]} == {"Alice Müller", "Cleo"}
        with pytest.raises(Forbidden):
            exports.ledger_csv(w, chair_admin, chair_id=other_chair.id)
    with read_session() as r:
        assert r.query(AuditLog).filter_by(action="export.ledger_csv").count() == 3


# ----- QR -------------------------------------------------------------------------------------
def test_qr_urls_and_svg_have_no_active_content(monkeypatch):
    from tests.conftest import reload_settings
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://testserver/")
    reload_settings()
    urls = exports.qr_urls()
    assert urls == {"single": "http://testserver/coffee/single", "double": "http://testserver/coffee/double"}
    svg = exports.qr_svg(urls["single"], "SINGLE & <more>")
    assert svg.startswith("<svg") and "SINGLE &amp; &lt;more&gt;" in svg
    assert "<script" not in svg and "style=" not in svg and "onload" not in svg.lower()
    assert re.search(r'<path d="M', svg)


def test_qr_files(tmp_path):
    names = exports.write_qr_files(tmp_path / "out")
    assert sorted(names) == ["coffee-double.svg", "coffee-single.svg"]
    assert "SINGLE" in (tmp_path / "out" / "coffee-single.svg").read_text()
