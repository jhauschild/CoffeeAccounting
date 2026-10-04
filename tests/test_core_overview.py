"""overview.py: read-only open-site queries (task 1.5)."""

from __future__ import annotations

import dataclasses
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import event, select

from app.models import AuditLog, Price, User
from app.services import audit, groups, ledger, overview, users
from app.services.errors import NotFound
from tests import factories as f

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)
LONG_AGO = datetime(2025, 1, 1, tzinfo=UTC)


@pytest.fixture
def price50(db):
    return f.set_price(db, 50, effective_from=LONG_AGO)


def _coffees(db, user, n, at):
    return f.add_events(db, user, ["single"] * n, at=at)


# ----- balance wording ----------------------------------------------------------------------
def test_balance_label_and_words_never_use_a_minus_sign():
    assert overview.balance_label(350) == ("owes", 350)
    assert overview.balance_label(-200) == ("credit", 200)
    assert overview.balance_label(0) == ("even", 0)
    for cents in (350, -200, 0, 1, -1, 100_000_00, -100_000_00):
        words = overview.balance_words(cents)
        assert "-" not in words and "−" not in words
        state, amount = overview.balance_label(cents)
        assert amount >= 0 and state in overview.BALANCE_STATES
    assert "3.50" in overview.balance_words(350)
    assert overview.balance_words(-200).startswith("Credit")


def test_people_rows_carry_neutral_balance_wording(db, price50, chair, global_admin):
    owes = f.make_user(db, "Owes Person", chair)
    credit = f.make_user(db, "Credit Person", chair)
    f.make_user(db, "Even Person", chair)
    _coffees(db, owes, 3, NOW - timedelta(days=1))
    f.make_payment(db, credit, global_admin, 500, at=NOW - timedelta(days=1))
    page = overview.people(db, now=NOW)
    by_name = {r.display_name: r for r in page.rows}
    assert by_name["Owes Person"].balance_label == ("owes", 150)
    assert by_name["Credit Person"].balance_label == ("credit", 500)
    assert by_name["Even Person"].balance_label == ("even", 0)
    for r in page.rows:
        assert "-" not in r.balance_words and "−" not in r.balance_words


# ----- site totals --------------------------------------------------------------------------
def test_site_totals_numbers(db, price50, chair, other_chair, global_admin):
    alice = f.make_user(db, "Alice", chair)
    bob = f.make_user(db, "Bob", other_chair)
    f.add_events(db, alice, ["single", "double"], at=NOW - timedelta(days=2))  # 3 shots, 150
    f.add_events(db, bob, "single", at=NOW - timedelta(days=40))  # 1 shot, 50, September
    f.make_payment(db, alice, global_admin, 100, at=NOW - timedelta(days=1))
    f.make_payment(db, bob, global_admin, 150, at=NOW - timedelta(days=1))
    t = overview.site_totals(db, now=NOW)
    assert (t.total_shots, t.consumed_cents, t.paid_cents) == (4, 200, 250)
    assert (t.owed_total_cents, t.credit_total_cents) == (50, 100)
    assert t.current_price_cents == 50
    assert (t.month_shots, t.month_amount_cents) == (3, 150)
    assert len(t.trend) == 12 and t.trend[-1] == overview.MonthPoint("2026-10", 3, 150)
    assert t.trend[-2] == overview.MonthPoint("2026-09", 1, 50)
    assert t.trend[0].label == "2025-11"
    assert sum(p.shots for p in t.trend) == 4
    by_chair = {c.name: c for c in t.chairs}
    assert by_chair[chair.short_name].shots == 3 and by_chair[chair.short_name].owed_cents == 50
    assert by_chair[other_chair.short_name].credit_cents == 100
    assert sum(c.members for c in t.chairs) == 2


def test_site_totals_empty_and_no_price(db):
    t = overview.site_totals(db, now=NOW)
    assert t.total_shots == 0 and t.current_price_cents is None and t.chairs == ()
    assert len(t.trend) == 12 and all(p.shots == 0 and p.amount_cents == 0 for p in t.trend)


def test_month_boundary_summer_time(db, price50, chair):
    u = f.make_user(db, "Bound", chair)
    # Berlin is UTC+2 on 30 Sep / 1 Oct 2026: local midnight = 22:00 UTC.
    f.add_events(db, u, "single", at=datetime(2026, 9, 30, 21, 59, 59, tzinfo=UTC))  # still September
    f.add_events(db, u, ["single", "single"], at=datetime(2026, 9, 30, 22, 0, 0, tzinfo=UTC))  # October 00:00
    t = overview.site_totals(db, now=NOW)
    assert t.trend[-2] == overview.MonthPoint("2026-09", 1, 50)
    assert t.trend[-1] == overview.MonthPoint("2026-10", 2, 100)
    assert t.month_shots == 2
    assert overview.people(db, now=NOW).rows[0].shots_month == 2
    # one second earlier "now" is still September
    sep = overview.site_totals(db, now=datetime(2026, 9, 30, 21, 59, 59, tzinfo=UTC))
    assert sep.trend[-1] == overview.MonthPoint("2026-09", 1, 50)


def test_month_boundary_winter_time_and_year_change(db, price50, chair):
    u = f.make_user(db, "Newyear", chair)
    # Berlin is UTC+1: local midnight on 1 Jan 2026 = 23:00 UTC on 31 Dec 2025.
    f.add_events(db, u, "single", at=datetime(2025, 12, 31, 22, 59, 59, tzinfo=UTC))
    f.add_events(db, u, "single", at=datetime(2025, 12, 31, 23, 0, 0, tzinfo=UTC))
    now = datetime(2026, 1, 20, 9, 0, tzinfo=UTC)
    t = overview.site_totals(db, now=now)
    assert t.trend[-1] == overview.MonthPoint("2026-01", 1, 50)
    assert t.trend[-2] == overview.MonthPoint("2025-12", 1, 50)
    assert [p.label for p in t.trend][:2] == ["2025-02", "2025-03"]


def test_trend_has_twelve_consecutive_months_across_dst(db, price50):
    t = overview.site_totals(db, now=datetime(2026, 3, 31, 12, 0, tzinfo=UTC))
    assert [p.label for p in t.trend] == [
        "2025-04", "2025-05", "2025-06", "2025-07", "2025-08", "2025-09", "2025-10", "2025-11", "2025-12",
        "2026-01", "2026-02", "2026-03",
    ]


# ----- people -------------------------------------------------------------------------------
def test_duplicate_names_get_a_stable_suffix(db, price50, chair, other_chair):
    a1 = f.make_user(db, "Anna Schmidt", chair)
    a2 = f.make_user(db, "Anna Schmidt", other_chair)
    f.make_user(db, "Anna Schmitt", chair)
    names = {r.id: r.display_name for r in overview.people(db, now=NOW).rows}
    assert names[a1.id] == "Anna Schmidt" and names[a2.id] == "Anna Schmidt (2)"
    # the suffix does not depend on filters, pages or sorting
    filtered = overview.people(db, chair_id=other_chair.id, now=NOW)
    assert [r.display_name for r in filtered.rows] == ["Anna Schmidt (2)"]
    paged = overview.people(db, per_page=1, page=2, now=NOW)
    assert paged.rows[0].display_name == "Anna Schmidt (2)"
    assert {r.id: r.display_name for r in overview.people(db, sort="balance", now=NOW).rows} == names
    # a hidden (inactive, zero balance) namesake does not cause a suffix
    f.make_user(db, "Unique Name", chair)
    f.make_user(db, "Unique Name", chair, status="inactive")
    assert [r.display_name for r in overview.people(db, query="unique", now=NOW).rows] == ["Unique Name"]


def test_search_folds_umlauts(db, price50, chair):
    f.make_user(db, "Jürgen Müller", chair)
    f.make_user(db, "Other Person", chair)
    for q in ("muller", "mueller", "MÜLLER", "  jurgen  "):
        assert [r.display_name for r in overview.people(db, query=q, now=NOW).rows] == ["Jürgen Müller"], q
    assert overview.people(db, query="zzz", now=NOW).total == 0
    # LIKE wildcards are plain characters
    assert overview.people(db, query="%", now=NOW).total == 0
    assert overview.people(db, query="_", now=NOW).total == 0


def test_chair_filter_sorting_and_paging(db, price50, chair, other_chair, global_admin):
    a = f.make_user(db, "Aaa", chair)
    b = f.make_user(db, "Bbb", chair)
    c = f.make_user(db, "Ccc", other_chair)
    _coffees(db, a, 1, NOW - timedelta(days=1))
    _coffees(db, b, 5, NOW - timedelta(days=60))
    _coffees(db, c, 3, NOW - timedelta(days=2))
    f.make_payment(db, c, global_admin, 1000, at=NOW - timedelta(days=1))

    def order(**kw):
        return [r.display_name for r in overview.people(db, now=NOW, **kw).rows]

    assert order() == ["Aaa", "Bbb", "Ccc"]
    assert order(sort="balance") == ["Bbb", "Aaa", "Ccc"]  # most owed first, credit last
    assert order(sort="shots_month") == ["Ccc", "Aaa", "Bbb"]
    assert order(sort="shots_total") == ["Bbb", "Ccc", "Aaa"]
    assert order(sort="bogus") == ["Aaa", "Bbb", "Ccc"]
    assert order(chair_id=chair.id) == ["Aaa", "Bbb"]
    p = overview.people(db, per_page=2, page=2, now=NOW)
    assert (p.total, p.pages, p.page, [r.display_name for r in p.rows]) == (3, 2, 2, ["Ccc"])
    assert overview.people(db, per_page=2, page=99, now=NOW).page == 2
    assert overview.people(db, per_page=0, page=-3, now=NOW).page == 1
    row = overview.people(db, query="bbb", now=NOW).rows[0]
    assert (row.shots_month, row.shots_total, row.balance_cents, row.chair_name) == (0, 5, 250, chair.short_name)


def test_merged_users_are_never_listed_and_totals_follow_the_target(db, price50, chair, global_admin):
    keep = f.make_user(db, "Keeper", chair)
    dup = f.make_user(db, "Keeper Duplicate", chair)
    _coffees(db, keep, 1, NOW - timedelta(days=1))
    _coffees(db, dup, 2, NOW - timedelta(days=1))
    f.make_payment(db, dup, global_admin, 20, at=NOW - timedelta(days=1))
    users.merge_users(db, admin=global_admin, duplicate_id=dup.id, target_id=keep.id)
    db.commit()
    page = overview.people(db, now=NOW)
    assert [r.id for r in page.rows] == [keep.id]
    r = page.rows[0]
    assert (r.shots_total, r.shots_month, r.balance_cents) == (3, 3, 130)
    assert overview.people(db, query="duplicate", now=NOW).total == 0
    t = overview.site_totals(db, now=NOW)
    assert (t.total_shots, t.consumed_cents, t.paid_cents, t.owed_total_cents) == (3, 150, 20, 130)
    assert sum(c.members for c in t.chairs) == 1
    hist = overview.person_history(db, dup.id, now=NOW)  # a merged id resolves to the target
    assert hist.id == keep.id and len(hist.consumption) == 3 and len(hist.payments) == 1


def test_inactive_users_hidden_unless_balance_nonzero(db, price50, chair, global_admin):
    quiet = f.make_user(db, "Quiet Gone", chair)
    owing = f.make_user(db, "Owing Gone", chair)
    credit = f.make_user(db, "Credit Gone", chair)
    settled = f.make_user(db, "Settled Gone", chair)
    _coffees(db, quiet, 2, NOW - timedelta(days=3))
    f.make_payment(db, quiet, global_admin, 100, at=NOW - timedelta(days=2))  # exactly settled
    _coffees(db, owing, 1, NOW - timedelta(days=3))
    f.make_payment(db, credit, global_admin, 300, at=NOW - timedelta(days=3))
    _coffees(db, settled, 1, NOW - timedelta(days=3))
    f.make_payment(db, settled, global_admin, 50, at=NOW - timedelta(days=3))
    for u in (quiet, owing, credit, settled):
        users.set_user_status(db, admin=global_admin, user_id=u.id, active=False)
    db.commit()
    rows = {r.display_name: r for r in overview.people(db, now=NOW).rows}
    assert set(rows) == {"Owing Gone", "Credit Gone"}
    assert all(r.inactive for r in rows.values())
    assert rows["Owing Gone"].balance_cents == 50 and rows["Credit Gone"].balance_cents == -300
    with pytest.raises(NotFound):
        overview.person_history(db, quiet.id)
    with pytest.raises(NotFound):
        overview.person_history(db, settled.id)
    assert overview.person_history(db, owing.id, now=NOW).inactive is True
    t = overview.site_totals(db, now=NOW)
    assert sum(c.members for c in t.chairs) == 2
    assert t.total_shots == 4  # hidden users' shots still count towards the site total


def _count_statements(engine, fn) -> int:
    stmts: list[str] = []

    def on_exec(conn, cursor, statement, *args):
        stmts.append(statement)

    event.listen(engine, "before_cursor_execute", on_exec)
    try:
        fn()
    finally:
        event.remove(engine, "before_cursor_execute", on_exec)
    return len(stmts)


def test_people_query_count_does_not_grow_with_users(db, engine, price50, chair, other_chair, global_admin):
    def make(n):
        for i in range(n):
            u = f.make_user(db, f"Person {i % 4}", chair if i % 2 else other_chair)
            _coffees(db, u, 2, NOW - timedelta(days=i % 40))
            f.make_payment(db, u, global_admin, 10, at=NOW - timedelta(days=1))

    def people():
        return overview.people(db, query="person", sort="balance", per_page=50, now=NOW)

    def everything():
        people()
        overview.site_totals(db, now=NOW)
        overview.chairs_overview(db, now=NOW)
        overview.person_history(db, db.scalars(select(User.id)).first(), now=NOW)

    make(3)
    everything()  # warm up
    small = _count_statements(engine, people)
    small_all = _count_statements(engine, everything)
    make(40)
    assert len(people().rows) == 43
    big = _count_statements(engine, people)
    big_all = _count_statements(engine, everything)
    assert small == big and small <= 2
    assert small_all == big_all


# ----- person history -----------------------------------------------------------------------
def test_person_history_marks_reversals_and_lists_payments(db, price50, chair, global_admin):
    u = f.make_user(db, "Histo Ry", chair)
    e1, e2 = f.add_events(db, u, ["single", "double"], at=NOW - timedelta(days=3))
    ledger.admin_reverse_event(db, admin=global_admin, event_id=e2.id, now=NOW - timedelta(days=2))
    f.make_payment(db, u, global_admin, 70, at=NOW - timedelta(days=2))
    f.make_payment(db, u, global_admin, -20, at=NOW - timedelta(days=1))
    db.commit()
    h = overview.person_history(db, u.id, now=NOW)
    assert h.display_name == "Histo Ry" and h.chair_name == chair.short_name and not h.inactive
    assert [(c.shots, c.unit_price_cents, c.amount_cents, c.is_reversal, c.is_reversed) for c in h.consumption] == [
        (-2, 50, -100, True, False),
        (2, 50, 100, False, True),
        (1, 50, 50, False, False),
    ]
    assert [p.amount_cents for p in h.payments] == [-20, 70]  # newest first
    assert h.payments[0].date > h.payments[1].date
    assert (h.shots_total, h.consumed_cents, h.paid_cents, h.balance_cents) == (1, 50, 50, 0)
    assert h.balance_label == ("even", 0)
    with pytest.raises(NotFound):
        overview.person_history(db, uuid.uuid4())


# ----- chairs -------------------------------------------------------------------------------
def test_chairs_overview_group_money_and_admin_names(db, price50, chair, other_chair, global_admin):
    ga = f.make_admin(db, role="chair", chairs=[chair])
    ga.user.display_name = "Gina Group"
    former = f.make_admin(db, role="chair", chairs=[chair])
    former.user.display_name = "Former Fred"
    member = f.make_user(db, "Payer", chair)
    far = f.make_user(db, "Far Away", other_chair)
    _coffees(db, member, 4, NOW - timedelta(days=5))
    f.make_payment(db, member, ga, 120, at=NOW - timedelta(days=4))
    f.make_payment(db, member, former, 30, at=NOW - timedelta(days=4))
    _coffees(db, far, 2, NOW - timedelta(days=5))
    groups.record_remittance(db, head_admin=global_admin, group_admin_id=ga.id, amount_cents=100, idempotency_key="r1")
    former.active = False
    db.commit()
    rows = {c.chair_id: c for c in overview.chairs_overview(db, now=NOW)}
    a, b = rows[chair.id], rows[other_chair.id]
    assert a.group_admins == ("Gina Group",)  # current admins only
    assert (a.collected_cents, a.handed_over_cents, a.held_cents) == (150, 100, 50)
    assert a.members == 3  # Payer and the two group admin accounts
    assert a.owed_cents == 200 - 150 and a.credit_cents == 0
    assert b.group_admins == () and (b.collected_cents, b.handed_over_cents, b.held_cents) == (0, 0, 0)
    assert (b.members, b.owed_cents) == (1, 100)
    assert [c.name for c in rows.values()] == sorted(c.name for c in rows.values())


# ----- prices -------------------------------------------------------------------------------
def test_price_history_newest_first(db, global_admin):
    f.set_price(db, 40, effective_from=datetime(2025, 1, 1, tzinfo=UTC), admin=global_admin)
    f.set_price(db, 55, effective_from=datetime(2026, 6, 1, tzinfo=UTC), admin=global_admin)
    rows = overview.price_history(db)
    assert [(r.effective_from.year, r.price_per_shot_cents) for r in rows] == [(2026, 55), (2025, 40)]
    assert rows[0].effective_from.tzinfo is not None


# ----- sentinel: nothing sensitive ever leaves ----------------------------------------------
ALLOWED_FIELDS = {
    "ChairSummary": {"chair_id", "name", "full_name", "members", "shots", "consumed_cents", "paid_cents",
                     "owed_cents", "credit_cents"},
    "SiteTotals": {"total_shots", "consumed_cents", "paid_cents", "owed_total_cents", "credit_total_cents",
                   "current_price_cents", "month_shots", "month_amount_cents", "trend", "chairs"},
    "PersonRow": {"id", "display_name", "chair_id", "chair_name", "shots_month", "shots_total", "balance_cents",
                  "inactive"},
    "PeoplePage": {"rows", "total", "page", "pages", "per_page", "sort", "query", "chair_id"},
    "HistoryConsumption": {"date", "shots", "unit_price_cents", "amount_cents", "is_reversal", "is_reversed"},
    "HistoryPayment": {"date", "amount_cents"},
    "PersonHistory": {"id", "display_name", "chair_id", "chair_name", "inactive", "shots_month", "shots_total",
                      "consumed_cents", "paid_cents", "balance_cents", "consumption", "payments"},
    "ChairOverview": {"chair_id", "name", "full_name", "members", "group_admins", "owed_cents", "credit_cents",
                      "collected_cents", "handed_over_cents", "held_cents"},
    "PricePoint": {"effective_from", "price_per_shot_cents"},
}


def test_sentinel_nothing_sensitive_in_any_overview_value(db, chair, other_chair, global_admin):
    keys = ("email", "username", "hash", "paynote", "consnote", "audit", "ip", "adminname", "pricenote", "gaemail")
    S = {k: f"SENTINEL-{k}-{uuid.uuid4().hex[:10]}" for k in keys}
    db.add(Price(price_per_shot_cents=50, effective_from=LONG_AGO, created_by_admin_id=global_admin.id,
                 note=S["pricenote"]))
    db.commit()
    gadmin = f.make_admin(db, role="chair", chairs=[chair], username=S["adminname"])
    gadmin.user.email = f"{S['gaemail']}@tum.de"
    member = f.make_member(db, "Visible Member", chair, username=S["username"], email=f"{S['email']}@tum.de",
                           password_hash=S["hash"])
    guest = f.make_guest(db, member, "Visible Guest", username=S["username"] + "g", password_hash=S["hash"] + "g")
    other = f.make_member(db, "Other Member", other_chair)
    f.add_events(db, member, ["single", "double"], at=NOW - timedelta(days=2))
    f.add_events(db, guest, "single", at=NOW - timedelta(days=2))
    rev = f.add_events(db, other, "single", at=NOW - timedelta(days=2))[0]
    ledger.admin_reverse_event(db, admin=global_admin, event_id=rev.id, note=S["consnote"], ip=S["ip"],
                               now=NOW - timedelta(days=1))
    ledger.add_adjustment(db, admin=global_admin, user_id=member.id, quantity=1, note=S["consnote"], ip=S["ip"],
                          now=NOW - timedelta(days=1))
    f.make_payment(db, member, gadmin, 100, at=NOW - timedelta(days=1), note=S["paynote"])
    f.make_payment(db, guest, global_admin, 25, at=NOW - timedelta(days=1), note=S["paynote"])
    groups.record_remittance(db, head_admin=global_admin, group_admin_id=gadmin.id, amount_cents=40,
                             idempotency_key="sent-1", note=S["paynote"])
    audit.log(db, actor_type="admin", actor_id=global_admin.id, action="sentinel.test", target_type="user",
              target_id=member.id, metadata={"detail": S["audit"]}, ip=S["ip"])
    db.commit()
    # the sentinels really are stored
    assert db.query(AuditLog).filter(AuditLog.source_ip == S["ip"]).count() >= 1
    assert db.query(User).filter(User.email == f"{S['email']}@tum.de").count() == 1

    values = [
        overview.site_totals(db, now=NOW),
        overview.people(db, now=NOW),
        overview.people(db, query="visible", sort="balance", now=NOW),
        overview.person_history(db, member.id, now=NOW),
        overview.person_history(db, guest.id, now=NOW),
        overview.person_history(db, other.id, now=NOW),
        *overview.chairs_overview(db, now=NOW),
        *overview.price_history(db),
    ]
    assert len(overview.people(db, now=NOW).rows) >= 4

    def walk(obj):
        yield obj
        if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            assert {x.name for x in dataclasses.fields(obj)} == ALLOWED_FIELDS[type(obj).__name__], type(obj)
            for x in dataclasses.fields(obj):
                yield from walk(getattr(obj, x.name))
        elif isinstance(obj, (tuple, list)):
            for item in obj:
                yield from walk(item)

    seen = 0
    for v in values:
        blob = repr(v) + repr(dataclasses.asdict(v))
        for key, sentinel in S.items():
            assert sentinel not in blob, (key, type(v))
        for part in walk(v):
            blob = repr(part)
            for sentinel in S.values():
                assert sentinel not in blob
            seen += 1
    assert seen > 30
    row = overview.people(db, now=NOW).rows[0]
    assert not hasattr(row, "email") and not hasattr(row, "username")
