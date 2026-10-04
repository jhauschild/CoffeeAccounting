# Task 1.5: authz by own chair, read-only overview queries

Status: done. Commit "overview: read-only site queries, authz checks (task 1.5)".
Files: `app/services/overview.py` (new), `app/services/authz.py`, `tests/test_core_overview.py` (17), `tests/test_core_authz_v2.py` (9).

## authz
- `visible_chair_ids` for a group admin now reads the linked user's `chair_id` from the DB (not the cached `admin.user` relationship), so a chair change applies immediately; an unlinked role-`chair` admin fails closed (`set()`). Head admin: `None`. Inactive admin: `Forbidden`. `ensure_admin_can_access_user` unchanged (uses it).
- Own-account rule (ledger `_ensure_not_own_account`) tested for add_payment, add_adjustment, admin_reverse_event, set_balance, and through a merged duplicate (effective ids). Head admin may post to a group admin's account.

## overview.py (all public, frozen dataclasses; field sets pinned by the sentinel test)
- `site_totals(db, now=None) -> SiteTotals`: total_shots, consumed_cents, paid_cents, owed_total_cents, credit_total_cents, current_price_cents, month_shots, month_amount_cents, `trend` (12 `MonthPoint(label "YYYY-MM", shots, amount_cents)`, oldest first, last = current Berlin month), `chairs` (`ChairSummary`: chair_id, name (short), full_name, members, shots, consumed/paid/owed/credit cents). Chairs listed if active or having members/events. Shots/consumed/paid include hidden (inactive, zero-balance) users; members counts visible only.
- `people(db, *, query, chair_id, sort="name", page, per_page, now) -> PeoplePage` (rows, total, page, pages, per_page, sort, query, chair_id). `PersonRow`: id, display_name (" (2)" suffix by creation order among ALL visible accounts with the same normalized name, so stable under filter/sort/page), chair_id, chair_name (short), shots_month, shots_total, balance_cents (positive = owes), inactive; properties `balance_label`, `balance_words`. Sorts: name, balance (most owed first), shots_month, shots_total (desc); unknown sort falls back to name. per_page clamps 1..200, page clamps into range. 2 SQL statements regardless of user count.
- `person_history(db, user_id, now=None) -> PersonHistory`: id (the effective id; a merged id resolves to its target, routes should redirect), display_name (with suffix), chair, inactive, shots, balance, `consumption` (HistoryConsumption: date, shots, unit_price_cents, amount_cents, is_reversal, is_reversed), `payments` (HistoryPayment: date, signed amount_cents; negative = paid back). Newest first. Raises `NotFound` for unknown/hidden people.
- `chairs_overview(db, now=None) -> tuple[ChairOverview]`: chair_id, name, full_name, members, group_admins (current only, display names), owed_cents, credit_cents, collected_cents, handed_over_cents, held_cents (from `groups.chair_rollup`; collected by chair at event time).
- `price_history(db) -> tuple[PricePoint(effective_from, price_per_shot_cents)]` newest first (incl. future-dated).
- `balance_label(cents) -> ("owes"|"credit"|"even", abs_amount)`; `balance_words(cents)` returns English fallback text "Owes €3.50" / "Credit €2.00" / "Even" (no minus). strings.py was off limits, so these are NOT t() keys: task 5.1 should format `balance_label` through its own `t()` keys (e.g. "owes {amount}") and may drop `balance_words`.

## Notes for 5.1
- Everything is read-only, no auth: the route must apply the `view_site` gate itself.
- Money in views: use abs amounts from `balance_label`; payments/reversals carry real signs, show them as "paid back"/"reversal" in words if desired.
- Pass `now` only in tests.

## Known-broken
- None from this task.
