# Task 4.4: /admin/groups, remittances UI, set balance, group-balance CSV

Status: done. Commit "admin: group balances, remittances, set balance (task 4.4)".

## What changed
- `app/web/admin_groups.py` (new, head admin only via `require_global_admin`, group admins get 403): `GET /admin/groups`, `POST /admin/groups/remittances` (preview), `POST /admin/groups/remittances/{id}/correct` (preview), `GET /admin/exports/group-balances.csv`. Included in `routes_admin.py` (one-line change, as in 4.2).
- `app/web/admin_users.py`: `POST /admin/users/{user_id}/balance` (preview of set balance; `global_user_access` + `require_global_admin`).
- `app/services/stepup.py`: three registered actions: `set_balance`, `remittance`, `remittance_correction` (idempotency key `stepup:<nonce>`). `ActionResult`/`ConfirmView` gained optional `show_balance`, `words` (balances as "Owes X"/"Credit X"), `amount_label`, `held_before_cents`, `held_after_cents`. New `NoChange` (code `no_change`, subclass of InvalidAmount) when the target balance equals the current one or a correction equals the entry.
- Set balance form: amount (non-negative) + "owes / has credit" select, so no minus sign is typed; confirm page shows balance now/afterwards in words and "The person owes X more/less".
- Remittance correction form: the admin enters what the entry SHOULD have been (`corrected_to`); the correction books the difference (0 reverses the entry). One correction per entry (the form disappears; the service refuses a second one: flash `conflict`).
- `app/services/exports.py`: `group_balances_csv` (head only, audited `export.group_balances_csv`, `csv_text` on every text cell, signed amounts, one row per group admin plus per-chair total rows, flags former/negative). Ledger CSV and dashboard "recent payments" now label bookkeeping payments `bookkeeping`.
- `app/services/group_report.py` (new): `remittance_rows` for the page. `app/services/stats.py`: `PaymentRow.collector_name` (linked member name or admin username) and `bookkeeping` kind label; user detail payments table has a "Collected by" column (admin-only; the user pages never use `stats`).
- Templates: `admin/groups.html` (new), `confirm.html`, `user_detail.html` (set balance card for head admin only, collector column, bookkeeping badge), `exports.html`, `base.html` (nav link for head), `_macros.html` (`words`, `held`). Strings in `strings_admin.py`.
- Held display uses the absolute amount plus the badge "More handed over than collected" (no minus sign); CSV keeps signed numbers.

## Tests
- `tests/test_admin_groups.py` (43): page, preview writes nothing, remittance books and held decreases, double submit books once, TOTP code needed when window closed, corrections (once, of a correction, same amount, to zero), negative flagged, former group admin listed while non-zero, group admin 403 on every new route, set balance up/down (bookkeeping kind, no collector, group balances untouched), no-change refused, CSV content/injection/audit/403, collector visible to admins only.
- `tests/test_admin_routes_authz.py` (new routes in POST_DATA, PREVIEW_POSTS, registry assertion, world fixture has a group admin and remittance), `tests/admin_support.py` (`BALANCE_PATH` covers the new paths).
- Full suite incl. e2e: 1485 passed, 0 failed, 0 errors (baseline 1406).

## For later tasks
- 4.5 dashboard tile "held by groups": `groups.list_group_balances` sum of `held_cents` (see `groups_page`).
- 4.3 role holders page can link to `/admin/groups`; demotion must keep role `chair`.
- Edits outside the ownership list (minimal): `routes_admin.py` include, `stats.py` (collector name, kind label).
- Nothing needed from the concurrent agent's files.
