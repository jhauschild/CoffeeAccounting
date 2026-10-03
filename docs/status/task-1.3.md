# Task 1.3: ledger collector, bookkeeping, set_balance, month shots

Status: done. Commit "ledger: collector, bookkeeping, set_balance, month shots (task 1.3)".
Files: `app/services/ledger.py`, `tests/test_core_ledger_v2.py` (30 tests). Factories untouched.

## Behaviour
- `add_payment(..., kind="cash", idempotency_key=None)`: cash sets `collector_admin_id` = recording admin. A correction copies `kind` and `collector_admin_id` from the original (the `kind` argument is ignored), whoever records it. `bookkeeping` has NULL collector and needs a head admin (`Forbidden` otherwise; also when correcting a bookkeeping payment).
- Idempotency: existing key returns the existing event without inserting or auditing. Key reused for another user (effective) or amount raises `Conflict`. Key must be 1..80 chars (`InvalidInput`). Lookup happens after the scope/own-account/amount checks and before the correction checks, so a retried correction returns the first result.
- `set_balance(db, *, admin, user_id, target_balance_cents, idempotency_key, note=None, ip=None, now=None)`: head only (`require_global`). Books `bookkeeping` payment of `current_balance - target` (balance = consumed - paid, merged profiles included). Zero difference with a new key raises `InvalidAmount` (no zero rows); a repeat of a used key returns the original event. Key is required.
- `get_month_shots(db, user_id, now=None)`: net SUM(quantity) (coffees, adjustments, reversals) of the effective user (merged profiles included) within the local calendar month (`local_month_bounds`, half-open, DST-safe). A reversal counts in the month it is created, so reversing last month's coffee gives a negative contribution this month.
- Own-balance rule: role `chair` admin with `user_id` cannot `add_payment`, `add_adjustment`, `admin_reverse_event` or `set_balance` for the effective user of their own linked account (`Forbidden`). Head admins may.
- Audit metadata of `payment.recorded`/`payment.corrected` gains `kind`. Totals unchanged (count both kinds).

## Tests
Task files + existing ledger files: 109 passed. Full suite (e2e excluded): 526 passed, 57 failed, 238 errors = baseline (496 passed) + 30 new, no new failures.

## Notes for later tasks
- Check-ledger (1.4) should flag cash payments with NULL collector (legacy v1 rows copy NULL on correction).
- Group balance/remittances (1.4) should use `collector_admin_id` + `payment_events.chair_id`; bookkeeping rows are excluded by `kind='cash'`.
