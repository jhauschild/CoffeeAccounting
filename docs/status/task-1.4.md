# Task 1.4: group balances, remittances, check-ledger additions

Status: done. Commit "groups: group balances, remittances, check-ledger additions (task 1.4)".
Files: `app/services/groups.py` (new), `app/services/checker.py`, `app/cli.py` (prints notes), `tests/test_core_groups.py` (22), `tests/test_core_groups_checker.py` (21). `ledger.py` untouched.

## groups.py
- `collected(db, admin_id)`, `remitted(db, admin_id)` (extra helper), `held(db, admin_id)`: plain signed SUMs; collected counts only `kind='cash'` rows with that collector.
- `chair_rollup(db) -> list[ChairRollupRow]` (chair_id, chair_short_name, chair_full_name, collected_cents, remitted_cents, held_cents, negative); only collectors/targets with role `chair`; chairs without group money omitted; sorted by short name.
- `list_group_balances(db) -> list[GroupBalanceRow]` (admin_id, username, display_name, chair_id, chair_short_name, collected_cents, remitted_cents, held_cents, is_current, negative). Lists every active role-`chair` admin, and inactive (former) ones only while held != 0. Sorted by chair short name, username.
- `record_remittance(db, *, head_admin, group_admin_id, amount_cents, idempotency_key, correction_of_id=None, note=None, ip=None, now=None) -> GroupRemittance`. Errors: `Forbidden` (not an active head admin), `InvalidAmount` (0, non-int, bool, |x| > 1,000,000.00), `InvalidInput` (key not 1..80 chars, target not role `chair`), `NotFound` (unknown admin or correction target), `Conflict` (key reused with other admin/amount/correction target; correction of another admin's entry, of a correction, or a second correction). Idempotent retry returns the existing row without a new audit entry (idempotency lookup happens before the correction checks).
- Audit actions: `remittance.recorded` / `remittance.corrected`, target_type `admin`, target_id = group admin, metadata remittance_id, amount_cents, chair_id, correction_of_id.

## Decision to note
- A correction stores the **chair of the entry it corrects**, not the linked user's current chair, so both rows net out in the same chair roll-up even if the former admin's person changed chair meanwhile. For an ordinary (non-correction) entry the chair is the linked user's chair at event time, as specified.

## checker.py
- `CheckReport` gains `remittances` and `notes` (defaults, so old constructors still work). `ok` still depends only on `problems`. CLI prints `NOTE ...` lines after the OK/FAILED line (exit code unaffected).
- New error codes: `payment_kind`, `cash_without_collector`, `bookkeeping_with_collector`, `orphan_collector`, `correction_collector`, `correction_kind`, `remittance_admin`, `remittance_admin_role`, `remittance_recorder`, `zero_remittance`, `remittance_correction_orphan`, `remittance_correction_self`, `remittance_correction_admin`, `remittance_correction_of_correction`, `double_remittance_correction`, `group_balance_mismatch` (rows recomputed in Python vs `groups.collected/held/chair_rollup`, per admin and per chair).
- Notes: group admin or chair with negative held; former group admin still holding money.

## Later tasks
- 4.4 can use `list_group_balances` and `chair_rollup` directly for /admin/groups, the dashboard "held by groups" tile and CSV. Callers must catch the typed errors above and pass a step-up-derived idempotency key.
- Legacy v1 cash payments with NULL collector now fail check-ledger (as intended).

## Tests
New files: 43 passed. Full suite (e2e excluded): 611 passed, 57 failed, 238 errors = baseline 568 + 43; failed/errors unchanged.
