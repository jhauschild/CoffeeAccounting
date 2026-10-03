# Brief 01a — core-ledger (agent name: `core-a`)

Dir: `/home/claude/coffee-ledger` (branch `main`). You run alone. Read `docs/agents/00-protocol.md`, `docs/ARCHITECTURE.md`, and PROMPT §1, §4, §7 (audit table/triggers), §10–§12 (the parts relevant to you).

## Build (you own everything marked **A** in the architecture)

1. `app/config.py`: Settings from environment (all variables in PROMPT §11) with production validation (§9: https base URL, strong `SECRET_KEY`, `ACCESS_CODE` ≥ 8 chars, non-placeholder; dev may use http). `get_settings()` cached.
2. `app/db.py`: engine factory, SQLite pragmas on every connection (WAL, `foreign_keys=ON`, `busy_timeout`), `read_session()`, `write_session()` with `BEGIN IMMEDIATE` (see architecture transaction rules). Must work for a file-based DB used by multiple threads.
3. `app/models.py`: **all tables** listed in the architecture, with every constraint from PROMPT §4 as `CheckConstraint`/`Index` (unique partial indexes for `reversal_of_id` and `correction_of_id`; use `sqlite_where`/`postgresql_where`). Plus the `effective_users` view.
4. `migrations/` + `alembic.ini`: one initial migration creating everything, including the audit-log UPDATE/DELETE-rejecting triggers (SQLite; keep a PostgreSQL branch if cheap). `alembic upgrade head`, `downgrade base`, `alembic check` must work.
5. `app/money.py`, `app/timeutil.py` (local day/week/month bounds, weeks Mon–Sun, DST-safe), `app/services/errors.py`.
6. Services: `prices.py`, `ledger.py`, `users.py`, `chairs.py`, `audit.py`, `authz.py`, `checker.py` exactly per architecture signatures. Key behaviors: price snapshot at insert time; idempotent `record_coffee` on `nonce` (second call returns the existing event with `created=False`, also under concurrent threads); active-user check inside the same write transaction; undo copies the original's quantity/unit price/amount negated, ignores the current price, only the user's own latest event from the same session within `UNDO_WINDOW_SECONDS`, at most once, never a reversal; admin reverse/adjust/payment with scope checks; totals follow `effective_users`; merge never moves events, re-points earlier merges, revokes the duplicate's sessions (call a helper that B will implement later: for now issue a direct `UPDATE user_sessions SET revoked_at`), audits.
7. `app/cli.py`: argparse dispatcher with `check-ledger`, `set-price`, `purge-expired`; call `app.cli_admin.register(subparsers)` if the module exists (create `app/cli_admin.py` with an empty `register`).
8. `tests/conftest.py` + `tests/factories.py`: temp-file SQLite migrated by Alembic; fixtures `db`, factories `make_chair`, `make_user`, `make_admin(role, chairs)`, `set_price`, `add_events` helpers. Other agents depend on these; keep names stable and documented in a docstring.
9. Tests `tests/test_core_*.py` covering: every DB constraint rejected via raw SQL; price snapshot and price change behavior (future-dated, backdating rejected, none configured); idempotency incl. a threaded concurrent test on a file DB; double reversal race (threads) → one reversal; reversal-of-reversal rejected; undo window/expiry/ownership; deactivated user cannot record; totals incl. credit and merge (no event moved); scope checks; audit-log triggers; chair-change audit; money parse/format; timezone boundaries; `check-ledger` detects seeded corruption (tampered amount, orphan); migrations up/down/up and `alembic check`.

## Done when

`python -m pytest -q` is green; `alembic check` clean; `python -m app.cli check-ledger` runs on a fresh DB; everything committed on `main`; `docs/status/core-a.md` lists the final public function names if you deviated (avoid deviating).
