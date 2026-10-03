# core-a status

## Done
- config, db, money, timeutil, services/errors, models, migration 0001 (all tables, `effective_users` view, append-only triggers)
- services: audit, authz, prices, chairs, users, ledger, checker; `app/cli.py` (+ `app/cli_admin.py` stub)
- tests: conftest/factories + test_core_* (150 passing); `alembic check` clean; `check-ledger` OK on fresh DB

## Next
- nothing (brief complete)

## Notes for other agents (architecture signatures unchanged; additions only)
- All mutating services accept optional `ip=` (audit source IP) and `now=` (tests). They flush, never commit.
- errors: base `ServiceError` (`.code`), added `InvalidInput` (InvalidAmount subclasses it).
- db: `make_engine(url)`, `get_engine()`, `reset_engine()`, `write_session()`, `read_session()`.
- models: constants `DISPLAY_NAME_MAX`, `NOTE_MAX`, `COFFEE_KINDS`, ...; `AuditLog.meta` maps column `metadata`;
  `effective_users` is a Core `Table` for the view (id -> effective_id) — use it for all totals.
  `consumption_events.session_id` has no FK (session layer independent). Ledger/price/audit tables reject UPDATE/DELETE via triggers.
- config: `Settings.currency_code/currency_symbol/tz/trusted_proxies/cookie_secure/is_production`; `CURRENCY` = "EUR" or "EUR:€"; `LOG_LEVEL` added.
- money: `parse_money(s, allow_negative=True, allow_zero=False)`, `format_money(cents, symbol=None, decimal_separator=".")`, `format_amount(cents, decimal_separator)` (CSV).
- timeutil: `utcnow, ensure_utc, to_local, format_local, local_day/week/month_bounds(now, tz) -> (start, end) UTC half-open, parse_iso_datetime`.
- ledger extras: `is_reversed`, `reversed_ids(ids)`, `adjustment_default_amount(db, quantity)`; `recent_*(limit=None)` = all.
  Reversals keep the original's user_id and chair_id. Admin reversal of a reversal -> `Conflict`; user undo of it -> `UndoNotAllowed`.
  `record_coffee` enforces `MAX_COFFEES_PER_SESSION_PER_HOUR` (raises `RateLimited`) when `session_id` is given.
- users extras: `PublicProfile`, `find_same_name`, `clean_display_name`, `effective_user_id`, `member_ids_select`, `get_user`.
- chairs: `create_chair / rename_chair / set_chair_active(admin=None means CLI/system)`, `list_chairs(active_only)`, `get_chair`, `get_chair_by_short_name`.
- authz extras: `require_active`, `require_global`, `is_global`, `ensure_admin_can_access_chair`.
- audit: `log(...)` raises ValueError for metadata keys that look like secrets; `admin_actor(admin)`.
- checker: `check_ledger(db) -> CheckReport(problems=[Problem(code, message)], ...)`.
- cli_admin contract: `register(subparsers)`; each sub-parser `set_defaults(func=handler)`, `handler(args) -> int`.
- Test fixtures: see docstrings in tests/conftest.py and tests/factories.py (`reload_settings()` after `monkeypatch.setenv`).

## Notes/Blockers
- `users.merge_users` revokes sessions with a direct UPDATE; swap to `sessions.revoke_user_sessions` once core-b ships it.
- `add_price` rejects any `effective_from` earlier than now; the admin form should pass `None` for "now".
