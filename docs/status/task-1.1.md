# Task 1.1: squashed v2 schema, models

Status: done. Commit "schema: v2 squashed migration and models (task 1.1)".

## What changed
- `migrations/versions/0001_initial_schema.py`: v2 schema merged in (no 0002). New tables `pending_registrations`, `password_reset_tokens`, `group_remittances`, `used_nonces`; `admin_chairs` dropped; `admin_sessions.stepup_until` replaces `totp_verified`; `pending_actions.kind` accepts `view_site`; `payment_events` gains `kind`, `idempotency_key`, `collector_admin_id`. View `effective_users` and the append-only triggers are unchanged, plus triggers for `group_remittances` (corrections are new rows, so it is append-only like `payment_events`).
- `app/models.py` mirrors it (`PendingRegistration`, `PasswordResetToken`, `GroupRemittance`, `UsedNonce`; `AdminChair` removed). `AdminUser.user` relationship and a read-only `AdminUser.chairs` property (= the linked user's chair) replace the old relationship.
- `tests/test_core_schema_v2.py` (new, 20 tests) and `tests/test_core_db_migrations.py` (expected tables) updated.

## Decisions
- **Users compatibility.** All new `users` columns are nullable at DB level. `account_kind` is NULL only for legacy v1 rows (no login). Every CHECK is conditional on `account_kind IS NOT NULL`: when set, it must be member|guest; a member needs email and no sponsor; a guest needs a sponsor and no email; username, username_normalized and a non-empty password_hash are required; sponsor is not the user itself. `username_normalized` is unique (NULLs repeat); `uq_users_email` is a partial unique index (`WHERE email IS NOT NULL`, sqlite and postgresql). Later task (after 2.5, when profile creation is gone) may tighten `account_kind` to NOT NULL in this same migration.
- **No CHECK "kind=cash requires collector_admin_id".** v1 `ledger.add_payment` does not set it; enforce in the service layer in task 1.3 (set `collector_admin_id` on every cash payment, copy it on corrections) and in `check-ledger` (task 1.4). Only `kind IN ('cash','bookkeeping')` is a CHECK.
- `pending_registrations` columns (contract does not list them): kind, username, username_normalized, display_name, chair_id, email (member), sponsor_id (guest), password_hash, token_hash (unique), created_at, expires_at, consumed_at; same member/guest shape CHECKs as `users`.
- `group_remittances` columns: group_admin_id, chair_id, amount_cents (signed, nonzero), recorded_by_admin_id, correction_of_id (partial unique), idempotency_key (unique), note, created_at.
- `used_nonces`: integer id, nonce (unique), consumed_at.

## Minimal compatibility edits outside models
- `app/services/authz.py`: `visible_chair_ids` returns `{c.id for c in admin.chairs}` (the group admin's own chair; task 1.5 owns the rest).
- `app/services/admin_auth.py`: `AdminChair` imports removed; `create_admin(role="chair")` and `set_admin_chairs` raise `InvalidInput` until group admins are built from a user account (tasks 4.x). `AdminSession(totp_verified=...)` is NOT shimmed: it now raises TypeError.
- `tests/factories.py`: new `make_member`, `make_guest`; `make_admin(role="chair")` creates a linked member in `chairs[0]` (or a new chair); `AdminChair` rows no longer created.

## Hand-off: known-broken v1 tests (full suite, e2e file excluded: 496 passed, 57 failed, 238 errors)
Root causes: `AdminSession(totp_verified=...)` in `admin_auth._new_session` (279 hits, every admin login), `create_admin(role="chair")`/`set-admin-chairs` (5), and `make_admin(role="chair")` adding an extra "Test Member" user (1). Owner: task 4.1 rewrites admin login/session (stepup_until) and fixes most of these; chair-admin tests are rewritten with group admins in 4.x.
| File | Failed | Errors |
| --- | --- | --- |
| test_audit_security_authz_csrf.py | 4 | 159 |
| test_admin_routes_authz.py | 0 | 36 |
| test_admin_actions.py | 0 | 32 |
| test_audit_security_injection_config.py | 16 | 0 |
| test_admin_auth.py | 14 | 0 |
| test_admin_views.py | 0 | 11 |
| test_admin_web_login.py | 10 | 0 |
| test_audit_security_admin_auth.py | 3 | 0 |
| test_audit_security_gate_sessions.py | 3 | 0 |
| test_audit_ledger_reversal.py | 2 | 0 |
| test_admin_cli.py | 2 | 0 |
| test_admin_audit_coverage.py | 1 | 0 |
| test_admin_stats_exports.py | 1 | 0 |
| test_audit_ledger_prices.py | 1 | 0 |

Everything else passes (775 baseline + 21 new/changed schema tests; `tests/test_e2e_scan.py` not run).

## Acceptance output
`alembic upgrade head`, `downgrade base`, `upgrade head` all exit 0; `alembic check`: "No new upgrade operations detected."; view `effective_users` and the audit/consumption/payment/prices/group_remittances triggers present after upgrade.
