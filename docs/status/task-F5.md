# Task F5: fixes for the M5 review (docs/status/review-M5.md)

Regression tests: `tests/test_final_f5.py` (37 tests; 26 fail on the v2 tree, the rest are controls and the L-8
service-level tests, which were verified by mutation), plus `tests/test_admin_routes_authz.py` (L-7) and
`tests/test_admin_mail_qr.py` (L-9). Full suite: 1891 passed, 4 skipped, 0 failed (baseline 1844 passed).

## What changed
- M-1 `ledger.add_payment`: a NEGATIVE cash payment that is not a correction, recorded by a non-head admin, may not
  exceed the target's credit (`max(0, -balance)` of the effective user): new `errors.PaybackExceedsCredit`
  (subclass of `InvalidAmount`, code `payback_exceeds_credit`, string `admin.err.payback_exceeds_credit`). Head admins
  may exceed it; corrections are exempt (still bounded by the F4 rules); an idempotent replay returns the old entry.
  `groups.over_credit_paybacks(db)` lists every negative cash entry (not corrections) that exceeded the credit at its
  own time (payments up to and including its timestamp, itself excluded, minus consumption up to that time, over the
  effective user as merged today). Shown as a "Paid back above credit" card on /admin/groups and as a `check-ledger`
  note (never a failure).
- M-2 open site: `HistoryPayment.is_bookkeeping`; kind `adjustment` -> "Balance adjustment" with its own sentence
  (`site.person.adjustment_hint`); the "Paid back" sentence appears only when a payback row exists. The owner's account
  page already used "Balance correction (credited/charged)"; a test pins it.
- M-3 `routes_overview._anonymous`: `ratelimit.OVERVIEW_ANON` = 30 rows per 10 minutes per IP (IPv6 by /64). Live
  pending cookie or over the cap: read-only path, redirect to /login without row and cookie. The write transaction
  starts only when a row is created (limit re-checked under the write lock).
- M-4 `users.set_user_status(active=False)`: `Forbidden` for a user linked to an ACTIVE group admin unless the actor
  is a head admin (route answers 403). Reactivation and former admins unaffected.
- L-1 `admin_auth._attempt_meta`: audit metadata of failed and rate-limited logins is `{step, username_hash}` (HMAC-SHA256
  with HKDF key label `admin-login-username` over the normalised name, 16 hex) plus `username` only when it matches an
  existing admin account. The key `username_attempted` is gone.
- L-2 `config._validate_v2`: production refuses `BALANCE_TOTP_REQUIRED=false`; README and .env.example updated.
- L-3 decision documented in `docs/V2-CONTRACT.md` (Derived values) and the `groups.py` docstring; no code change.
- L-4 `list_group_balances` (and so the CSV): inactive group admins with ANY collection or remittance event stay
  listed (greyed row, "former group admin"), even with held 0.
- L-5 `authz.admin_label(admin)` (linked display name, else username) used by `stats._admin_names/_collector_names`
  (user detail, audit page), the ledger CSV, `group_report` and the prices page.
- L-6 user detail: the correction select lists only payments the actor may correct (head: all; group admin: own
  collected, never bookkeeping).
- L-7 AST scan `balance_service_references` over every `app/web/**/*.py` (imports under any alias, module attribute
  access, bare names, `getattr(x, "name")`, star imports from ledger/users/groups); allow-list is empty on purpose:
  the executor is `app/services/stepup.py`, a service, so it is not scanned. Self-test on aliased samples included.
- L-8 service-level tests: `set_balance` refuses a group admin before anything else (also a key replay); own-account
  rule on effective ids for payment, adjustment, reversal and correction (admin's profile merged into B; a profile
  merged into the admin's own account). Mutation-checked.
- L-9 QR: matrix-equality test for the four URLs, with and without label, standalone and inline; four distinct matrices.

## Existing tests changed
- `test_core_groups` and `test_admin_groups`: a settled former admin now stays listed (L-4).
- `test_audit_security_login_sessions::test_cookies_hardened_in_production`: production cannot turn TOTP off any more, so
  the admin is enrolled (`totp=True`) instead.
- `test_site_sentinel`: the -0.20 payback in the world fixture is booked by the head admin (a group admin is capped).
- `test_admin_audit_coverage`: new login-failure metadata. `test_core_overview`: allowed field set gains `is_bookkeeping`.

## Later tasks must know
- A group admin can no longer record a paid-back above the person's credit; UI shows `admin.err.payback_exceeds_credit`.
- Failed-login audit rows carry `username_hash`/`username`, not `username_attempted`.
- The strict-flag computation uses the effective user as merged today (a later merge can change the old credit).
