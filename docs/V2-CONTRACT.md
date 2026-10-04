# V2 contract (delta to ARCHITECTURE.md)

Authoritative for v2 work. Read this plus your task brief; open `PLAN-v2` sections only when a brief points to them. Where this file and PLAN-v2 rev 3 differ, this file wins (it carries the rev 4 decisions). v1 rules in ARCHITECTURE.md (transactions, errors, ownership, strings, no inline JS/CSS) still apply.

## Decisions (final)
- D1 Schema: **squash into `migrations/versions/0001_initial_schema.py`** (single head, nothing deployed). No 0002. Keep `render_as_batch=True`. Must keep the `effective_users` view and audit-log triggers. Check: upgrade, downgrade base, upgrade, `alembic check`.
- D2 "Sponsor" = a verified member who vouches for guests (A13).
- D3 Group money is tracked per collecting admin; chair rollup groups by the **chair stored on the event at event time**. A demoted admin with a non-zero held amount stays listed as "former group admin".
- Mail-login key, token HMAC and CSRF use HKDF with distinct labels derived from `SECRET_KEY`.

## Schema changes (owner A)
- `users`: add `username`, `username_normalized` (unique), `account_kind` (member|guest), `email` (members only, partial unique), `verified_at`, `sponsor_id` (FK users, guests only), `password_hash`. CHECKs: member needs email and no sponsor; guest needs sponsor and no email; password hash required.
- New: `pending_registrations`, `password_reset_tokens`, `group_remittances`, `used_nonces` (nonce unique, consumed_at; consumed in the same transaction as the action it authorises, for every step-up action).
- `admin_users`: add `user_id` (unique nullable FK), `password_hash` nullable, CHECK role `chair` needs a user link. Drop `admin_chairs`. Role `chair` is shown in the UI as "group admin".
- `admin_sessions`: replace `totp_verified` with `stepup_until`.
- `payment_events`: add `kind` (`cash` | `bookkeeping`, default `cash`), `idempotency_key` (unique nullable), `collector_admin_id` (FK admin_users, nullable; required when kind=cash). A correction copies `collector_admin_id` from the payment it corrects (service layer, tested). Head admin "set balance" entries are `bookkeeping`, never counted as collected.
- `group_remittances`: group admin id, chair_id (at event time), signed amount_cents, recorded_by head admin id, optional `correction_of_id` (unique partial), idempotency_key (unique), note, created_at.
- `pending_actions.kind`: add `view_site`.

## Derived values
- `collected(admin)` = SUM(payment amount_cents WHERE kind=cash AND collector_admin_id=admin). A group admin's negative cash payment (money paid back) reduces it.
- `held(admin)` = collected(admin) - SUM(remittances of admin).
- Chair rollup: collected by `payment_events.chair_id`, remittances by `group_remittances.chair_id`, only for collectors with role `chair`.
- Decision L-3: `groups.held(admin)` (collected minus remitted of that one admin) is the authoritative per-admin figure. A remittance records `chair_id` = the chair of the group admin's linked user at event time (a correction keeps its original's chair), so the per-chair roll-up is informational: if a group admin's profile moves to another chair and the role is later restored, remitted cash can show against a chair that did not collect it. `held` and `check-ledger` are unaffected.
- Paid back (negative cash): a group admin may book it (not as a correction) only up to the person's current credit (balance below zero, effective-user aware); a head admin may exceed it. `groups.over_credit_paybacks` flags every negative cash payment that exceeded the credit at the time (shown on /admin/groups and as a `check-ledger` note).
- `groups.list_group_balances` and the group balances CSV list every group admin, and every former one (inactive, role `chair`) that has any collection or remittance event, even with held 0.
- `balance = consumed - paid` unchanged; `paid` counts both kinds. UI wording: "You owe X" / "Credit X", no minus sign.

## New and changed service interfaces
```python
# ledger.py (A)
get_month_shots(db, user_id, now=None) -> int
add_payment(db, *, admin, user_id, amount_cents, kind="cash", note=None, correction_of_id=None, idempotency_key=None, ...)
set_balance(db, *, admin, user_id, target_balance_cents, idempotency_key, note=None)   # head admin only; books kind=bookkeeping
# groups.py (A)
collected(db, admin_id); held(db, admin_id); chair_rollup(db); record_remittance(db, *, head_admin, group_admin_id, amount_cents, idempotency_key, correction_of_id=None, note=None)
# overview.py (A, read-only)  grouped queries over effective_users; never returns email, username, hash, note, ip, recording admin
# passwords.py (A)  hash, verify, validate_policy(password, username, email)  -- min 10, max 128
# authz.py (A)  visible_chair_ids(db, admin): {admin.user.chair_id} for group admins; None for head admin
# mail.py (B)  class Mailer: send(message) ; backends smtp|console|memory|file ; hourly cap ; safe error categories
# mail_credentials.py (B)  Fernet store in SECRETS_DIR, modes 0700/0600, HKDF key; save/load/clear/status
# registration.py (B)  begin_member, begin_guest, confirm_member, approve_guest, reject_guest, reassign_sponsor
# recovery.py (B)  request_reset(db, username), reset_password(db, token, new_password)
# stepup.py (M)  require_stepup dependency; confirm payload HMAC + nonce (used_nonces)
```
- Member registration for an already-registered email: identical response page; mail says "you already have an account, sign in or use Forgot password" instead of a link.
- `create-admin` refuses a username held by a user; registration refuses a username held by a CLI admin.
- Removed: `gate.py`, `onboarding.py` profile selection, `/join`, `/profiles`, `admin_chairs`, `set-admin-chairs`, `ACCESS_CODE` requirement.

## Route and ownership additions
- U: `/register`, `/verify/{token}`, `/login`, `/logout`, `/forgot`, `/reset/{token}`, `/account` (+ password, edit), `/coffee/done/{id}`, `/overview*`, `/privacy`.
- M: `/admin/login`, TOTP enrolment, step-up confirm pages, `/admin/admins`, `/admin/groups`, QR page (4 codes), set balance, sponsor reassign; CLI `setup`, `setup-mail`, `mail-status`, `test-mail`, `clear-mail`.
- Every `/admin` route stays in the route-enumeration test. A user cookie alone never reaches `/admin`.

## Test rules
- Test config uses cheap Argon2 parameters; one test asserts production parameters.
- Mail logic tests use the `memory` backend; protocol tests use a local aiosmtpd server with a generated certificate (recreate the spike from PLAN-v2 section 7b).
- Task agents run only their own files: `pytest -q -x --tb=short <files> | tail -40`.
