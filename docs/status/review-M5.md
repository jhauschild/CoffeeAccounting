# Review M5 (independent, fresh context)

Reviewed at `05c79b9` (v2 head). Scope: admin tasks 4.1 to 4.5, user pages 3.1/3.2, open site 5.1/5.2, and the F4 fixes.
Method: real HTTP and service-level attack scripts (under the session scratchpad, not committed), mutation experiments on a
copy of the repo, and reading of the code and of every task hand-off. No application code or tests were changed.

Result: **0 critical, 0 high, 4 medium, 9 low.** The step-up, authorization, privacy, account and secrets areas hold up
against every attack tried; all F4 fixes (M1-M5, L1-L8) were re-verified and hold. The findings below are residual gaps.

## Critical

None.

## High

None.

## Medium

### M-1. A group admin can cover missing cash with a fake "paid back" payment (negative cash has no cap)
- Where: `app/services/ledger.py:398-460` (the negative cash path; `collector_admin_id = admin.id` at line 438, no check that the user holds any credit).
- Observed: group admin `ga` collects 50.00 from user A (held = 5000). `ga` then books `amount_cents=-5000` (kind cash) on user B, who never paid. Result: `held` for `ga` drops to 0, B's balance becomes "owes 50.00", and `check-ledger` reports ok (script `atk/test_c3.py`). The step-up gate does not help, because the actor is the legitimate group admin who confirms it themselves.
- Impact: the held-cash figure that the head admin relies on can be zeroed by a group admin with no remittance, at the price of an invented debt on a member in their own chair (visible to that member and to head admins, but nothing flags it).
- Fix: reject a negative cash payment larger than the target's current credit (balance below zero) unless a head admin records it, or surface "paid back" events above credit as a flagged item on /admin/groups.

### M-2. The open site labels bookkeeping adjustments (set balance) as "Paid back: money that was returned to the person"
- Where: `app/web/routes_overview.py:203` maps every negative payment event to `"payback"`, including `kind == "bookkeeping"` events created by `set_balance`.
- Observed: head admin sets a user's balance so that they owe 5.00; any logged-in viewer then sees on `/overview/people/<id>`: "2026-10-04 15:57 EUR 5.00 Paid back" plus the explanatory sentence that money was returned to the person (script `atk/test_d3.py`). No money moved.
- Impact: misleading public record; members will read a bookkeeping correction as a cash refund.
- Fix: map `kind == "bookkeeping"` to its own neutral label ("Balance adjustment") and add that wording to the site template.

### M-3. Every cookie-less GET of `/overview*` writes a database row with no rate limit
- Where: `app/web/routes_overview.py:74-83` (`_anonymous`) and `app/services/pending.py:55-58` (`create_view_site_pending`: "every call stores a new row").
- Observed: a client that never returns the pending cookie (any scanner or crawler) causes one write transaction and one `pending_actions` row per request. Rows are only removed by `purge-expired`, and nothing in the route or middleware limits the rate. The database is SQLite with a single writer, so an unauthenticated flood also contends with real writes (payments, step-up confirms).
- Fix: apply the existing `ratelimit` helper per IP to the anonymous branch, or serve a plain redirect without a row when no cookie is presented and only create the row after the user returns with one.

### M-4. A group admin can lock a peer group admin out by deactivating the peer's user profile
- Where: `app/services/users.py:224-237` (`set_user_status` has no linked-admin guard), compared with `update_profile` at lines 185-186, which does guard `_is_active_group_admin`. `_account_ok` in `app/services/admin_auth.py` (about line 257) kills admin login for an inactive linked user.
- Observed: `g` and `peer` are both group admins of the same chair. `set_user_status(admin=g, user_id=peer.user_id, active=False)` succeeds; `peer`'s admin row stays `active=True` but every request fails `_account_ok` (script `atk/test_b4.py`). The peer cannot recover alone, and the action needs no step-up.
- Impact: an admin can silence a peer who is about to review their payments (a possible companion of M-1). It is audited, but only after the fact.
- Fix: make `set_user_status(active=False)` raise `Forbidden` for a user linked to an active group admin unless the actor is a head admin, mirroring `update_profile`.

## Low

### L-1. `username_attempted` is stored verbatim in the audit log on failed and rate-limited logins
- Where: `app/services/admin_auth.py:463` and `:487`.
- Observed: by inspection, a person who pastes their password into the username field has it written (truncated to `MAX_USERNAME_LENGTH`) into `audit_log.metadata`, which is shown on admin pages and exported.
- Fix: store only a short hash of the attempted name, or the name only when it matches an existing account.

### L-2. `BALANCE_TOTP_REQUIRED=false` is accepted in production
- Where: `app/config.py:217` (default is `is_production`, but `_validate_v2` does not reject an explicit false in production).
- Observed: with the variable set to false, balance actions need only an open step-up window, as intended for development. Nothing warns in production.
- Fix: log a startup warning (or refuse) when `is_production` and `balance_totp_required` is false.

### L-3. Remittance chair is taken from the group admin's current chair, not from the chairs where the cash was collected
- Where: `app/services/groups.py:216` (`chair_id = target.user.chair_id`).
- Observed: if a group admin's profile is moved to another chair after demotion (role and link are kept) and the role is later restored, new remittances carry the new chair while earlier collections carry the old one, so `chair_rollup` per chair shows remitted cash against a chair that did not collect it. `groups.held` itself (collected minus remitted per admin) stays correct and `check-ledger` is unaffected.
- Fix: document that the roll-up is by event-time chair and remittance chair is informational, or record remittances against the admin only.

### L-4. `list_group_balances` omits inactive admins whose held is zero
- Where: `app/services/groups.py` (`list_group_balances`).
- Observed: a former group admin with held = 0 disappears from /admin/groups and from `group_balances_csv`, together with their history of remittances. Correct for the live total, but a head admin cannot find the row to correct an old remittance.
- Fix: include inactive admins that have any collection or remittance event, greyed out.

### L-5. Admin names are rendered from `username` (login name), not a display name
- Where: `app/services/stats.py:369-373` (`_admin_names`), `app/services/exports.py:118-122` (ledger CSV), `templates/admin/user_detail.html` lines about 165 and 187.
- Observed: for group admins the login `username` is shown as the recorder; the linked member's display name is not used. Admin-only pages (nothing reaches the open site; verified), but a mixed list of usernames and display names is hard to read in the CSV.
- Fix: show the linked user's display name when present.

### L-6. Correction dropdown in the user detail page lists payments the actor cannot correct
- Where: `templates/admin/user_detail.html` lines about 36-40.
- Observed: a group admin sees payments collected by another admin in the correction select; submitting yields `Forbidden` after the step-up preview.
- Fix: filter the options by collector for non-head admins.

### L-7. The static scan test is a plain regex over `app/web/*.py`
- Where: `tests/test_admin_routes_authz.py:130-145`.
- Observed: `from app.services.ledger import add_payment as _ap` followed by `_ap(...)` is not matched. I added such a route to a copy of the repo: the scan passes, but `test_every_post_route_is_allow_listed_or_requires_stepup` fails, so a new POST route is still caught. An existing allow-listed route could still be edited to call an alias without any test failing.
- Fix: scan the AST for any import of those names into `app/web` instead of call sites.

### L-8. Mutation survivors show untested rules
- Evidence from mutating a copy: (a) removing `require_global` from `ledger.set_balance` at service level: 73 tests pass (only the route test catches it); (b) `_ensure_not_own_account` using raw instead of effective ids: 102 tests pass (the merged-own-account case is untested); (c) removing the spent-nonce precheck in `stepup.authorise`: 40 pass (equivalent mutant: the unique insert into `used_nonces` still blocks replay, so no action needed).
- Fix: add one service-level test for (a) and one for (b).

### L-9. QR codes: label is not covered by an automated decode test
- Where: `app/services/exports.py` (`qr_svg`).
- Observed: I rebuilt the module matrix from the SVG path for all four URLs, with and without label, and it equals the `segno` matrix (script `atk/test_qr.py`), and all four URLs are distinct. The repo has no test that does this; only structural assertions.
- Fix: add the matrix-equality check from `atk/test_qr.py` to the repo tests.

## Checked and fine

(a) Step-up
- Unsigned, tampered, replayed, other-admin, other-session and expired payloads are all refused; the nonce is spent in the same transaction as the action (mutation "nonce not consumed" is caught).
- The step-up window is not extended by use (mutated: caught) and cannot be forced open (mutated: caught). TOTP replay inside 120 s is refused (mutated: caught). Concurrent use of a recovery code succeeds exactly once.
- A direct `POST /admin/stepup/confirm` without a preview, or without CSRF, fails. Preview routes always roll back (verified by row counts). `StepupGrant` is minted only in `authorise()`.
- With `BALANCE_TOTP_REQUIRED=false` the window alone suffices, as designed (see L-2).

(b) Authorization
- Group admins see only their linked user's chair; head-only actions (merge, set balance, remittance, price, roles, groups page) refuse group admins at route and service level (service level for `set_balance` untested, L-8).
- Own-account rule uses effective ids across merges. Demotion deactivates the row, revokes its sessions and the next request fails (mutations caught).

(c) Ledger
- Scripted mixed operations (cash, bookkeeping via `set_balance`, corrections, remittances, a merge, a demotion, a former admin) end with `groups.held = collected - remitted`, `chair_rollup` equal to the sum of the group rows plus unassigned, and `check-ledger` ok. Corrections copy kind, collector and chair; wrong sign, over-amount and second correction are refused. `set_balance` is never counted as cash (mutation caught).

(d) Open site
- Login required; anonymous visitors get a 303 to /login with a pending row. Responses carry `Cache-Control: private, no-store` (mutation caught). No email, username, admin id or collector appears on any `/overview*` page; names and notes are escaped (script payloads rendered inert). Unknown ids, bad UUIDs and directory probes return the same not-found page. Search `q` and `chair` are bounded.

(e) Accounts
- Password change revokes other sessions, including linked admin sessions. Guest approve/reject needs CSRF (mutation caught) and a valid token; used, expired and unavailable states render without leaking whether an account exists. Rate limits are enforced. Access logs redact `/verify/` and `/reset/` tokens in the app logger, `scripts/run.sh` (`--no-access-log`), Caddy and nginx configs (mutation caught).

(f) CLI and secrets
- `allow_abbrev=False` on setup commands (mutation caught). Passwords come from getpass or stdin, never argv; the mail credential file is Fernet-encrypted with restrictive permissions; `mail status` prints names only, never values; error messages name variables, not their contents.

## DoD table (PLAN-v2 section 9, items 1-10)

| # | Item | Status | Evidence / gap |
|---|------|--------|----------------|
| 1 | Accounts: register, verify, login, reset, change password | Met | `tests/test_final_f4.py`, account tests; attack scripts pass |
| 2 | Group admin = linked chair-role admin, scoped by chair | Met | `tests/test_admin_routes_authz.py`; M-4 is a related gap |
| 3 | Step-up for every balance-changing action | Met | `tests/test_admin_stepup.py` (40); static scan has the alias gap L-7 |
| 4 | Cash vs bookkeeping, collector recorded | Met | ledger tests; M-1 and M-2 are rule/labelling gaps |
| 5 | Group balances and remittances, `held = collected - remitted` | Met | scripted scenario plus check-ledger; L-3, L-4 |
| 6 | Open site, login-only, privacy | Met | `tests/test_site_sentinel.py`; M-2, M-3 |
| 7 | Guest flows and view_site pending | Met | route tests; M-3 for volume |
| 8 | CLI setup, mail status, QR codes, dashboard | Met | CLI tests; QR matrix equality verified by script only (L-9) |
| 9 | Secrets and logging hygiene | Met | access-log tests; L-1 (audit log content) |
| 10 | check-ledger covers group and correction rules | Met | checker tests; scenario passes |
