# Plan v2, revision 4: decisions and amendments

Date: 2026-10-03. Supersedes the conflicting parts of `PLAN-v2-accounts-and-site.md` (rev 3). The working copy of these rules is `docs/V2-CONTRACT.md` on branch `v2` of the repo.

## Your decisions

1. Migration: **squash** into `0001_initial_schema.py`. No second revision.
2. A13 confirmed: a sponsor is a verified member who vouches for guests.
3. Former group admins: demoted admins with money still held stay listed as "former group admin"; group money is rolled up by the chair stored on each event at the time.
4. Repository: restored from `coffee-ledger.bundle` in the CoffeeProject folder. Baseline: 775 tests pass (the one e2e file not run here), 56 s. Work continues on branch `v2`; the code travels between sessions as `coffee-ledger-v2.bundle` in the same folder.
5. Plan: Pro, rarely at the limit. Workflow stays conservative: one agent at a time, small tasks, cheaper model by default.

## Amendments to rev 3

- **Collector tracking.** `payment_events` gets `collector_admin_id`; a correction copies it from the payment it corrects, so a head-admin correction reduces the right group balance. Group balance = cash collected by that admin minus remittances.
- **Kind rename.** `payment_events.kind` is `cash` or `bookkeeping` (not `correction`), avoiding the clash with `correction_of_id`. The head admin's "set balance" books `bookkeeping`; a group admin's money paid back is negative `cash`.
- **Chair rollup** uses the chair on each payment and remittance at event time, only for collectors with the group-admin role.
- **Already-registered email:** same page for the visitor; the mail says "you already have an account, sign in or use Forgot password".
- **Username namespace:** `create-admin` refuses a username a user holds, registration refuses a CLI admin's.
- **Key separation:** HKDF with a distinct label for the mail-login encryption, token HMAC and CSRF.
- **Nonces:** new `used_nonces` table consumed in the same transaction as every step-up action (merge, reversal, adjustment, remittance, set balance), not only payments.
- **Tests:** cheap Argon2 parameters in test config; the fake-SMTP spike must be recreated in task 2.2.
- **Mail cap:** when the hourly cap is reached the dashboard says "cap reached", not "mail broken".

## Status

Phase 0 done (restore, decisions, contract, task ledger). Next: task 1.1, the squashed migration and models. Task list: `docs/status/TASKS.md` in the repo.
