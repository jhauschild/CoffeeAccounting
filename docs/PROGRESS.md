# Progress

## Current state (v2, branch `v2`)

v1 (QR scanning, profiles, ledger, admin area; 776 tests) is finished. v2 replaces profile selection with username accounts (verified TUM email members, sponsored guests), adds password sign-in, mail through the operator's LRZ mailbox, group admins with group balances and remittances, TOTP step-up for balance changes, the open `/overview` site and four QR codes.

Implementation tasks through M5 (packages 1 to 5) are done and merged; the M5 review (R5) and task 6.1 (this ops/docs task) are the open work. Remaining: 6.2 real `docker compose up` check (no Docker daemon was available while writing the ops files, so no image build or container run has been done), 7.1 Playwright e2e rewrite, 7.2 ledger audit and security review, 7.3 acceptance run and `docs/ACCEPTANCE.md` update (it still describes v1). Test count at the last gate (after 4.5 and 5.2): 1828 passed, 4 skipped, 0 failed, including the e2e file. The ledger of tasks with status is `docs/status/TASKS.md`; hand-offs are in `docs/status/task-*.md`.

Not verified yet: Docker build and run, the real LRZ mail server (covered by the post-deployment mail checklist in the README, not by tests), HSTS over real TLS, `deploy/nginx.conf`.

## Tasks (one line each; see `docs/status/TASKS.md`)

| Id | Result |
| --- | --- |
| 0.1 to 0.3 | restore, baseline, decisions (squash migration, sponsor = verified member, group money per collecting admin), `V2-CONTRACT.md` and the task ledger |
| 1.1 | squashed migration `0001_initial_schema.py`, models, CHECKs; alembic up/down/up/check clean |
| 1.2 | v2 settings, `passwords.py`, `keys.py` (HKDF) |
| 1.3 | ledger: payment kind, idempotency, collector, month shots, set balance, own-balance rule |
| 1.4 | `groups.py`, remittances, check-ledger additions |
| 1.5 | authz by own chair, `overview.py` |
| 2.1 | Mailer interface, memory/console/file backends, caps, mail texts |
| 2.2 | encrypted mail-login store, verified-TLS SMTP backend, fake-SMTP protocol tests |
| 2.3 | member registration and verification |
| 2.4 | guest registration, sponsor approval, reassign |
| 2.5 | login, forgot/reset, limits, pending-action change, gate removal |
| R4, F4 | M4 review (0 critical or high, 5 medium, 8 low) and the fixes (correction rules, chair lock, username probe limit, log redaction, URL neutralising, HKDF labels) |
| 3.1, 3.2 | user pages for registration, approval, login, recovery; scan result and account pages |
| 4.1 to 4.3 | admin login for group admins and TOTP enrolment; step-up flow; roles, `/admin/admins`, sponsor reassign UI |
| 4.4 | `/admin/groups`, remittances UI, set balance, group balance CSV |
| 4.5 | CLI `setup`, `setup-mail`, `mail-status`, `test-mail`, `clear-mail`; mail status; four QR codes; dashboard tiles |
| 5.1, 5.2 | `/overview`, people, person, chairs, prices pages; privacy sentinel crawl test |
| 6.1 | ops and docs for v2: compose `secrets` volume, `.env.example`, backup/restore notes, smoke script, README, architecture, this file |

## Superseded v1 notes

The v1 phases (core, user web, admin, ops, ledger audit, security review, acceptance) were completed with 776 tests; their evidence is in `docs/ACCEPTANCE.md` until task 7.3 replaces it.
