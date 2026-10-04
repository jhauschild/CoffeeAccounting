# Task ledger (v2)

Resume rule for any session: read this file and docs/V2-CONTRACT.md, take the first `todo` task whose dependencies are `done`, do only that task, commit when green, update this file. Two failed fixes of one failure: mark `blocked`, write the error, stop. Branch: `v2`. Tests: only your own files; the full suite runs at gates.

Status: todo | doing | done | blocked. Tier: H strongest model, L cheaper model.

| Id | Task | Tier | Depends | Status | Result |
| --- | --- | --- | --- | --- | --- |
| 0.1 | Restore repo from bundle, baseline tests | - | - | done | 775 passed (e2e file excluded), 56 s |
| 0.2 | Resolve plan decisions | - | 0.1 | done | D1 squash, D2 yes, D3 yes (V2-CONTRACT.md) |
| 0.3 | V2-CONTRACT.md and this ledger | - | 0.2 | done | |
| 1.1 | Squash migration, models, CHECKs; downgrade/upgrade/alembic check | H | 0.3 | done | 20 new schema tests pass; alembic up/down/up/check clean; 14 v1 test files known-broken, see docs/status/task-1.1.md |
| 1.2 | Config additions, passwords.py | L | 1.1 | done | settings, passwords.py, keys.py (HKDF); 538 passed at merge |
| 1.3 | Ledger: kind, idempotency, collector_admin_id, month shots, set_balance | H | 1.1 | done | collector, bookkeeping, set_balance, month shots, own-balance rule; 30 tests |
| 1.4 | groups.py, remittances, check-ledger additions | H | 1.3 | done | groups.py, remittances, checker additions; 43 tests |
| 1.5 | authz by own chair, overview.py | L | 1.3 | done | authz own chair, overview.py; 26 tests |
| 2.1 | Mailer interface, memory and file backends, caps | L | 1.2 | done | mail.py backends, caps, templates; 56 tests |
| 2.2 | Encrypted credential store, smtp backend, fake-SMTP and credential tests | H | 2.1 | done | encrypted credential store, verified-TLS SMTP, protocol tests; 58 tests |
| 2.3 | Member registration and verification | H | 2.1 | done | member registration services; 85 tests |
| 2.4 | Guest registration, sponsor approval, reassign | H | 2.3 | done | guest registration, approval, reassign; 55 tests |
| 2.5 | Login, forgot/reset, limits, pending-action change, gate removal | H | 2.3 | done | login, recovery, gate removed, minimal routes; e2e updated |
| R4 | M4 review of 1.3, 1.4, 2.2-2.5 (read-only, writes docs/status/review-M4.md) | H | 2.5 | done | 0 critical/high, 5 medium, 8 low; see review-M4.md |
| F4 | Fix M4-review findings M1-M5, L3-L6, L8 (see review-M4.md) | H | R4 | done | M1-M5, L3-L6, L8 fixed; 49 tests; see task-F4.md |
| 3.1 | User pages and strings for 2.3-2.5 | L | 2.5 | done | member and guest pages, approve/reject, unavailable state, privacy; 45 tests |
| 3.2 | Scan result page, account page | L | 1.3 | done | scan result and account pages, change_password; 28 tests |
| 4.1 | Admin login for group admins, TOTP enrolment | H | 1.1 | done | v2 admin login, TOTP enrolment, stepup_until; suite green |
| 4.2 | Step-up dependency and confirm pages | H | 4.1 | done | step-up confirm flow, require_stepup, 40 tests |
| 4.3 | Role button, /admin/admins, sponsor reassign UI | L | 4.1 | done | roles.py, /admin/admins, sponsor reassign UI; 28 tests |
| 4.4 | /admin/groups, remittances UI, set balance, CSV | H | 4.2, 1.4 | done | /admin/groups, remittances, set balance, CSV; 79 tests |
| 4.5 | CLI setup commands, QR page with 4 codes, dashboard tiles | L | 2.2 | doing | |
| 5.1 | /overview and /overview/people | L | 1.5 | done | /overview and /overview/people; 37 tests |
| 5.2 | Person page, chairs, prices, privacy sentinel test | H | 5.1 | doing | |
| 6.1 | .env.example, compose secrets volume, backup exclusion, README, privacy, smoke | L | 2-5 | todo | |
| 6.2 | Real docker compose up check | L | 6.1 | todo | |
| 7.1 | Playwright e2e rewrite | L | 3, 5 | todo | |
| 7.2 | Ledger audit and security review (fresh reviewer) | H | all | todo | |
| 7.3 | Acceptance run, ACCEPTANCE.md update | L | 7.2 | todo | |

Gates: M4 after 2.5, M5 after 4.5, M6 after 7.3. At each gate: full suite, alembic check, commit, then bundle (see docs/status/PERSIST.md).
