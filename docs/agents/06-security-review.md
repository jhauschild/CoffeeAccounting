# Brief 06 — security reviewer (agent name: `security`)

Dir: `/home/claude/wt/audit-security` (worktree, branch `audit-security`, created from merged `main`). You did not write this code. Read `docs/agents/00-protocol.md`, `docs/ARCHITECTURE.md`, PROMPT §5, §6, §9.

## Job: attack the application as an internet-facing service

Review code and run targeted tests (write them as `tests/test_audit_security_*.py`). Cover:
- **Access gate bypass:** reach `/register`, `/profiles`, profile search, or profile selection without the code; replay/forge `coffee_gate`; brute-force limits; code leakage in logs/pages/QR page/audit log.
- **Sessions:** cookie flags on every Set-Cookie (user, admin, gate, pending); token entropy and hash-only storage (inspect DB); rotation on registration/selection/admin login; revoked/expired/inactive handling; user cookie can never reach `/admin`; admin cookie path.
- **CSRF** on every state-changing POST (user and admin), incl. scan POST fetch-metadata checks; **authorization** on every route via route enumeration (anonymous / user / chair-admin out of scope / disabled admin); IDOR on `/coffee/done/{uuid}`, undo, admin user and event ids; chair scope on exports and stats.
- **Admin auth:** Argon2id parameters, TOTP replay/window, recovery codes single-use, rate limits incl. distributed username enumeration timing, password change revoking sessions, bootstrap env ignored after first admin.
- **Injection/output:** XSS via display name/chair names/notes in every template (and CSV), CSV formula injection, SQL injection attempts through search/sort/filter params, open redirects, header injection, request-size limits, unsafe deserialization, path traversal on static.
- **Config/headers:** CSP has no `unsafe-inline`; HSTS and Secure cookies in production; docs/OpenAPI disabled in production; no stack traces; startup refuses weak secrets and http base URL; trusted-proxy handling (spoofed `X-Forwarded-For` ignored unless from a trusted proxy).
- **Secrets hygiene:** grep repo, logs, audit metadata and error pages for passwords, tokens, TOTP secrets, access code, cookies. Run `pip-audit` and report.

## Output

Findings list as `SEV — file:line — issue — exploit sketch — suggested fix`. Keep regression tests that pass; mark demonstrations of real bugs `xfail(strict=True)`. Commit on your branch. Do **not** fix application code.
