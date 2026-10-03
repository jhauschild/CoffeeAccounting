# Task: Coffee ledger (trust-based, QR-driven, with price history)

Act as a senior full-stack engineer. Design and implement a small, robust, self-hosted web application that records coffee consumption and payments in a university department. Prefer the simplest solution that satisfies the invariants below; do not add abstractions, services, or features that are not listed.

Work in the current working directory (it may be empty; if it is not, inspect it first and follow any existing conventions).

## 1. Context and fixed decisions

These decisions are final. Do not re-open them.

- **Trust-based ledger, not a payment processor.** The app never handles payments. Payment events only record that an administrator received money outside the application.
- **Money is tracked.** All amounts are integers in minor units (cents) in one configurable currency (default EUR). Never use floats for money.
- **The price changes over time.** Every consumption event stores a snapshot of the price that applied when it happened. Past amounts are never recalculated when the price changes.
- **Internet-reachable.** Users often scan on mobile data, so the app is reachable from the public internet, always behind HTTPS. Because of that: a department access code gates profile creation and selection (section 5), public endpoints are rate-limited, and admins use password + TOTP (section 6).
- **Local profiles only.** No external identity provider (no TUM SSO, Shibboleth, Microsoft, Google, etc.), no passwords for normal users, **no email address and no free-text note** on user profiles.
- **Mobile-first.** The primary use is scanning a QR code on the coffee machine with a phone.
- **Scale assumption:** up to ~200 users and a few hundred events per day, one server, one operator with little time. *(Adjust if wrong.)*
- **Database:** SQLite (WAL mode) is the supported production database: one file, trivial backup. Keep the code portable (SQLAlchemy 2 + Alembic, no SQLite-only SQL outside migrations) so PostgreSQL could be adopted later, but do not build PostgreSQL deployment now. Run the app as a single process.
- **Deployment:** Docker + docker-compose (one service, one named volume), behind a TLS-terminating reverse proxy.
- **UI language:** English, with every user-facing string in one central catalog so German can be added later.
- **Out of scope for v1** (do not build, but do not make them impossible): erasure or anonymization tooling, user email/notes, public JSON API, API keys, passkeys, cached aggregates, per-user data export, PostgreSQL deployment, separate prices for single and double (a double is always 2 × the per-shot price).

## 2. Working method

1. Briefly report: what exists in the directory, the architecture you propose (one paragraph + a module list), and any assumptions. Then write `docs/ARCHITECTURE.md` (modules, which module owns which tables and routes, and the service-layer function signatures) before writing application code. Continue without waiting for confirmation.
2. Build in three milestones. At the end of each: all tests pass, `docs/PROGRESS.md` is updated (done / not done / known issues), and the work is committed with a clear message.
   - **M1 – Core scan-to-ledger:** data model (including prices), migrations, access gate, registration/profile selection, sessions, scan flow, undo, success + account pages, ledger invariants, tests for all of that.
   - **M2 – Administration:** admin auth (password + TOTP), chairs, price management, dashboard, user table, payments/corrections/reversals/merge/deactivation/session revocation, audit log, CSV export, QR page, CLI commands, tests.
   - **M3 – Operations:** Dockerfile, compose, backup/restore, health endpoints, privacy page, README, hardening pass, end-to-end browser test.
3. Be honest in the final report. For every item in the Definition of Done, say whether you **verified it by running it** or only implemented it. If Docker, a browser, or network access is unavailable in your environment, say so instead of claiming success.

## 3. Scan flow (the critical path)

Two permanent QR codes: `{PUBLIC_BASE_URL}/coffee/single` and `{PUBLIC_BASE_URL}/coffee/double` (single = 1 shot, double = 2 shots). The base URL is configuration. The codes contain only these URLs.

**GET must never change state.** `GET /coffee/{single|double}` returns a tiny page (`Cache-Control: no-store`) containing a form that POSTs to `/coffee/{kind}` with a **server-issued signed request token** (HMAC with the app secret; contains kind, random nonce, issued-at; expires after 30 minutes). Issuing the token writes nothing to the database. A visible button is present as a no-JS fallback.

The page auto-submits the form from a static script file (no inline JS; strict CSP) **only** when the document is visible and not prerendering (wait for `visibilitychange`/`prerenderingchange` if needed), and only once (disable the button, set a guard flag).

`POST /coffee/{kind}`:
1. Verify the token signature, kind, and expiry; reject cross-site requests (`Sec-Fetch-Site: cross-site`, bad `Origin`).
2. **If the browser has a valid user session and the profile is active:** in one transaction, check the profile is still active, look up the price in effect (if none is configured, record nothing and show a safe "not configured yet, tell an administrator" page), then insert the consumption event with the price snapshot, using the token nonce as the idempotency key (unique constraint). If the nonce already exists, do not insert; redirect to that event's success page as if it had just succeeded. Respond with `303` to `/coffee/done/{event_uuid}`.
3. **If there is no valid session:** insert a `pending_actions` row (random opaque id, kind, nonce, expiry 1 hour, `consumed_at` null), set a short-lived HttpOnly cookie referencing it, and `303` to `/join`. The pending action lives server-side; nothing about it travels in a URL, so there is no redirect parameter to abuse.
4. After registration or "use an existing profile", in the **same transaction** that creates the session: atomically consume the pending action (`UPDATE … WHERE consumed_at IS NULL`; proceed only if one row changed), insert the event with the stored nonce (price looked up at that moment), then `303` to the success page. Double-submitting registration therefore creates neither a second profile nor a second coffee (the registration form carries its own one-time token; a second submit is redirected to the already-created result).
5. Expired or already-consumed pending actions fall back to the plain registration/selection flow with a short explanation.

`GET /coffee/done/{event_uuid}` is read-only, requires that the event belongs to the current session's user, and shows:
- large success indicator; "Single recorded" / "Double recorded"; shots added; price per shot and the amount charged; local timestamp;
- totals: shots consumed and amount consumed, amount paid, balance (negative balance is shown as "credit");
- **Undo** button, shown only for the user's most recent coffee event made from this session, only if not already reversed, and only within `UNDO_WINDOW_SECONDS` (default 300);
- link to the account page.

Refreshing the success page, pressing Back to the intermediate page, retrying a POST, or double-tapping must never create a second event. Two separate scans (separate GETs → different nonces) create two events.

**Undo** (`POST /coffee/undo/{event_uuid}`, CSRF-protected) appends a reversal event referencing the original, with the original's quantity, price snapshot and amount negated; it never edits or deletes. The original can be reversed at most once; a reversal cannot be reversed; two concurrent undos produce exactly one reversal. Undo ignores the current price.

## 4. Data model and ledger invariants

Use UUIDs for all externally visible identifiers. Timestamps are timezone-aware UTC internally; display in `LOCAL_TIMEZONE` (default Europe/Berlin). "Today/week/month" use local calendar boundaries, weeks Monday–Sunday.

**chairs:** id, full_name, short_name, active, created_at. Never deleted. The label shown in the UI is configurable (`CHAIR_LABEL`, default "Chair", alternative "Coffee group").

**users:** id, display_name, normalized_name, chair_id, status (`active` | `inactive` | `merged`), merged_into_id (nullable), created_at, last_activity_at. Names need not be unique; wherever profiles are listed, show the chair next to the name. `normalized_name` must make "Müller" findable by "muller" and "mueller" (casefold, German umlaut transliteration, strip other diacritics, collapse whitespace; apply the same function to queries).

**prices (immutable, append-only):** id, price_per_shot_cents (integer ≥ 0), effective_from (UTC, unique), created_by_admin_id, note, created_at. The price in effect at time *t* is the row with the greatest `effective_from ≤ t`. Prices cannot be backdated (`effective_from` must not be earlier than the time of entry); a wrong price is superseded by a new row. Only global admins can add prices (admin page and `python -m app.cli set-price --cents N [--from ISO8601]`). If no price is in effect, recording a coffee is refused (see section 3); never fall back to zero.

**consumption_events (immutable, append-only):** id, user_id, chair_id (the user's chair **at event time**), quantity (signed shots), type (`single` | `double` | `reversal` | `adjustment`), unit_price_cents (snapshot), amount_cents (signed), price_id (nullable, the price row used), idempotency_key, reversal_of_id (nullable), session_id (nullable; which browser session created it), admin_id (nullable), note (nullable), created_at.
- `single`/`double`: `amount_cents = quantity × unit_price_cents`, taken from the price in effect at insert time.
- `reversal`: copies unit_price_cents; `quantity` and `amount_cents` are exactly the negatives of the original's.
- `adjustment` (admin only): admin enters quantity and amount; the form pre-fills `quantity × current price`, and the admin may override the amount.

**payment_events (immutable, append-only):** id, user_id, chair_id (at event time), amount_cents (signed money received), admin_id (required), correction_of_id (nullable), note (nullable), created_at. Payments are in money, not shots, because the price varies.

Database-level constraints (SQLAlchemy `CheckConstraint`/indexes, mirrored in the Alembic migration), not just application checks:
- `quantity <> 0` on consumption events; `amount_cents <> 0` on payment events;
- `type='single'` ⇒ quantity 1; `type='double'` ⇒ quantity 2; for both, `amount_cents = quantity × unit_price_cents`; `type='reversal'` ⇒ quantity < 0 and `reversal_of_id` not null; other types ⇒ `reversal_of_id` null; `adjustment` ⇒ `admin_id` not null;
- quantity and amount never have opposite signs (`amount_cents = 0` is allowed only when the price was 0 or for an explicit adjustment);
- unique `idempotency_key`;
- **unique partial index** on `reversal_of_id` (an event is reversed at most once) and on `correction_of_id`;
- price rows: `price_per_shot_cents >= 0`, unique `effective_from`;
- foreign keys enforced (SQLite: `PRAGMA foreign_keys=ON` on every connection); unique session-token hash; unique normalized admin login.

Service-layer rules enforced inside the write transaction (and tested): a reversal copies the original's quantity/amount negated; a reversal cannot itself be reversed; normal users can only create single/double events and reversals of their own most recent in-window event; users can never supply a quantity, amount, price, user id, or chair id.

SQLite specifics: WAL mode, `busy_timeout`, and write transactions that take the write lock up front (`BEGIN IMMEDIATE`) so the "still active?" check, the price lookup, and the insert are atomic. Transient lock errors show a safe "please try again" page.

**Derived values** are always computed from the ledger, never stored:
- `consumed_shots = SUM(consumption quantity)`; `consumed_amount = SUM(consumption amount_cents)`;
- `paid_amount = SUM(payment amount_cents)`;
- `balance = consumed_amount − paid_amount` (positive = the user owes; negative = credit).

No conversion between shots and money exists anywhere: prepaid credit is consumed at the snapshot price of each later coffee. Totals follow the *effective user*: events of a merged profile count for the profile it was merged into.

**Merge (global admin only):** mark the duplicate `status='merged'`, set `merged_into_id` (re-point any profiles previously merged into the duplicate), revoke its sessions, write an audit entry. **Do not modify or move any ledger event.** Provide a SQL view or query helper that resolves the effective user, and use it everywhere totals are computed. A merged profile no longer appears in lists and cannot scan.

Provide `python -m app.cli check-ledger`: verifies all invariants above on existing data (orphaned or double reversals, quantity/type mismatches, `amount = quantity × unit price` for single/double, snapshot price matches the price row in effect at `created_at`, reversal amounts equal the negated original, merge chains without cycles) and exits non-zero on problems.

## 5. Users, access gate, and sessions

**Access gate.** Because the app is internet-reachable, nobody can create or select a profile, or see the profile list, without the department access code. The code is a shared secret in `ACCESS_CODE` (required in production, at least 8 characters, compared in constant time) that the operator shares with the department, e.g. on a sign next to the QR codes. Rotating it means changing the environment variable and restarting. `/join` asks for the code once per browser; a correct code sets a short-lived signed cookie (`coffee_gate`, 1 hour, HttpOnly, Secure, SameSite=Lax) that unlocks `/register` and `/profiles`. Wrong-code attempts are rate-limited (e.g. 10 per 15 minutes per IP). A browser that already has a valid user session never needs the code, and scans from it work as before. The QR codes never contain the code.

**Registration** fields: display name (required, trimmed, length-limited), chair (required, from active chairs only), and a privacy acknowledgement checkbox. If the name already exists in the selected chair, show "A profile with this name already exists in this chair. Is it you? → Use existing profile", but still allow continuing. If registration follows a scan, say clearly that the pending coffee will be recorded afterwards. Registration submissions are rate-limited per IP (e.g. 10 per hour).

**Existing-profile selection:** searchable list of active profiles (name + chair only), reachable only through the access gate, a prominent notice that this is a trust-based system and that choosing someone else's profile books coffee to them, and a link to register a new profile. The search endpoint is rate-limited.

**Edit profile:** display name and chair. Every chair change by a user or admin is written to the audit log (actor type recorded).

**Account page:** profile, shots consumed, amount consumed, amount paid, balance, recent consumption and payment history, current price, edit profile, "remove this browser" (revokes the current session). Users cannot edit amounts, payments, prices, or quantities.

**Sessions:**
- Cookie `coffee_session`: random 256-bit opaque token only. Store only its SHA-256 hash (a fast hash is correct for a high-entropy random token) plus user_id, created_at, last_seen_at, expires_at (default 180 days, `SESSION_LIFETIME_DAYS`), revoked_at.
- Flags: HttpOnly; Secure; SameSite=Lax; Path=/. (Secure is always on in production; it may be off only in development.)
- Issue a new token on registration and on profile selection (rotate; invalidate any previous session of that browser).
- Update `last_seen_at` at most once per hour to avoid a write on every scan. Deactivated or merged users' sessions are invalid immediately.
- Cap coffees per session (`MAX_COFFEES_PER_SESSION_PER_HOUR`, default 30) to stop accidental loops; do not rate-limit scans per IP (mobile carriers share IPs).
- No identity or authorization data in localStorage; no passwords for users.
- Keep the session layer independent of the ledger (ledger rows reference only `user_id`), so passkeys or magic links can be added later without schema changes to the ledger.
- Document the limitation that phone cameras, in-app QR scanners, and home-screen web apps may use a different cookie jar than the browser where the user registered; the "use existing profile" flow is the recovery path and must be fast.

## 6. Administration

**Accounts and roles:** `global` and `chair` administrators (chair admins are assigned one or more chairs via an `admin_chairs` table). Admin accounts are created only via CLI:
- `python -m app.cli create-admin --username NAME --role global|chair [--chair SHORT ...]` (prompts for password; also support bootstrap via `ADMIN_BOOTSTRAP_USERNAME` / `ADMIN_BOOTSTRAP_PASSWORD` for first start, ignored once any admin exists);
- `python -m app.cli set-admin-chairs`, `reset-admin-password`, `reset-admin-totp`, `disable-admin`, `set-price`.

**Admin authentication:** username + password (Argon2id via `argon2-cffi`, minimum length 12) **and a TOTP second factor** (`pyotp`; enrollment on first login with QR/secret, 8 single-use recovery codes stored hashed; required when `ADMIN_TOTP_REQUIRED` is true, which is the production default). Separate cookie `coffee_admin` with `Path=/admin`, Secure, HttpOnly, SameSite=Lax; separate sessions table; own expiry (default 12 h, `ADMIN_SESSION_HOURS`); CSRF token on every state-changing form; login rate limiting (e.g. 5 failures per 15 minutes per username+IP, stored in the database so restarts don't reset it, covering both password and TOTP failures); logout; password change (revokes the admin's other sessions); session revocation. Normal-user sessions can never reach `/admin`. Document that the proxy should additionally restrict `/admin` to department or VPN addresses where possible.

**Authorization:** every `/admin` route enforces role and chair scope server-side. A chair admin sees and modifies only users currently in their chairs. Chair admins can record payments/corrections, reverse events, deactivate/reactivate, and revoke sessions for those users, but cannot change a user's chair, merge profiles, manage chairs or prices, or see other chairs. Global admins can do everything, including creating/renaming/deactivating/reactivating chairs (chairs with users or events are never deleted) and adding prices.

**Dashboard:** total consumed (shots and amount), total paid, total balance; today / this week / this month (shots, amount consumed, payments received); totals grouped by chair (by the event's chair); current price and recent price changes; last 20 consumption and last 20 payment events.

**User table:** display name, chair, shots consumed, amount consumed, amount paid, balance, last activity, status. Search by name (normalized), filter by chair, sort by balance / name / consumption / last activity, pagination, and **CSV export honoring the current filters** (audited). CSV rules: UTF-8 with BOM; delimiter configurable (`CSV_DELIMITER`, default `;` for German Excel); decimal separator configurable (`CSV_DECIMAL_SEPARATOR`, default `,`); **neutralize spreadsheet formula injection** (prefix text cells starting with `= + - @ \t \r` with `'`); proper quoting. Also provide a ledger CSV export (consumption events with quantity, unit price, amount; and payment events) filtered by date range and chair.

**User detail:** complete consumption, payment, and audit history; record a payment (money amount, positive or negative, with note; parsed strictly: `12.50` or `12,50`, at most two decimals, rejected otherwise); enter consumption adjustments (type `adjustment`, with note); reverse an erroneous consumption event; change chair (global only); deactivate/reactivate; revoke browser sessions; merge into another profile (global only).

**Price page (global only):** current price, full price history (who set it, when, effective from, note), form to add a new price with an effective date/time (default: now). Changing the price affects only coffees recorded afterwards.

**QR page:** shows both canonical URLs and the current price, generates labeled printable SVG QR codes (use a pure-Python library such as `segno`; no external services), a clean print stylesheet (one code per half-page, large "SINGLE" / "DOUBLE" labels, plus an optional free-text line the admin types before printing, e.g. "Access code: …", which is not stored). URLs come from `PUBLIC_BASE_URL`. Also `python -m app.cli qr --out DIR`.

## 7. Audit log

Append-only `audit_log`: id, actor_type (`admin` | `user` | `system`), actor_id, action, target_type, target_id, created_at, metadata (JSON), source_ip. No update/delete code path, plus database triggers that reject UPDATE/DELETE (create them in the Alembic migration). Record: admin login attempts (success/failure incl. TOTP step, username attempted), logout, TOTP enrollment/reset, chair create/rename/deactivate/reactivate, price changes, any chair change of a user (actor type shown), admin edits of a user, payment entries, adjustments, reversals, merges, deactivation/reactivation, session revocations, CSV exports, password changes, CLI admin management. Never log passwords, TOTP secrets or codes, tokens, the access code, or cookies. Source IP is taken from `X-Forwarded-For` only when the request comes from a proxy listed in `TRUSTED_PROXY_IPS`.

## 8. Privacy (kept proportionate)

Identifiable consumption records are stored on an internet-reachable server. Provide a `/privacy` page: what is stored (display name, chair, ledger events with amounts, session records, admin audit log), why, who can see it, the configurable retention statement (`RETENTION_TEXT`), and configurable operator contact (`OPERATOR_CONTACT`). The app must be described everywhere as a trust-based departmental ledger that does not prove real-world identity. No analytics, trackers, external fonts, CDNs, or third-party calls; all assets served locally. Deactivation is the only removal mechanism in v1; state in the README that erasure tooling is intentionally not included.

## 9. Security (internet-facing)

Implement and test: HTTPS only in production (startup refuses a non-https `PUBLIC_BASE_URL`; HSTS header; Secure cookies); the access gate; CSRF protection on every state-changing user and admin form (plus the scan token and fetch-metadata/Origin check); input validation and length limits; output escaping (Jinja autoescape on); ORM/parameterized queries only; session rotation; rate limiting on admin login, access-code attempts, registration, and profile search; security headers including a strict CSP (`default-src 'self'`, no inline scripts or styles), `X-Content-Type-Options`, `Referrer-Policy: same-origin`, `frame-ancestors 'none'`; request-size limits; no stack traces or debug info in production (FastAPI docs/OpenAPI disabled in production); all redirects go to fixed internal paths. Never trust role, user id, chair id, quantity, price, amount, or totals from the browser; do not rely on hidden UI for authorization. Fail clearly at startup in production if `SECRET_KEY` or `ACCESS_CODE` is missing, short, or a known placeholder. Run `pip-audit` (or equivalent) and report the result.

## 10. Technology

Python 3.12, FastAPI, SQLAlchemy 2, Alembic, Jinja2 server-rendered templates, plain CSS (small, mobile-first, large tap targets, works without JS except for the scan auto-submit), minimal JS in static files, pytest, Docker, docker-compose. Keep the module structure flat and obvious (e.g. `app/{config,db,models,services,routes_user,routes_admin,cli}.py`, `templates/`, `static/`, `migrations/`, `tests/`). Business rules live in a service layer used by routes and CLI, not in templates or routes. Money formatting and parsing live in one helper.

## 11. Configuration (environment variables, `.env.example` without real secrets)

`PUBLIC_BASE_URL`, `DATABASE_URL` (default SQLite file in the data volume), `SECRET_KEY`, `ACCESS_CODE`, `ENVIRONMENT` (`development` | `production`), `SESSION_LIFETIME_DAYS`, `ADMIN_SESSION_HOURS`, `ADMIN_TOTP_REQUIRED`, `LOCAL_TIMEZONE`, `APP_TITLE`, `OPERATOR_CONTACT`, `RETENTION_TEXT`, `CHAIR_LABEL`, `CURRENCY` (code and symbol), `UNDO_WINDOW_SECONDS`, `MAX_COFFEES_PER_SESSION_PER_HOUR`, `TRUSTED_PROXY_IPS`, `CSV_DELIMITER`, `CSV_DECIMAL_SEPARATOR`, `ADMIN_BOOTSTRAP_USERNAME`, `ADMIN_BOOTSTRAP_PASSWORD`. The price itself is data (set via CLI or admin page), not configuration.

## 12. Tests

Use pytest with a file-based SQLite database (not `:memory:`), so concurrency tests use real threads/connections. Include unit tests and integration tests for the full scan-to-ledger flow. At minimum:

- access gate: no code → no `/register`, `/profiles`, or profile search; wrong code rate-limited; correct code unlocks; browsers with a session scan without any code;
- registration without a pending coffee; registration after scanning single; after scanning double (event recorded exactly once, correct quantity and amount); double-submitting registration;
- existing-session single and double scans; GET performs no writes (assert row counts); repeated GETs create nothing;
- same request token replayed (same user and a different user) → one event; two scans with different tokens → two events; expired token rejected; refresh and Back after success;
- undo within window; after expiry; second undo; undo of someone else's event; undo of a reversal; concurrent undos → exactly one reversal;
- a user deactivated between page load and POST cannot record; merged profile cannot scan;
- profile selection on a "new browser"; session rotation; remove-this-browser; revocation by admin; profile editing; chair change audited;
- **prices:** event uses the price in effect at insert time; a later price change leaves earlier events untouched; a future-dated price is not used early and takes effect at its `effective_from`; reversal after a price change returns exactly the original amount; no price configured → nothing recorded and a safe message; backdated price rejected; price changes audited and global-only; adjustment pre-fills amount but accepts an override; money parsing accepts `12.50`/`12,50` and rejects `12.505`, negatives where invalid, and non-numbers;
- totals: shots consumed, amount consumed, amount paid, balance, negative balance (credit) consumed at later prices, totals after reversal and after merge (unchanged, no event moved);
- admin: payment entry, correction, adjustment, reversal; admin login with TOTP (wrong code, recovery code, rate limiting); a test that **enumerates every `/admin` route** and asserts it rejects anonymous callers, normal-user sessions, and out-of-scope chair admins, and allows in-scope admins; global admin sees all chairs;
- CSRF failure on user and admin forms; CSV export respects filters, neutralizes `=cmd|...` style names, and formats amounts per the configured decimal separator; name search ("muller" finds "Müller");
- DB constraints rejected directly via SQL (zero quantity, bad type/quantity combo, amount ≠ quantity × price, duplicate idempotency key, second reversal of one event, opposite-sign amount);
- production config: startup fails with http base URL, missing/weak `SECRET_KEY` or `ACCESS_CODE`; security headers and HSTS present;
- timezone boundaries for today/week/month; `check-ledger` detects seeded corruption (including a tampered amount);
- migrations: `alembic upgrade head` on an empty DB, `downgrade base`, upgrade again, and no diff between models and migrations (`alembic check`).

Add **one end-to-end browser test** (Playwright, headless Chromium) of: scan URL → auto-submit → access code → registration → success page → refresh → second scan without any prompt. If a browser is unavailable, mark it skipped and say so.

## 13. Deployment, operations, documentation

Provide: `Dockerfile` (non-root user, minimal image, healthcheck), `docker-compose.yml` (one app service, named volume for the database, environment from `.env`), `.env.example`, migrations run explicitly with `alembic upgrade head` (document the compose command; do not run migrations implicitly on every start unless guarded and documented), `GET /healthz` (process up) and `GET /readyz` (database reachable and migrated), stdout logging with level configuration, a reverse-proxy example (Caddy or nginx with TLS, HSTS, forwarded headers, `TRUSTED_PROXY_IPS`, optional IP restriction for `/admin`), firewall guidance, `scripts/backup.sh` (consistent SQLite backup via `sqlite3 .backup` or `VACUUM INTO`, with retention of N copies) and a documented restore procedure that you actually test, maintenance guidance (expired sessions and pending actions purge via `python -m app.cli purge-expired`; DB growth is small).

`README.md` covering: purpose; architecture; trust, access-gate and authentication model; money and price-history model; local development; production deployment; environment variables; migrations; creating the first admin (including TOTP enrollment); setting the first price; creating chairs; printing QR codes; backup and restore; security considerations; known limitations; upgrade procedure. Include this limitation verbatim: *"Normal-user identity is based on a long-lived browser session and voluntary profile selection. It does not cryptographically prove the user's real-world identity. This is intentional for a low-stakes, trust-based departmental coffee ledger."* Also document: no erasure tooling in v1, the shared access code and how to rotate it, the in-app-browser cookie-jar caveat, the single-process requirement, and the "Out of scope for v1" list as future improvements.

## 14. Definition of done

1. `docker compose up` starts the app; migrations run; `/readyz` is green. *(If Docker is unavailable, say so and verify with a local uvicorn run instead.)*
2. A global admin can be created from the CLI, enroll TOTP and log in; chairs can be created; a first price can be set.
3. A new user scanning either QR code can pass the access gate, register, and gets the intended coffee recorded exactly once at the current price; later scans from the same browser record a coffee with no prompt.
4. Single adds 1 shot and double adds 2 at the right amount; refresh/retry/Back never duplicates; an accidental entry can be undone via a reversal event and no history is deleted.
5. After a price change, new coffees use the new price and old entries keep theirs; undo of an old entry returns its original amount.
6. Admins can record payments in money; shots, amounts consumed, amounts paid, and balances are correct everywhere.
7. Chair admins cannot access other chairs; global admins can see all.
8. CSV export works and is formula-safe; QR codes can be generated and printed.
9. All automated tests pass, `alembic check` is clean, `check-ledger` passes on a seeded database, `pip-audit` has been run.
10. Production configuration exposes no debug information, requires HTTPS, and refuses insecure secrets.

## 15. Final report

End with: a concise architecture summary; the list of created files; exact commands for local startup, tests, production migration, creating the first admin, setting the first price, backup and restore; the verified/not-verified status of each Definition-of-Done item; remaining limitations and recommended future work.
