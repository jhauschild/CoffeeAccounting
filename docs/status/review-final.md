# Final audit of coffee-ledger v2 (task 7.2)

Independent final auditor, fresh context. Code under audit: branch `v2` at `aa864a5` (tag `v2`), Python 3.13.16 venv.
No application code and no existing test was changed. Everything below was run by me; the scripts that produced it are in
`docs/status/repro/` and the new tests are `tests/test_audit_final_properties.py` and `tests/test_audit_final_scenarios.py`.

## 1. Result in one table

| Severity | Count | Titles |
|---|---|---|
| Critical | 0 | |
| High | 0 | |
| Medium | 1 | M1 Any signed-in user can stall scans for everyone: Argon2 runs inside the SQLite write transaction on every sign-in |
| Low | 3 | L1 Reversing a negative adjustment ends in an unhandled 500; L2 Shipped default `TRUSTED_PROXY_IPS` makes 20 failed sign-ins lock out every visitor; L3 Only direct dependencies are pinned; Docker image uses another Python minor than the one tested |

Definition of done (plan section 9): 9 of 10 VERIFIED, 1 NOT VERIFIED (item 9, the real `postout.lrz.de` server cannot be reached from here).
Production-configuration probe: 260 checks, 259 pass, the 1 failure is M1 (kept as a failing check on purpose, it is the reproduction).

## 2. Mechanical results (exact output)

### 2.1 Migrations (empty temp SQLite database, `scratchpad/mig/m.db`)

```
$ alembic upgrade head
INFO  [alembic.runtime.migration] Running upgrade  -> 0001, schema (v1 + v2 squashed): all tables, effective_users view, append-only triggers
exit=0
$ alembic downgrade base
INFO  [alembic.runtime.migration] Running downgrade 0001 -> , schema (v1 + v2 squashed): all tables, effective_users view, append-only triggers
exit=0
$ alembic upgrade head
INFO  [alembic.runtime.migration] Running upgrade  -> 0001, schema (v1 + v2 squashed): all tables, effective_users view, append-only triggers
exit=0
$ alembic check
No new upgrade operations detected.
exit=0
```
After `downgrade base` the database holds no table, view or trigger left over (checked with `select type,name from sqlite_master` on a second database).

### 2.2 pip-audit

```
$ pip-audit --version
pip-audit 2.10.1
$ pip-audit -r requirements.txt
No known vulnerabilities found
exit=0
```
The network was reachable for this tool (it queried the advisory service); the result is real, not skipped.

### 2.3 Docker

`docker` CLI 29.8.2 exists, the daemon does not (`failed to connect to the docker API at unix:///var/run/docker.sock`).
`cp .env.example .env` (plus `MAIL_FROM`), `docker compose config` -> exit 0 (file renders; ports bound to 127.0.0.1). **No image was built and no container was started; nothing here claims a build.** The temporary `.env` was deleted again.

### 2.4 Long scripted scenario, `check-ledger`, independent recomputation

`docs/status/repro/long_scenario.py DB --seed 7` (261 successful operations of 20 kinds, all through the services: 15 member registrations with confirmation, 7 guest registrations with sponsor approval, 7 promotions, 14 remittances, 68 scans, 14 undos, 11 adjustments, 26 cash payments, 8 paid-backs, 21 payment corrections, 4 remittance corrections, 5 admin reversals, set_balance, price changes, merges, deactivations, chair changes of non-admins, sponsor reassignment; plus forbidden operations that had to be refused: own chair change, own balance change, cross-chair payment, pay-back above credit, set_balance and remittance by a group admin, peer deactivation, second correction, over-correction, promoting a guest; every one was refused):
```
long_scenario exit=0
ok_total 261  unexpected []  must_refuse_but_succeeded []  check_ledger_ok True  problems []
events: consumption 98, payments 62, remittances 18, users 22, prices 8
$ python -m app.cli check-ledger
OK: 98 consumption events, 62 payment events, 22 users, 8 prices checked
NOTE former group admin member5 still holds 500 cents
NOTE group admin member9 has handed over 425 cents more than collected   (and 3 more NOTE lines, 6 paid-back notes)
check-ledger exit=0
```
Seeds 1 to 12 all: exit 0, 261 ok operations, `check-ledger` OK (events per seed between 90 and 107 consumption, 51 to 63 payments, 18 to 45 remittances).

`docs/status/repro/verify_scenario.py DB` recomputes totals, per-user balances, group collected / handed over / held and chair roll-ups with plain `sqlite3` (own merge walk, no application code) and compares them with the service functions, the HTML of `/admin/groups`, `/overview`, `/overview/chairs`, the three CSV exports, and the group admin scoping of `/admin/users` and the exports (a group admin sees only its own chair, 403 elsewhere). Seed 7: `"checks": 146, "failures": []`; seeds 1 to 12: 130 to 155 checks each, 0 failures.
These runs are also automated as `tests/test_audit_final_scenarios.py` (seeds 1 to 3 and the authorization matrix; 4 tests, 34 s).

### 2.5 Property test (task 2)

`tests/test_audit_final_properties.py`: 18 tests, 13.7 s. Hypothesis is not installed, so it uses seeded random sequences (16 seeds x 70 steps = 986 executed operations plus the refused ones; a failure names the seed and step). After each run, raw SQL recomputes: balance = consumed - paid for every effective user (paid counts both payment kinds); bookkeeping (`set_balance`) is never counted as collected; held = collected - remitted per group admin and per chair; corrections inherit collector, kind and chair from the corrected payment even after the person moved chairs; no consumption, payment, remittance, price or audit row is deleted or updated (a snapshot of every row survives unchanged, and SQL `UPDATE`/`DELETE` on all protected tables is rejected by the triggers); `check_ledger` stays clean.
Mutation check (copy of the repo, one change each): "correction takes the person's current chair" -> detected; "correction takes the recorder as collector" -> detected; "held off by one" -> detected; "bookkeeping counted in the cash-collected query" -> survived, and is an equivalent mutant (`collected()` also filters on a collector, and bookkeeping rows have none), not a gap.
Reversals in the generator only pick quantity > 0 events, because of L1.

### 2.6 Existing suite and browser tests

`python -m pytest -q` with my two new files: see section 2.7. Browser tests alone (`tests/test_e2e_*.py`, Chromium available, not skipped): `10 passed in 19.66s`.

### 2.7 Full suite

`python -m pytest -q -p no:cacheprovider` on the final tree, including my two new files (22 tests): `1922 passed, 4 skipped, 95 warnings in 284.89s (0:04:44)`, exit 0. The 4 skips come from the suite's own environment guards (`importorskip`/`skipif` for optional libraries, docker CLI, month-boundary guard); I did not run with `-rs`, so I cannot name them individually.

## 3. Findings (all reproduced)

### M1 (medium): Argon2 runs inside the SQLite write transaction, so one signed-in user can stall scans for everybody

- Where: `app/web/routes_user.py:189` opens `write_session()` (BEGIN IMMEDIATE) around `login.sign_in`; `app/services/login.py:74` (`verify_and_rehash`) and `:78` (`verify_dummy`) hash with Argon2id (production cost, about 0.2 s) while the single writer lock is held. Same pattern: `registration.py:233,391`, `recovery.py:151`, `account.py:51`. Failed sign-ins are capped (5 per name and address, 20 per address per 15 min) but successful ones are not limited at all. The admin login does it correctly (hash outside the lock).
- Scenario (reproduced five times, `docs/status/repro/prod_instance.py`, section "dos", production Argon2 parameters, uvicorn with the flags of `scripts/run.sh`, scan = GET token page + POST): a scan alone takes a median 0.012 s (max 0.019 s). While ONE client signs in over and over with its own valid password the same scan takes a median 0.76 s and up to 3.4 s; with 3 clients sign-ins start to fail with 503 (`database is locked` after the 5 s busy timeout) and with 6 clients scans reach 3.8 s; in 4 of the 5 runs at least one scan itself answered 503. Any person who can register (a TUM address or a sponsor) can do this with a one-line loop; it stops when the account is deactivated. Nothing is lost or corrupted (503 is fail-safe).
- Fix: verify the password hash before opening the write transaction (as `admin_auth.start_login` does) and take the lock only to record the result, and add a per-address cap on successful sign-ins.

### L1 (low): reversing a negative adjustment crashes with an unhandled `IntegrityError` (500)

- Where: `app/services/ledger.py:224` (`_make_reversal` negates the quantity) and `:308`; `migrations/versions/0001_initial_schema.py:229` (`ck_consumption_events_reversal_shape` requires reversal quantity < 0); `templates/admin/user_detail.html:166` still offers the button (`can_reverse`) for an adjustment of -2.
- Scenario (`docs/status/repro/repro_reverse_negative_adjustment.py`, exit 1 = reproduced): head admin books an adjustment of -2 shots, then presses Reverse. The step-up preview runs the action and fails: the page answers 500 "Something went wrong" (no stack trace in the body; the log has the traceback). Nothing is written; at service level `admin_reverse_event` raises `sqlalchemy.exc.IntegrityError`. Reversing a coffee, a positive adjustment, a reversal (refused with `Conflict`) or an already reversed event all behave correctly. Workaround: book the opposite adjustment.
- Fix: refuse `quantity <= 0` events in `admin_reverse_event` with a `ServiceError` and hide the button for them (the admin books +2 instead), or allow adjustment reversals by relaxing the check to `quantity <> 0`.

### L2 (low): with the shipped default `TRUSTED_PROXY_IPS` (empty) all visitors behind the proxy share one address, so 20 failed sign-ins lock everybody out

- Where: `.env.example` (`TRUSTED_PROXY_IPS=` empty), `app/web/deps.py:80-83` (`client_ip`), `scripts/run.sh` (uvicorn trusts only 127.0.0.1 by default). In the documented Docker deployment the container sees the bridge gateway as the peer, so `X-Forwarded-For` is ignored until the operator sets the list (README "Trusted proxy addresses" explains it and asks for a manual check; nothing warns when it is missing).
- Scenario (`docs/status/repro/repro_shared_ip_lockout.py`, exit 1 = reproduced): the same TCP peer sends 21 sign-ins with unknown usernames (the first 20 answer 401, the 21st 429); a different visitor then signs in with the CORRECT password and gets 429 for 15 minutes. The same shared bucket also swallows registration, reset and admin-login limits.
- Fix: in production log a loud warning (or refuse to start) when `TRUSTED_PROXY_IPS` is empty and the first request arrives with `X-Forwarded-For` from a private address, and preset `docker-compose.yml` with the bridge subnet.

### L3 (low): only the 13 direct dependencies are pinned, and the image uses another Python than the one tested

- Where: `requirements.txt` (13 lines, all `==`), `Dockerfile:2` (`FROM python:3.12-slim`, tag not a digest).
- Observed: the venv that every test, probe and `pip-audit` ran against is Python 3.13.16 with 77 installed packages; transitive ones that matter for security (`starlette==1.7.0`, `h11`, `httptools`, `pydantic`, `anyio`, `cffi`, `MarkupSafe`) are not in `requirements.txt`, so `docker build` resolves whatever is newest that day on a different interpreter minor. `pip-audit -r requirements.txt` is clean today (2.2); the build is not reproducible.
- Fix: generate a fully pinned, hashed lock file (`pip-compile --generate-hashes`) and install with `--require-hashes`; pin the base image by digest and run the test suite on the same Python minor as the image.

### Observations that are not findings (not defects, recorded so nobody re-investigates them)

- Anonymous `GET /overview*` writes one `pending_actions` row (return-to-page after sign-in), capped at 30 per 10 min per address and removed by `purge-expired`. Documented in README (weekly purge).
- CSV export downloads write one `audit_log` row (by design).
- A 70 KB request header is accepted by uvicorn itself (200); header size limits are the reverse proxy's job (Caddy and nginx examples limit them).
- `/static/*.css` carries `ETag` and `Last-Modified` but no `Cache-Control`.
- Plan DoD 3 reads "no admin screen assigns chairs". There is no chair assignment for admins any more (no `admin_chairs`, the promote button has no picker, a group admin's scope is its own chair). The head admin can still move a person to another chair (`POST /admin/users/{id}/chair`, head only, audited, no TOTP: plan A7 lists chair changes as a non-balance action). I read DoD 3 in that sense.
- Merging the account behind a group admin (`merge_group_admin.py`): the merge is accepted, the role row stays active, the account can no longer sign in, `check-ledger` stays OK, every page still renders (no 5xx) and the head admin can still record the remittance of the held money.
- When mail is down the registration page still says "check your mail" (known, plan item L7).

## 4. Authorization matrix (verified by `docs/status/repro/authz_matrix.py`: 76 method/path pairs enumerated from the live app, 748 probes, 0 mismatches)

The route list comes from the running application (OpenAPI paths plus `/healthz`, `/readyz`), and the script fails if a route has no policy entry or a policy entry has no route. Principals: anonymous; signed-in member (user cookie only); group admin (admin cookie; "own" = target in its chair, "foreign" = target in another chair); head admin. "denied" = 303 to the login page, or 403, and the database is byte-identical before and after.

| Route class (examples) | Anonymous | Member | Group admin | Head admin |
|---|---|---|---|---|
| Public: `/login`, `/register`, `/forgot`, `/privacy`, `/`, `/healthz`, `/readyz`, `GET /reset/{t}`, `GET /verify/{t}`, `/admin/login`, `GET /coffee/{kind}` | allowed | allowed | allowed | allowed |
| `POST /coffee/{kind}` (signed scan token) | parked to `/login`, no coffee; forged token 400 | books one coffee | same as member only with a user cookie | same |
| Member area: `/account*`, `POST /logout`, `/coffee/done`, `/coffee/undo`, `/overview*` | denied | allowed | denied (an admin cookie is not a user session) | denied |
| Any admin: `/admin`, `/admin/users`, user and ledger CSV, `/admin/exports`, `/admin/qr*`, `/admin/account*`, `/admin/stepup/confirm`, TOTP setup, admin logout | denied | denied (user cookie is not valid under `/admin`) | allowed, data scoped to own chair | allowed |
| Scoped person routes: `GET /admin/users/{id}`, payment, adjustment, reverse, rename, status, sessions/revoke | denied | denied | own: allowed, foreign: 403, unknown id: 404 | allowed |
| Head only: `/admin/groups`, remittances (+correct), group-balances CSV, chairs*, prices*, audit, admins, `balance` (set), `chair`, merge, sponsor, promote, demote | denied | denied | 403 | allowed |

Variants applied to every POST: valid CSRF token with a same-origin `Origin`; no token (403 or login redirect, nothing written); valid token with `Origin: https://evil.example` (403, nothing written). Further results: every `GET` or `HEAD` leaves the stored state unchanged (the only change allowed is the audit row of a CSV download); the first request on every balance-changing route (payment, adjustment, reverse, balance, merge, remittance, remittance correction) books nothing for the head admin (it only shows the confirm page); a user cookie does not open `/admin/users` (303), an admin cookie does not open `/overview` (303); positive controls on fresh data: group admin renames an own-chair person (303, changed), group admin renames a foreign person (403, unchanged), head admin renames any person (303, changed).
Route-level policy is also enforced in the services (the long scenario refuses a group admin acting on a foreign chair, on its own chair or its own balance, 4 of 4 each).

## 5. Definition of done (plan section 9) mapped to evidence I ran

| # | Item | Status | Evidence (my run) |
|---|---|---|---|
| 1 | Members register with username, password, verified TUM email, non-TUM refused; guests via sponsor approval by mail | VERIFIED | `prod_instance.py` over HTTPS with a real TLS SMTP server: member registration mails a link (https, `PUBLIC_BASE_URL`), GET shows a form and writes nothing, POST verifies and signs in, link is single-use; `someone@gmail.com` refused, no account, no mail; guest cannot sign in before approval, sponsor mail link offers approve and reject, POST approve works, then the guest signs in. `long_scenario.py`: 15 member and 7 guest registrations, 261 ok operations. |
| 2 | Recovery by username reaches the right inbox; each guest of one sponsor recovers only their own account | VERIFIED | Same run: member reset mail goes to the member's own address; for `guest1` the mail goes to the sponsor `alice@tum.de`; the link resets `guest1` only (`guest1` new password works, old fails, second guest `guest4` of the same sponsor keeps the old password and still signs in); link single-use, all sessions of the account revoked, password change revokes the linked admin session; forgot-password answers identically for known and unknown names. |
| 3 | One chair per person, no admin screen assigns chairs, group admin acts only in own chair | VERIFIED (reading in 3.4) | Matrix: group admin on foreign targets 403 for every scoped route; `prod_instance.py`: group admin cannot book for another chair, cannot set a balance, cannot remit; scenario refusals own_chair 4/4, cross_chair 4/4; no chair assignment for admins exists. The head admin can move a person (see "Observations"). |
| 4 | Register, Single, Double, Website each have a QR code; the registration QR never records a coffee | VERIFIED | `/admin/qr` lists the four targets (`/register`, `/coffee/single`, `/coffee/double`, `/overview`); opening each one anonymously and signed in leaves `consumption_events` unchanged; the only write path is `POST /coffee/{kind}` with a signed token. |
| 5 | Any verified signed-in user can open the site; no email, username, hash, note or IP on any page | VERIFIED | 12 site pages (`/overview`, chairs, people, prices and every person page) fetched as a member after planting emails, usernames, notes ("first payment", "ga cash", "opening balance") and client addresses: none appears; anonymous visits are redirected to sign-in. |
| 6 | Head admin can set every balance and record money from group admins; group balance shows collected, handed over, held and matches admin page and site | VERIFIED | Production-mode HTTP run: group admin books 12.00 cash, head records a 5.00 remittance, head sets a balance (bookkeeping entry), all through the step-up confirm; `/admin/groups` and `/overview/chairs` both show 12.00 / 5.00 / 7.00 for the chair. Plus `verify_scenario.py`: 130 to 155 independent comparisons per seed over 12 seeds, 0 differences. |
| 7 | Every balance-changing action requires TOTP inside the unlock window, nothing else asks for TOTP, nothing is written without it | VERIFIED | Production defaults: the confirm page asks for a code; no code, wrong code, tampered payload, replayed nonce and another session's payload all write nothing; a correct code books and opens the window, a second action inside it needs no code; 8 concurrent confirms book exactly once; wrong codes are rate limited (429 from the 6th); price change, rename, deactivation and chair change succeed without a code on a fresh session, all admin pages load without one; startup refuses `BALANCE_TOTP_REQUIRED=false` in production. |
| 8 | A scan shows debt or credit in words plus shots this month | VERIFIED | Receipt page text from the production run: "Credit: EUR 3.50 ... Shots this month 5 ...", wording keys `Outstanding:` / `Credit:` / `All settled`. |
| 9 | Mail through `postout.lrz.de` with verified TLS; login entered at setup, stored encrypted outside database and backups, in no log, page or backup | NOT VERIFIED | The real server is unreachable from this sandbox (`socket.create_connection(("postout.lrz.de", 587))` -> `OSError: Address family not supported by protocol`), so the TLS handshake with that host was not exercised; that remains the post-deployment mail checklist. What was verified locally: STARTTLS with certificate and host name verification against a TLS SMTP server using the stored (decrypted) login; an untrusted certificate is refused with category `tls`; a rejected login gives `auth`; server down gives `connect`. The planted mail password and `SECRET_KEY` appear in no log, no page, no mail, not in the database or its WAL, not in the backup made by `scripts/backup.sh` (mode 600), and the credential file `mail-login.enc` is Fernet ciphertext (0600, directory 0700). `mail_failure_probe.py`: failure paths print no secret. `.env.example` and `docker-compose.yml` default `SMTP_HOST` to `postout.lrz.de`. |
| 10 | Tests pass (incl. fake-SMTP tests), `alembic check` clean, `check-ledger` passes, `pip-audit` clean, e2e passes | VERIFIED | Sections 2.1 to 2.7: full suite result in 2.7, `alembic check` "No new upgrade operations detected.", `check-ledger` OK on 12 scenario databases, `pip-audit` "No known vulnerabilities found", e2e `10 passed`. |

## 6. Security review: checked and fine

Run against a real production-configuration instance (`prod_instance.py`: HTTPS with a self-signed certificate, uvicorn started like `scripts/run.sh`, planted `SECRET_KEY` and planted SMTP password, local TLS SMTP server); 260 checks.

- **Start-up validation**: production refuses to start with `BALANCE_TOTP_REQUIRED=false`, an `http` base URL, a short key, a placeholder key, the published dev key, the console mail backend or an empty `MAIL_FROM`; starts with a valid configuration.
- **Authentication and sessions**: wrong admin password 401 with generic text; sign-in with another letter case works; session id changes at sign-in (no fixation); logout revokes server-side (old cookie replayed -> 303); session cookies are stored only as hashes (no raw cookie value found in database, backup or log); login errors identical for wrong password and unknown user; forgot-password identical for known and unknown names; password reset revokes all sessions and is single-use; an un-enrolled admin is forced to TOTP setup; enrolment shows 8 recovery codes once; the enrolment itself opens the step-up window of that session only.
- **CSRF and Origin**: all 70 POST pairs of the matrix (no token, forged token, token of another session or scope, cross-site Origin, `Sec-Fetch-Site: cross-site`, null Origin, suffix-spoofed host) are refused with nothing written; `POST /coffee/{kind}` additionally needs a signed, expiring scan token; login forms use a cookie-bound token.
- **Cookies in production** (real TLS): `coffee_session`, `coffee_csrf`, `coffee_pending`, `coffee_admin`, `coffee_admin_login` are all `HttpOnly; Secure; SameSite=Lax`, admin cookies `Path=/admin`.
- **Headers and CSP**: on 48 page checks (anonymous pages, user pages, admin pages for head and group admin, receipts, error pages 403/404, CSV downloads, SVG download, static CSS): `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` (no inline script or style), `nosniff`, `Referrer-Policy: same-origin`, `X-Frame-Options: DENY`, COOP, Permissions-Policy, HSTS `max-age=31536000`, `Cache-Control: no-store` on every dynamic response, no `Server` banner, CSV as attachment, no CORS headers, preflight and TRACE refused.
- **FastAPI docs** `/docs`, `/redoc`, `/openapi.json`, `/docs/oauth2-redirect`: 404 in production.
- **Error pages**: 404, 403, 400, 401, 429, 503 and the 500 of L1 show no stack trace, class name or path; bad UUIDs, NUL bytes, bad percent escapes, a 20 kB URL, JSON bodies, invalid UTF-8: all 4xx, no 5xx. Fuzzing (`fuzz_and_race.py`): 4032 POSTs (every form field of every POST route x 42 hostile values, as head admin, group admin, member): 0 responses >= 500, 0 tracebacks, 0 unhandled errors in the log.
- **Request size**: a 70 KB form, a chunked 100 kB body without `Content-Length` and a 100 kB username are refused with 413.
- **Rate limits** (measured): member sign-in 6th failure 429; one address with many usernames 21st failure 429; registration 11th per address 429; forgot-password 4th per name 429; admin sign-in 6th failure 429; step-up code guesses 429 from the 6th; mail cap 30 per hour global and per recipient; concurrent registrations of one address never exceed the cap of 5 (8 threads: 5 pending, 3 refused). Note M1 and L2.
- **Races**: the same step-up confirm from 8 threads books exactly one payment; the same scan token from 8 threads books exactly one coffee.
- **Injection**: no raw SQL with user data anywhere in `app/` (only constants: `SELECT 1`, PRAGMAs, partial index predicates); two uses of `|safe` (QR SVG built from configuration and escaped labels); Jinja autoescape on; hostile names, notes and chair names (`<script>`, `"><img onerror>`, `{{7*7}}`, `${7*7}`, formula prefixes, CRLF) are accepted as data and appear HTML-escaped on all HTML pages (positive controls assert the escaped text is present); 42 reflected query parameters (`q`, `next`, `msg`, `err`, `notice`, `from`, `to`, `page`, ...) x 3 payloads on all pages: never echoed raw; `?next=` cannot redirect off-site; redirects use fixed internal paths.
- **CSV injection** in all three exports (users, ledger, group balances): every cell that starts with `=`, `+`, `-`, `@`, TAB or CR is prefixed with an apostrophe (positive control: `'=HYPERLINK`, `'@SUM(A1)`, `'=1+1`, `'+cmd` present), plain negative amounts are left alone.
- **Header injection**: CRLF in display name, sponsor address or email address never reaches mail headers or recipients; forged `Host`, `X-Forwarded-Host` and `X-Forwarded-Proto` do not change the links in mails (they use `PUBLIC_BASE_URL`); a forged cross-origin `Origin` on a form post is 403.
- **Secrets**: planted `SECRET_KEY`, SMTP password, head password and user password are absent from the application log (841 to 3000 lines), the SQLite file, WAL and SHM, the backup, the credential store, all 1000+ HTTP response bodies and all mails; one-time verify and reset tokens are absent from the log (the access log redacts them); the audit log holds no password, token or TOTP URI; repo grep (`git grep`, `rg`) finds no committed key, token or password (only `.env.example` placeholders, which production refuses); CLI output masks the user name (`s***`), prints no password; failing mail logins (rejected, untrusted certificate, server down) print only a category.
- **Backups**: `scripts/backup.sh` succeeds on the live database, file mode 0600, database only, no secrets directory.
- **Append-only**: SQL `UPDATE` and `DELETE` on `audit_log`, `consumption_events`, `payment_events`, `prices`, `group_remittances` are rejected by triggers (property test), and no code path in `app/` issues them.
- **Group admin hardening**: cannot change own chair, own balance, set balances, record remittances, deactivate a peer, promote guests; negative cash is capped to the person's credit (`PaybackExceedsCredit`), head admins may exceed it and it is flagged by `check-ledger`.
- **Client address handling**: IPv6 keyed by /64; `X-Forwarded-For` honoured only from trusted peers (L2 for the default).

## 7. Reproduction scripts and tests (all in this commit)

| File | What it does | Exit code |
|---|---|---|
| `docs/status/repro/long_scenario.py` | 200+ operation seeded scenario through the services, then `check-ledger` | 0 = all expectations met |
| `docs/status/repro/verify_scenario.py` | independent SQL recomputation vs services, admin pages, site pages, CSVs | 0 = no difference |
| `docs/status/repro/authz_matrix.py` | every route x 4 principals x CSRF variants | 0 = matrix holds |
| `docs/status/repro/prod_instance.py` | production-mode HTTPS instance, 260 checks, secret grep, M1 measurement | 1 today because of M1 only |
| `docs/status/repro/mail_failure_probe.py` | mail login/TLS failures leak nothing | 0 |
| `docs/status/repro/fuzz_and_race.py` | 4032 fuzzed POSTs, double-submit races | 0 |
| `docs/status/repro/merge_group_admin.py` | merging a group admin's account | 0 |
| `docs/status/repro/repro_reverse_negative_adjustment.py` | L1 | 1 = reproduced |
| `docs/status/repro/repro_shared_ip_lockout.py` | L2 | 1 = reproduced |
| `tests/test_audit_final_properties.py` | property test, 18 tests | passes |
| `tests/test_audit_final_scenarios.py` | scenarios and matrix as tests, 4 tests | passes |

Not verified by me: an actual `docker build` and `docker compose up` (no daemon), the real `postout.lrz.de` handshake (no route), behaviour behind the Caddy or nginx examples (not run), the app on the image's Python 3.12 (venv is 3.13).
