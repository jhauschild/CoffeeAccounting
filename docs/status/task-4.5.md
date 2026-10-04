# Task 4.5: CLI setup commands, mail status, four QR codes, dashboard tiles

Status: done. Commit "admin/cli: setup commands, mail status, four QR codes, dashboard tiles (task 4.5)".
Full suite incl. e2e: 1791 passed, 4 skipped (OpenCV decode tests, cv2/cairosvg not installed), 0 failed, 0 errors (baseline 1728).
63 new tests: `tests/test_admin_setup_cli.py` (39), `tests/test_admin_mail_qr.py` (29 incl. 4 skipped); QR assertions in `test_admin_views.py`, `test_admin_stats_exports.py`, `test_admin_cli.py` updated from two codes to four.

## What changed
- `app/cli_setup.py` (new, registered from `cli_admin.register`): `setup-mail`, `mail-status`, `test-mail ADDRESS`, `clear-mail [--yes]`, `setup`.
  - `setup-mail`: first probes `SECRETS_DIR` (creates it 0700, creates and removes a temp file); on failure prints "SECRETS_DIR (...) is not writable ... see README", exit 1, BEFORE any prompt. Then `getpass` for username, password, repeat password (mismatch: exit 1, nothing stored). `--password-stdin` (scripted): first stdin line is the username unless `--username` is given, next line the password. There is NO `--password`; `allow_abbrev=False` on `setup-mail`, `create-admin`, `reset-admin-password` because argparse otherwise accepts `--password` as an abbreviation of `--password-stdin` (tested). Stores via `mail_credentials.save_credentials`; prints only the masked user; audit `mail.login_saved` (system actor, no metadata).
  - `mail-status`: `mail configured: yes, user c***@lrz.de` / `no (run setup-mail)` / `no (mail login unreadable: re-run setup-mail)`, backend (smtp: host:port, security), `last send OK`, `last failure: <category> at <time>`, and a `state:` line (ok / mail failing: X / cap reached / mail not configured). Exit 0; works without a migrated database (then "last send: unknown").
  - `test-mail`: builds a message (strings `admin.mail.test_*`), checks the login for smtp (unreadable and not-configured messages), sends through `mail.send_in_background` (same path as the server: caps, in-process status, persisted status). Failure prints `test mail failed: <category>. <hint>`, exit 1; invalid address exit 2.
  - `clear-mail`: confirmation prompt unless `--yes`; audit `mail.login_cleared`.
  - `setup`: five steps (head admin via the existing `cmd_create_admin` with hidden prompts, TOTP-at-first-login notice with the admin login URL, mail login, first price, optional test mail), each asks `[Y/n]` and is skippable; defaults flip to "no" when an admin, login or price already exists. A failed step is reported, the run continues, exit 1 and "Not completed: ..." at the end. EOF on stdin exits with "run in an interactive terminal".
- `app/services/mail_status.py` (new): cross-process status, `card(db)` for page and CLI, `persist/record/read_status`.
- `app/services/mail.py`: `send_in_background` now ends with `mail_status.record(category)` (the old body moved to `_send_and_record`, unchanged). Nothing else in mail.py changed.
- `app/services/stats.py`: `head_tiles(db, admin)` (requires global admin) = held by groups (sum of `groups.list_group_balances` held_cents) + mail card. `app/web/admin_users.py` dashboard passes `tiles` only for the head admin; `templates/admin/dashboard.html` renders banner, mail card and "Held by groups" tile with a link to `/admin/groups` (negative total shows the 4.4 badge, no minus sign).
- QR: `exports.qr_urls()` now returns register, single, double, website (`QR_PATHS`), `write_qr_files` writes `coffee-<kind>.svg` for all four, `/admin/qr` shows four sheets and four downloads (`/admin/qr/{kind}.svg`, every administrator), price printed on single/double only, print CSS puts two sheets on a page (sheet 3 starts a new page). Free-text line unchanged: escaped, never stored or logged. No "access code" wording remains in admin strings/templates (test).
- Strings: `admin.mail.*`, `admin.dash.held*`, `admin.qr.label_register/website`, new `admin.qr.only_urls`. README: "Mail login" section, guided `setup`, four-code QR section, `docker compose run --rm -it app python -m app.cli setup-mail`.

## Decision: how the last send status crosses processes
The server and the CLI are different processes and `mail.get_status()` is per process. `send_in_background` (the only production send path, also used by `test-mail`) persists the result after the send in its own short write session, as audit rows with the system actor and no PII:
- `mail.send_failed`, metadata `{"category": "<one of mail.CATEGORIES>"}` only (unknown values become `other`; no address, host, text or login);
- `mail.send_ok`, no metadata.
Coalescing: a row is skipped when the latest mail row is the same kind (same category for a failure) and younger than 10 minutes, so at most one `mail.send_ok` per 10 minutes and a failure storm (anonymous registrations during an outage or after the cap) writes a row per category per 10 minutes. Any state flip is written immediately, so state is never wrong; timestamps can be up to 10 minutes stale. Persisting never raises into a send (logged as "mail status not persisted"). `mail_status.read_status(db)` returns a `mail.MailStatus` (so `.cap_reached` works), read by `mail-status` and the dashboard. `send_mail(db, ...)` (caller's session) is not persisted (no production caller; opening a second write session there would deadlock on the SQLite lock).
Retention: audit rows are append-only; they are few (see above).

## Later tasks must know
- 6.1 (README/ops): README sections edited here: "First administrator and TOTP" (guided setup paragraph), new "Mail login", "QR codes". `tests/test_ops_scripts.py` still passes against them. Compose must mount the `secrets` volume writable for the app user, otherwise `setup-mail` refuses by design.
- 7.1 e2e: the dashboard for the head admin has `id="mail-card-title"` and `id="held-tile-title"` sections; QR sheets carry `data-qr="register|single|double|website"`.
- Tests that count `audit_log` rows after a background send will now see `mail.send_ok`/`mail.send_failed` rows (none broke in the suite).
- `purge-expired` unchanged.
- Edits outside the ownership list (minimal): `app/services/mail.py` (`send_in_background` hook + docstring), `README.md` sections above.
- Known-broken tests: none.
