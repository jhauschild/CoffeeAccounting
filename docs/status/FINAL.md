# Coffee Ledger v2: handover for the operator

Date: 2026-10-04. Branch `v2`, acceptance run at commit `32bdd34` (details and evidence: `docs/ACCEPTANCE.md`). Full suite: **1952 passed, 4 skipped, 0 failed** (the 4 skips need `cairosvg`); e2e: 10 passed.

## What was built (the 7 packages of PLAN-v2 section 8)

1. **Core**: one squashed Alembic revision (`0001_initial_schema`), models, config, Argon2id passwords, key separation (HKDF), month shots, group balance and overview queries, authorisation by own chair.
2. **Platform**: mail service (smtp with verified TLS, console, memory, file backends, hourly cap), encrypted mail-login store, member registration and email verification, guest registration with sponsor approval, login, forgot/reset by username, rate limits.
3. **User pages**: register (member/guest), verify and approve pages, login, forgot/reset, scan result page (debt or credit in words plus shots this month), account page.
4. **Admin**: group admins and head admin login, TOTP enrolment, step-up confirm flow for every balance-changing action, role button, `/admin/groups` with remittances and set balance, sponsor reassign, mail status, QR page with four codes, CLI (`setup`, `setup-mail`, `mail-status`, `test-mail`, `clear-mail`, ...).
5. **Open site**: `/overview` (people, chairs, prices, person pages) for every signed-in account, with a crawl test that no private field leaks.
6. **Ops**: `.env.example` (no mail login in it), compose with a separate `secrets` volume, backup/restore scripts (database only), smoke script, hashed `requirements.lock`, README with the post-deployment mail checklist.
7. **Tests, audit, acceptance**: 1952 tests, Playwright e2e, ledger audit and security review (`docs/status/review-final.md`: 0 critical or high; the one medium and three lows were fixed in task F6), this acceptance run.

## Verified and not verified

| Verified by running it (details in `docs/ACCEPTANCE.md`) | NOT verified |
| --- | --- |
| All 10 DoD items on a development and a production instance (real TLS, TLS SMTP relay), with SQL cross-checks of every amount | **Docker**: no daemon here. `docker build`, `docker compose up`, the HEALTHCHECK, volume permissions: never run. `docker compose config` is valid |
| README commands: `setup`/`setup-mail` through a pty with hidden prompts, `mail-status`, `test-mail`, `clear-mail`, `create-admin`, `set-price`, `qr --out`, `check-ledger`, `purge-expired`, `alembic upgrade/downgrade/check`, `smoke.sh` in all three modes, backup and restore round trip | **The real `postout.lrz.de`**: TLS handshake, LRZ accepting the login and the From address, quota, spam handling (use the post-deployment checklist below) |
| The mail login is encrypted, outside the database and the backup, and in no log, page, mail or backup | Phone camera and in-app scanners, printing the QR codes (the four codes decode correctly from a Chromium rendering) |
| `alembic check` clean, `check-ledger` OK, `pip-audit -r requirements.lock` clean, e2e 10 passed | Caddy and nginx examples, firewall, cron lines, proxy log redaction in a real proxy; the lock file on the real `python:3.13-slim` image |

Defects found in the acceptance run: none blocking. Observations O1 to O9 are listed in `docs/ACCEPTANCE.md` (a load-sensitive timing test, `MAIL_FROM` display name ignored, and so on).

## First-time setup (exact commands)

On a Linux host with Docker Compose, a DNS name and a reverse proxy (see README "First-time setup" and "Production deployment").

```bash
git clone <repository-url> coffee-ledger && cd coffee-ledger && git checkout v2
cp .env.example .env && chmod 600 .env
python3 -c "import secrets; print(secrets.token_urlsafe(48))"      # paste as SECRET_KEY in .env
mkdir -p backups && sudo chown 10001 backups
# edit .env: PUBLIC_BASE_URL (https), SECRET_KEY, MAIL_FROM (the mailbox's address), OPERATOR_CONTACT, TRUSTED_PROXY_IPS
docker compose build
docker compose run --rm app alembic upgrade head
docker compose run --rm -it app python -m app.cli setup
docker compose up -d
curl -fsS http://127.0.0.1:8000/readyz                              # {"status":"ok","check":"ok"}
```

`setup` asks, step by step (each skippable): head admin (username, password twice, at least 12 characters), the mail login (`setup-mail`: SMTP username, password twice, all hidden), the first price, and an optional test mail. Each step is also a command of its own:

```bash
docker compose run --rm -it app python -m app.cli create-admin --username alice --role global
docker compose run --rm -it app python -m app.cli setup-mail
docker compose run --rm app python -m app.cli set-price --cents 50          # first price: nothing can be recorded before it
docker compose run --rm app python -m app.cli test-mail you@tum.de
docker compose run --rm app python -m app.cli mail-status
```

Then, in the browser:

1. `https://<host>/admin/login`: sign in as the head admin and **enrol TOTP immediately** (8 recovery codes are shown once; store them).
2. `/admin/chairs`: create the chairs (at least one before people register).
3. `/admin/qr`: print the four codes (Register, Single, Double, Website); or `docker compose run --rm app python -m app.cli qr --out /backups/qr` (files appear in `./backups/qr`).
4. Set `TRUSTED_PROXY_IPS` to the compose network's subnet (README "Trusted proxy addresses"); fail one admin login on purpose and check that the audit log shows your own address, not a `172.x` one.
5. Add the backup cron line from the README and copy backups off the machine.

## Post-deployment mail checklist (do it before announcing the site)

1. Ask TUM/LRZ whether automated mail from that mailbox is allowed and that `MAIL_FROM` matches the account; prefer a functional mailbox and an app password.
2. `docker compose run --rm -it app python -m app.cli setup-mail`.
3. `... test-mail <your TUM address>`.
4. Open the message, check `From` and `Auto-Submitted: auto-generated`, look in the spam folder.
5. Register a guest with your own address as sponsor and approve it.
6. Run a real password reset (`/forgot`) and use the link.
7. `... mail-status`: last send OK, no failure category; the dashboard card says the same.

If mails stop later: the head admin's dashboard banner and `mail-status` show the category (`auth` after a password change: re-run `setup-mail`; `tls`, `connect`, `recipient_rejected`, `timeout`, `cap_exceeded`; a "cap reached" banner means the hourly limit blocked sending, nothing is broken). A restore onto a new server needs `setup-mail` again (the mail login is deliberately not in backups; keep the same `SECRET_KEY`).

## First things to try with `docker compose up` (the Docker build was never run here)

1. `docker compose config` (valid here), then `docker compose build`: watch for `pip install --require-hashes` errors from `requirements.lock` (it was only installed on the local Python 3.13 venv); pin the base image by digest as the README says.
2. `docker compose up -d`, `docker compose ps` (healthy after the HEALTHCHECK on `/healthz`), `curl http://127.0.0.1:8000/readyz`, `docker compose logs app` (expect the `TRUSTED_PROXY_IPS is empty` warning until you set it).
3. Check the volumes: `docker compose exec app ls -ld /data /secrets /backups` (the app user must own `/data` and `/secrets`, `/secrets` mode 0700) and that `docker compose run --rm -it app python -m app.cli setup-mail` can write (it refuses with a clear message if not).
4. `scripts/smoke.sh --health-only https://<host>`, then the public run, then the signed-in run with a test account (it writes to the ledger; deactivate the account afterwards).
5. `docker compose exec -T app scripts/backup.sh`; check that `./backups` holds the database copy and **no** `mail-login.enc`.
6. Practise a restore on a copy (README "Backup and restore") before you need it.

## Resuming work

`docs/status/RESUME.md` is the protocol for a new session: clone the repo (branch `v2`), read `docs/status/TASKS.md` (all tasks done except 6.2, the real `docker compose up`, which is blocked on a Docker daemon) and `docs/V2-CONTRACT.md`, and take the next `todo` task. Hand-offs of every task are in `docs/status/task-*.md`, the audit in `docs/status/review-final.md`, acceptance scripts in `docs/status/repro/`. To finish task 6.2: run the section above on a machine with Docker, fix what breaks, mark 6.2 done in `TASKS.md`, update `docs/ACCEPTANCE.md` (Docker row) and `docs/PROGRESS.md`.

## Recommended future work

- Run the Docker build and the real mail checklist first (items above); then pin the base image by digest.
- Set `TRUSTED_PROXY_IPS` by default from the compose network, or fail start when a proxy header arrives from an untrusted private peer in production (L2 is only a warning today).
- Make `MAIL_FROM` honour a display name, or document that only the address is used (O2).
- Add `cairosvg` to `requirements-dev.txt` so the four QR-decode tests run; relax or retry the wall-clock test `test_wrong_password_and_unknown_user_hash_without_the_write_lock` on loaded CI machines (O1).
- Tell users when mail is down (the registration page still says "check your mail"), and consider a visible "mail broken" notice for the sponsor flow.
- Talk to the data protection contact about the open site before launch; consider an opt-out of the history pages for people who want to be shown by balance only.
- Not built on purpose (README "Out of scope"): erasure or anonymisation tooling, passkeys or SSO, balance reminder mails, self-service change of username or email, per-user data export, separate prices for single and double, PostgreSQL.
