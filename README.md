# Coffee Ledger

A small, self-hosted web app that records coffee consumption and payments in a university department. People scan one of two permanent QR codes on the coffee machine (single = 1 shot, double = 2 shots); an administrator records the money they receive. It is a **trust-based ledger, not a payment processor**: the app never touches money, it only records that an administrator received it.

## Contents

1. [Architecture](#architecture)
2. [Trust, access gate and authentication model](#trust-access-gate-and-authentication-model)
3. [Money and price history](#money-and-price-history)
4. [Local development](#local-development)
5. [Production deployment](#production-deployment)
6. [Environment variables](#environment-variables)
7. [Migrations](#migrations)
8. [First administrator and TOTP](#first-administrator-and-totp)
9. [First price](#first-price)
10. [Chairs](#chairs)
11. [QR codes](#qr-codes)
12. [Day-to-day operations](#day-to-day-operations)
13. [Backup and restore](#backup-and-restore)
14. [Upgrade procedure](#upgrade-procedure)
15. [Security considerations](#security-considerations)
16. [Known limitations](#known-limitations)
17. [Out of scope for v1 (possible future work)](#out-of-scope-for-v1-possible-future-work)

## Architecture

One Python process (FastAPI + Jinja2 server-rendered pages, plain CSS, a few static JS files, no CDN) with one SQLite database in WAL mode, behind a TLS-terminating reverse proxy (Caddy or nginx).

```
phone ──https──> reverse proxy (TLS, HSTS, size limit) ──http──> uvicorn (1 worker) ── SQLite file (/data/coffee.db)
```

| Part | Where |
| --- | --- |
| Settings and production validation | `app/config.py` |
| Tables, constraints, ledger rules | `app/models.py`, `migrations/`, `app/services/` |
| User and admin web routes, templates, static files | `app/web/`, `templates/`, `static/` |
| Command line (admin, price, checks, QR codes) | `app/cli.py`, `app/cli_admin.py` |
| Container, scripts, proxy examples | `Dockerfile`, `docker-compose.yml`, `scripts/`, `deploy/` |

The ledger is append-only: consumption events, payment events, prices and the audit log are never edited or deleted (database triggers reject changes to the audit log; undo and corrections are new, compensating rows). Totals are always computed from the ledger, never stored.

Health endpoints: `GET /healthz` (process is up) and `GET /readyz` (database reachable **and** migrated to the current head).

## Trust, access gate and authentication model

- **Normal users have no passwords, no email, no notes.** A profile is a display name plus a chair. A browser becomes "that person" through a random 256-bit session cookie (`coffee_session`, HttpOnly, Secure, SameSite=Lax, 180 days by default). Only the SHA-256 hash of the token is stored.
- **Department access code.** Because the app is reachable from the internet, nobody can create or select a profile (or even list profiles) without the shared `ACCESS_CODE`. It is entered once per browser on `/join`; a correct code unlocks `/register` and `/profiles` for one hour. A browser that already has a valid session never needs it. The QR codes never contain the code; print it on a sign next to them or hand it out some other way. Wrong attempts are rate-limited (10 per 15 minutes per IP).
- **Rotating the access code:** edit `ACCESS_CODE` in `.env`, then `docker compose up -d --force-recreate`. Existing user sessions keep working; only new registrations and profile selections need the new code. Rotate it when somebody who should not have it learns it.
- **Administrators** are created only from the command line. They log in with username + password (Argon2id, at least 12 characters) and a TOTP second factor (required while `ADMIN_TOTP_REQUIRED=true`, the production default), with 8 single-use recovery codes. Admin sessions use a separate cookie (`coffee_admin`, `Path=/admin`, 12 hours by default). Login failures (password and TOTP) are rate-limited in the database. There are two roles: `global` (everything) and `chair` (only users currently in their assigned chairs; no merging, no chair changes, no price or chair management).
- Every administrative action is written to the append-only audit log.

> Normal-user identity is based on a long-lived browser session and voluntary profile selection. It does not cryptographically prove the user's real-world identity. This is intentional for a low-stakes, trust-based departmental coffee ledger.

## Money and price history

- All amounts are **integer cents** in one configurable currency (`CURRENCY`, default `EUR`). No floats are used for money. Input such as `12.50` or `12,50` is accepted; more than two decimals is rejected.
- The price is **data, not configuration**. Prices are an append-only history: each row has an `effective_from` time, and the price in effect at time *t* is the row with the greatest `effective_from <= t`. A price cannot be backdated; a wrong price is corrected by adding a new one. Only global administrators can add prices (admin page or CLI).
- Every consumption event stores a **snapshot** of the unit price used, so a price change never alters past amounts. A double is always 2 x the per-shot price. Undo copies the original's quantity and price snapshot, negated, so it returns exactly the original amount even after a price change.
- Payments are recorded in **money** (not shots), because the price varies over time. `balance = consumed amount - paid amount`: positive means the user owes, negative is shown as credit. Credit is consumed at the snapshot price of each later coffee; there is no conversion between shots and money.
- If no price is in effect, scans record nothing and show a "not configured yet" page; the app never falls back to zero.

## Local development

Python 3.12 or newer.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
# edit .env for local use: ENVIRONMENT=development, PUBLIC_BASE_URL=http://localhost:8000,
# DATABASE_URL=sqlite:///./data/coffee.db (secrets may stay as they are in development)
mkdir -p data
alembic upgrade head
python -m app.cli set-price --cents 50
uvicorn app.main:app --port 8000
```

`ENVIRONMENT=development` allows an `http://` base URL and built-in development secrets. Create a chair at `/admin/chairs` (after `python -m app.cli create-admin --username me --role global`), then open `http://localhost:8000/coffee/single`.

Tests (file-based SQLite, no external services):

```bash
python -m pytest -q
```

The end-to-end browser test needs Chromium (`playwright install chromium`); it is skipped when no browser can be launched. Dependency audit: `pip-audit -r requirements.txt`.

## Production deployment

Requirements: a Linux host with Docker Compose, a DNS name, ports 80/443 reachable, and a reverse proxy on the host.

### 1. Configure

```bash
git clone <repository-url> coffee-ledger && cd coffee-ledger
cp .env.example .env
python3 -c "import secrets; print(secrets.token_urlsafe(48))"   # use as SECRET_KEY
chmod 600 .env
```

Edit `.env`: set `PUBLIC_BASE_URL` (https), `SECRET_KEY`, `ACCESS_CODE`, `OPERATOR_CONTACT` and `TRUSTED_PROXY_IPS` (see step 4). In production the app **refuses to start** when `PUBLIC_BASE_URL` is not https or when `SECRET_KEY` / `ACCESS_CODE` are missing, too short (32 / 8 characters) or still placeholders. `ENVIRONMENT=production` also enables HSTS and Secure cookies and disables the API docs.

### 2. Build, migrate, start

```bash
mkdir -p backups && sudo chown 10001 backups      # backup directory, writable by the container user
docker compose build
docker compose run --rm app alembic upgrade head   # explicit migration step; never run implicitly
docker compose up -d
curl -fsS http://127.0.0.1:8000/readyz            # {"status":"ok","check":"ok"}
```

The compose file runs **one** `app` service with a named volume `coffee_data` (database at `/data/coffee.db`), `env_file: .env`, `restart: unless-stopped`, and publishes the port on `127.0.0.1:8000` only, so only the local proxy can reach it. The image runs as a non-root user, runs a single uvicorn worker with `--proxy-headers`, and has a `HEALTHCHECK` on `/healthz`.

### 3. Reverse proxy and TLS

Use `deploy/Caddyfile` (automatic certificates) or `deploy/nginx.conf` + `deploy/nginx-proxy.conf` (certificates e.g. from certbot). Both: redirect to https, HSTS, request body limit of 64 KiB, `Host` forwarded unchanged (the app compares it with the `Origin` of form posts), `X-Forwarded-For` **overwritten** with the connecting address, no caching of dynamic pages, and an optional IP allowlist for `/admin`.

```bash
sudo cp deploy/Caddyfile /etc/caddy/Caddyfile      # edit the host name first
sudo systemctl reload caddy
```

**Restrict `/admin` to department or VPN addresses** by uncommenting the allowlist block in the proxy example. Passwords + TOTP protect the admin area, but there is no reason to expose its login page to the whole internet.

### 4. Trusted proxy addresses

`TRUSTED_PROXY_IPS` is a comma-separated list of IPs or CIDR networks. The application (and uvicorn) believe `X-Forwarded-For` only from those peers; the client IP is used for rate limits and the audit log. With a proxy on the host and the port published on the loopback interface, the container sees the Docker bridge gateway as the peer, not `127.0.0.1`:

```bash
docker network inspect "$(basename "$PWD")_default" --format '{{ (index .IPAM.Config 0).Subnet }}'
```

Put that subnet (for example `172.18.0.0/16`) into `TRUSTED_PROXY_IPS`, then `docker compose up -d`. Leave it empty if nothing proxies in front. To check it: fail one admin login and confirm the audit log shows your address as the source IP, not a `172.x` address.

### 5. Firewall

Allow only SSH, 80 and 443 inbound (for example `ufw allow OpenSSH && ufw allow 80,443/tcp && ufw enable`). Do not publish port 8000 on a public interface; Docker's published ports bypass `ufw` rules, which is why the compose file binds to `127.0.0.1`.

### 6. Check the instance

```bash
ACCESS_CODE='<your access code>' scripts/smoke.sh https://coffee.example.org
```

`scripts/smoke.sh --health-only URL` checks only health and headers. The full run needs a chair and a price (steps below) and **writes to the ledger**: it registers a profile named "Smoke Test <timestamp>", records a single and a double, replays a POST, and undoes what the undo window allows. Deactivate that profile afterwards in `/admin/users`.

### Without Docker

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
set -a; . ./.env; set +a
.venv/bin/alembic upgrade head
sh scripts/run.sh          # one uvicorn worker; run it under systemd or similar
```

Set `DATABASE_URL=sqlite:////var/lib/coffee/coffee.db` (absolute path, four slashes) and make the directory writable by the service user. The scripts in `scripts/` accept `DB_PATH=/var/lib/coffee/coffee.db` for the same file.

## Environment variables

Set in `.env` (see `.env.example`, which documents each one). Defaults are the application's.

| Variable | Default | Meaning |
| --- | --- | --- |
| `ENVIRONMENT` | `development` | `production` enforces https, secure cookies, HSTS, hides API docs |
| `PUBLIC_BASE_URL` | `http://localhost:8000` | public address; content of the QR codes; https in production |
| `DATABASE_URL` | `sqlite:///./data/coffee.db` | SQLite only; Compose forces `sqlite:////data/coffee.db` |
| `SECRET_KEY` | dev value | signs tokens and cookies; random, >= 32 characters in production |
| `ACCESS_CODE` | dev value | department access code, >= 8 characters in production |
| `TRUSTED_PROXY_IPS` | empty | IPs/CIDRs whose `X-Forwarded-*` are trusted |
| `SESSION_LIFETIME_DAYS` | `180` | user browser session lifetime |
| `ADMIN_SESSION_HOURS` | `12` | admin session lifetime |
| `ADMIN_TOTP_REQUIRED` | `true` | require TOTP for admins |
| `ADMIN_BOOTSTRAP_USERNAME`, `ADMIN_BOOTSTRAP_PASSWORD` | empty | creates the first global admin at start, ignored once any admin exists |
| `LOCAL_TIMEZONE` | `Europe/Berlin` | display and day/week/month boundaries (weeks start Monday) |
| `APP_TITLE` | `Coffee Ledger` | page title |
| `OPERATOR_CONTACT` | empty | shown on `/privacy` |
| `RETENTION_TEXT` | built-in sentence | retention statement on `/privacy` |
| `CHAIR_LABEL` | `Chair` | what chairs are called, e.g. `Coffee group` |
| `CURRENCY` | `EUR` | code, optionally `:` and a symbol, e.g. `EUR:€` |
| `UNDO_WINDOW_SECONDS` | `300` | how long the latest coffee can be undone |
| `MAX_COFFEES_PER_SESSION_PER_HOUR` | `30` | guard against accidental scan loops |
| `CSV_DELIMITER` | `;` | CSV delimiter (German Excel) |
| `CSV_DECIMAL_SEPARATOR` | `,` | `,` or `.` |
| `LOG_LEVEL` | `INFO` | stdout logging level |
| `BACKUP_HOST_DIR` | `./backups` | Compose only: host directory mounted at `/backups` |

## Migrations

Migrations run **explicitly**, never at container start:

```bash
docker compose run --rm app alembic upgrade head
```

`/readyz` returns 503 (`"check":"migrations"`) while the database is behind the code. Only one Alembic head exists; do not downgrade a production database except from a backup.

## First administrator and TOTP

Admin accounts exist only through the command line (or the one-time bootstrap). Prompts ask for the password twice (at least 12 characters):

```bash
docker compose run --rm app python -m app.cli create-admin --username alice --role global
# chair administrators: --role chair --chair SHORT [--chair SHORT ...]  (short names of existing chairs)
docker compose run --rm app python -m app.cli list-admins
```

Alternative for the very first start: set `ADMIN_BOOTSTRAP_USERNAME` and `ADMIN_BOOTSTRAP_PASSWORD` (>= 12 characters) in `.env`. The app creates that global admin at startup while no administrator exists (also available as `python -m app.cli bootstrap-admin`) and ignores the variables afterwards; remove both lines from `.env` once it worked.

**TOTP enrollment happens at the first login** at `https://<host>/admin/login`: after the password the page shows a QR code/secret for an authenticator app, you enter a code, and 8 single-use recovery codes are shown once (store them safely). **Enroll immediately after creating the account**: whoever knows the password first can enroll the second factor.

Management commands: `set-admin-chairs --username U --chair SHORT ...`, `reset-admin-password --username U` (revokes the admin's sessions), `reset-admin-totp --username U` (the admin enrolls again at the next login; use for a lost phone with no recovery codes), `disable-admin --username U [--enable]`. All are audited. Passwords are never taken from the command line; `--password-stdin` is available for scripting.

## First price

Nothing can be recorded until a price exists.

```bash
docker compose run --rm app python -m app.cli set-price --cents 50
docker compose run --rm app python -m app.cli set-price --cents 60 --from 2027-01-01T00:00   # scheduled change
```

`--from` is an ISO 8601 date/time (no offset means local time) and cannot be in the past. Global admins can do the same in the admin area under Prices, which also shows the full history.

## Chairs

Chairs (research groups; the label is `CHAIR_LABEL`) are created by a global admin in the admin area under Chairs (`/admin/chairs`; there is no CLI command). Chairs with users or events are never deleted, only deactivated. Registration offers active chairs only. Create at least one before users register.

## QR codes

The admin area has a QR page (`/admin/qr`) that shows both URLs and the current price and produces printable SVG codes (one per half page, large "SINGLE" / "DOUBLE" labels, optional free-text line such as "Access code: ...", which is **not stored**). The codes contain only `{PUBLIC_BASE_URL}/coffee/single` and `/coffee/double`. From the command line:

```bash
docker compose run --rm app python -m app.cli qr --out /backups/qr    # appears in ./backups/qr on the host
```

The URLs come from `PUBLIC_BASE_URL`; reprint if it changes.

## Day-to-day operations

- **Logs:** stdout (`docker compose logs -f app`), level via `LOG_LEVEL`.
- **Purge expired sessions, pending scans and rate-limit rows** (database growth is small; weekly is plenty), for example from cron:
  ```bash
  docker compose run --rm app python -m app.cli purge-expired
  ```
- **Check ledger integrity** (exit code 1 on problems; also useful after a restore):
  ```bash
  docker compose run --rm app python -m app.cli check-ledger
  ```
- **CSV exports** (users with balances, ledger by date range and chair) are in the admin area; they are formula-injection safe and audited.
- **Merging duplicate profiles, payments, corrections, reversals, deactivation:** admin area, user detail page. Merging never moves or edits ledger events.

## Backup and restore

`scripts/backup.sh` makes a consistent online copy with SQLite's backup API (the mechanism behind `sqlite3 .backup`; it needs only the Python standard library, so it runs inside the image where no `sqlite3` binary exists). It is safe while the app runs, verifies the copy (`PRAGMA integrity_check`, foreign keys, expected tables), writes `coffee-<UTC timestamp>.db` with mode 600, and keeps the newest `BACKUP_KEEP` (default 14).

```bash
docker compose exec -T app scripts/backup.sh          # writes to /backups = ./backups on the host
```

Nightly from cron (`crontab -e`), plus a copy off the machine, because backups on the same disk do not survive its loss:

```cron
17 3 * * * cd /opt/coffee-ledger && docker compose exec -T app scripts/backup.sh >> /var/log/coffee-backup.log 2>&1
47 3 * * * rsync -a --delete /opt/coffee-ledger/backups/ backup-host:/srv/coffee-ledger-backups/
```

Without Docker: `DB_PATH=/var/lib/coffee/coffee.db scripts/backup.sh /var/backups/coffee`.

**Restore** (the app must be stopped; the script refuses to run while another process has the database open, verifies the backup first, and keeps the replaced database as `pre-restore-<timestamp>.db` next to the backups):

```bash
docker compose stop app
ls backups/                                            # pick a file
docker compose run --rm --no-deps app scripts/restore.sh /backups/coffee-20270101T031700Z.db --yes
docker compose run --rm app python -m app.cli check-ledger
docker compose up -d
curl -fsS http://127.0.0.1:8000/readyz
```

If the backup came from an older version, run `docker compose run --rm app alembic upgrade head` before `up -d`. Everything recorded after the backup is lost; users can simply scan again.

**Test your restore** once on a copy (for example in a scratch directory with `DB_PATH=/tmp/test.db scripts/restore.sh <backup> --yes`) so you know it works before you need it.

## Upgrade procedure

```bash
docker compose exec -T app scripts/backup.sh              # 1. backup
git pull                                                   # 2. new code
docker compose build                                       # 3. new image
docker compose stop app                                    # 4. brief downtime avoids old code on a new schema
docker compose run --rm app alembic upgrade head           # 5. migrate explicitly
docker compose up -d                                       # 6. start
curl -fsS http://127.0.0.1:8000/readyz                     # 7. ready?
ACCESS_CODE='...' scripts/smoke.sh https://coffee.example.org   # 8. optional full check (writes a test profile)
```

Read the release notes and `.env.example` for new variables first. If something goes wrong, restore the backup from step 1 and start the previous image.

## Security considerations

- HTTPS only in production (startup refuses otherwise), HSTS, Secure/HttpOnly/SameSite cookies, strict CSP (`default-src 'self'`, no inline scripts or styles, `frame-ancestors 'none'`), `X-Content-Type-Options`, `Referrer-Policy: same-origin`, request size limit (64 KiB, also at the proxy), no stack traces and no API docs in production, redirects only to fixed internal paths.
- CSRF protection on every state-changing form, signed one-time scan tokens, `Sec-Fetch-Site`/`Origin` checks; scanning never changes state on GET.
- Rate limits, stored in the database (so restarts do not reset them): access code, registration, profile search, admin login (password and TOTP).
- No external services, CDNs, fonts, trackers or analytics.
- Secrets live only in `.env` (mode 600, not in the image or the repository); the access code, tokens, passwords and TOTP secrets are never logged.
- Keep the host patched, the proxy as the only public listener, `/admin` restricted by IP where possible, and backups readable only by the operator (they contain every name and balance).
- Dependencies: run `pip-audit -r requirements.txt` before each release.

## Known limitations

- Normal-user identity is based on a long-lived browser session and voluntary profile selection. It does not cryptographically prove the user's real-world identity. This is intentional for a low-stakes, trust-based departmental coffee ledger.
- **Single process:** run exactly one app process (one uvicorn worker, one container). Rate limiting, SQLite's single write lock and the session/gate handling assume it. Do not scale out and do not raise `--workers`.
- **Cookie jars:** phone cameras, in-app QR scanners and home-screen web apps may use a different cookie jar than the browser where the user registered, so the scan looks like a new browser. The recovery path is "use existing profile" on `/join` (access code, search, select), which is meant to be quick.
- **Shared access code:** anyone who knows it can create profiles or select someone else's profile. Choosing another person's profile books coffee to them; this is the accepted trust model.
- **No erasure tooling in v1.** Deactivating a profile is the only removal mechanism; ledger rows and the audit log are append-only and are not deleted or anonymized. The `/privacy` page states that profiles can only be deactivated and ledger entries are not deleted.
- SQLite on one server; no high availability. Back up regularly and copy backups off the machine.
- Bad shared-cache or network filesystems (NFS, some cloud volume types) are not supported for the SQLite file; use a local disk.
- Docker, the compose file and the proxy examples were checked as described in `docs/status/ops.md`; verify them on your host with `scripts/smoke.sh`.

## Out of scope for v1 (possible future work)

Erasure or anonymization tooling, user email/notes, a public JSON API, API keys, passkeys, cached aggregates, per-user data export, PostgreSQL deployment, and separate prices for single and double (a double is always 2 x the per-shot price). None of these is built; the design (identity separate from the ledger, integer cents, immutable events) does not make them impossible.
