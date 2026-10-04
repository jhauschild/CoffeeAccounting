# Coffee Ledger

A small, self-hosted web app that records coffee consumption and payments in a university department. People scan one of four permanent QR codes at the coffee machine (register, single = 1 shot, double = 2 shots, website); group admins and a head admin record the money they receive. It is a **trust-based ledger, not a payment processor**: the app never touches money, it only records that someone received it.

## Contents

1. [Purpose](#purpose)
2. [Architecture](#architecture)
3. [Trust and identity model](#trust-and-identity-model)
4. [Accounts, guests and sponsors](#accounts-guests-and-sponsors)
5. [Group admins, group balances and remittances](#group-admins-group-balances-and-remittances)
6. [Step-up TOTP](#step-up-totp)
7. [The open site and its privacy implications](#the-open-site-and-its-privacy-implications)
8. [QR codes](#qr-codes)
9. [Money and price model](#money-and-price-model)
10. [Local development](#local-development)
11. [Configuration](#configuration)
12. [First-time setup](#first-time-setup)
13. [Production deployment](#production-deployment)
14. [Mail login](#mail-login)
15. [Post-deployment mail checklist](#post-deployment-mail-checklist)
16. [Day-to-day operations](#day-to-day-operations)
17. [Backup and restore](#backup-and-restore)
18. [Proxy log redaction](#proxy-log-redaction)
19. [Upgrade notes](#upgrade-notes)
20. [Security considerations](#security-considerations)
21. [Known limitations](#known-limitations)
22. [Out of scope](#out-of-scope)

## Purpose

Members of a department scan a QR code each time they take a coffee. The app records the shot at the price in effect, shows the person what they owe, and lets group admins record cash they collect. The head admin sees the whole picture: who owes what, how much each group admin has collected and handed over, and can correct anything with a full audit trail. Every signed-in account can also read the open site (balances and history of everyone, see [the privacy section](#the-open-site-and-its-privacy-implications)).

## Architecture

One Python process (FastAPI + Jinja2 server-rendered pages, plain CSS, a few static JS files, no CDN) with one SQLite database in WAL mode, behind a TLS-terminating reverse proxy (Caddy or nginx). Mail goes out through one SMTP mailbox (default `postout.lrz.de`).

```
phone ──https──> reverse proxy (TLS, HSTS, size limit) ──http──> uvicorn (1 worker) ── SQLite file (/data/coffee.db)
                                                                      │
                                              /secrets/mail-login.enc (encrypted) ── smtp ──> postout.lrz.de
```

| Part | Where |
| --- | --- |
| Settings and production validation | `app/config.py` |
| Tables, constraints, ledger rules | `app/models.py`, `migrations/`, `app/services/` |
| User, site and admin web routes, templates, static files | `app/web/`, `templates/`, `static/` |
| Command line (admins, price, mail, checks, QR codes) | `app/cli.py`, `app/cli_admin.py`, `app/cli_setup.py` |
| Container, scripts, proxy examples | `Dockerfile`, `docker-compose.yml`, `scripts/`, `deploy/` |

The ledger is append-only: consumption events, payment events, prices, group remittances and the audit log are never edited or deleted (database triggers reject changes to the audit log; undo and corrections are new, compensating rows). Totals are always computed from the ledger, never stored. The module overview is in `docs/ARCHITECTURE.md`, the v2 rules in `docs/V2-CONTRACT.md`.

Health endpoints: `GET /healthz` (process is up) and `GET /readyz` (database reachable **and** migrated to the current head).

## Trust and identity model

> Identity is a verified TUM email (members) or a member's vouching (guests), plus a password. It does not prove the user's real-world identity. This is intentional for a low-stakes, trust-based departmental coffee ledger.

- A **member** is someone who confirmed a university email address (`ALLOWED_EMAIL_DOMAINS`, default `tum.de`, `mytum.de`, `*.tum.de`). A **guest** has no email of their own: a verified member, the **sponsor**, vouches for them.
- Sign-in is **username and password** at `/login` (Argon2id; one generic failure message; 5 failures per 15 minutes per username and IP, plus a per-IP cap, stored in the database). A browser stays signed in through a random 256-bit session cookie (`coffee_session`, HttpOnly, Secure, SameSite=Lax, 180 days by default); only its SHA-256 hash is stored. A lost cookie is replaced by signing in again.
- Administrators use a separate cookie (`coffee_admin`, `Path=/admin`, 12 hours by default). A user cookie alone never reaches `/admin`. Every administrative action goes to the append-only audit log.
- The email and the sponsor only prove membership; they say nothing about who is typing. Different TUM aliases of one person can create two accounts; admins can merge them.

## Accounts, guests and sponsors

- **Member registration** (`/register`): username, display name, chair, TUM email, password twice, privacy acknowledgement. A mail with `/verify/{token}` (valid 24 hours) goes to the address. Opening the link writes nothing (mail scanners prefetch links); the confirm button creates the account and signs the browser in. The page shown after the form is identical whether or not the address already has an account; an existing owner gets a mail saying so ("sign in or use Forgot password").
- **Guest registration**: username, display name, password and the **sponsor's email address** (a member's TUM address; there is no search and no member list). If the address belongs to a verified member, the sponsor receives a mail naming the guest and a link with **Approve** and **Reject** (valid 7 days, `GUEST_APPROVAL_TTL_DAYS`). The guest sees the same neutral page either way, so the form cannot be used to find out who is a member (the price of that: a mistyped sponsor address sends nothing). A guest inherits the sponsor's chair and cannot sign in before approval. At most 5 open requests per sponsor address, 3 per hour per IP. If a sponsor leaves, the head admin can assign a new sponsor (audited).
- **Chairs**: each person has exactly one chair (research group; the label is `CHAIR_LABEL`), chosen at registration. Chairs are created by the head admin under `/admin/chairs`; create at least one before people register.
- **Sign-in recovery**: `/forgot` takes the **username**. The mail goes to the member's own address or, for a guest, to the sponsor; it names the account, so a sponsor with several guests knows which one it is for. `/reset/{token}` (valid 1 hour, single use, only the hash is stored) sets a new password and signs the account out everywhere. Limits: 3 reset requests per hour per username, 10 per IP, 6 per recipient address.
- Passwords: 10 to 128 characters (`PASSWORD_MIN_LENGTH`), not equal to the username or the email's local part. Account page: change password, edit display name and chair (a group admin cannot change their own chair).
- If no mail login is stored, registration and recovery pages say "temporarily unavailable" instead of collecting data that cannot be verified.

## Group admins, group balances and remittances

- **Head admin**: the global administrator created on the command line. Can do everything, including setting any balance and recording money received from group admins. Has no user account, uses `/admin` directly.
- **Group admin**: a member promoted by the head admin (button on the member's page; guests cannot be promoted). The scope is the member's own chair: they see and book for the people of that chair only. They sign in at `/admin/login` with their account username and password. Demotion revokes their admin sessions; if they still hold group money they stay listed as "former group admin".
- **Cash and bookkeeping**: a payment recorded by an administrator is `cash` and counts as collected by that admin; money paid back is a negative cash payment. The head admin's "set balance" books the difference as a `bookkeeping` entry that is never counted as collected cash.
- **Group balance** per group admin: collected (cash payments they recorded) minus remittances (money the head admin recorded as received from them) = still held. A chair's figure adds up its group admins, grouped by the chair stored on each event at event time. Remittances are append-only; a mistake is corrected by a correction entry. A negative held amount (more handed over than collected) is allowed and flagged. The head admin sees this at `/admin/groups` (with CSV export) and on the dashboard tile "Held by groups"; the same numbers appear on the open site.
- A group admin cannot change their own balance, and cannot set balances or record remittances.

## Step-up TOTP

Every balance-changing action (payment, correction, adjustment, reversal, merge, set balance, remittance) goes through a read-only **confirm page** that shows person, amount and resulting balance, carries a signed payload and a one-time nonce, and only the confirm POST executes. While `BALANCE_TOTP_REQUIRED` is true (the production default) the confirm page asks for a TOTP or recovery code unless a step-up window is open. A correct code opens a fixed window (`STEPUP_WINDOW_SECONDS`, 300 s), so several payments in a row need one code. Nothing else asks for TOTP: price changes, deactivation, chair changes and role assignment do not. Replayed codes are rejected, a double submit books once, and the audit log records whether a fresh code or the open window authorised the action.

TOTP enrolment happens once, at the first admin login (QR code or secret, then 8 single-use recovery codes). Later logins need the password only. Enrol immediately after creating an account: whoever knows the password first can enrol the second factor.

## The open site and its privacy implications

`/overview` is a read-only, server-rendered site for **every signed-in account** (members and guests): totals, price history, per-chair summary, a people list with search and sorting, a page per person with their complete consumption and payment history, and per-chair group balances. Anonymous visitors are sent to `/login` and returned after signing in. Pages are `Cache-Control: private, no-store`.

**This means every signed-in account sees everyone's name, chair, balance, shots and full history, plus the names of the group admins and the group balances.** It never shows email addresses, usernames, password data, sessions, audit entries, IP addresses, notes or which admin recorded an entry (a crawl test seeds such values and checks every page). The registration form and `/privacy` say so, and the registration checkbox asks for acknowledgement.

Before you launch, talk to the department's data protection contact about this and about the retention text and operator contact on `/privacy` (`OPERATOR_CONTACT`, `RETENTION_TEXT`). This is not legal advice.

## QR codes

The admin area has a QR page (`/admin/qr`, every administrator) with four permanent codes, each a labeled printable SVG (two per printed page, large labels, an optional free-text line that is **not stored**): **REGISTER** `{PUBLIC_BASE_URL}/register`, **SINGLE** `/coffee/single`, **DOUBLE** `/coffee/double` and **WEBSITE** `/overview`. The codes contain only these addresses and no personal data. Scanning REGISTER never records a coffee. Scanning SINGLE or DOUBLE without a session stores the coffee for one hour and shows `/login` with a "Create account" link; after signing in it is recorded exactly once (a GET never writes). From the command line:

```bash
docker compose run --rm app python -m app.cli qr --out /backups/qr    # appears in ./backups/qr on the host
```

The URLs come from `PUBLIC_BASE_URL`; reprint if it changes.

## Money and price model

- All amounts are **integer cents** in one configurable currency (`CURRENCY`, default `EUR`). No floats are used for money. Input such as `12.50` or `12,50` is accepted; more than two decimals is rejected.
- The price is **data, not configuration**. Prices are an append-only history: each row has an `effective_from` time, and the price in effect at time *t* is the row with the greatest `effective_from <= t`. A price cannot be backdated; a wrong price is corrected by adding a new one. A price of 0 is accepted; coffees then record an amount of 0. Only the head admin can add prices (admin page or CLI).
- Every consumption event stores a **snapshot** of the unit price, so a price change never alters past amounts. A double is always 2 x the per-shot price. Undo copies the original's quantity and price snapshot, negated.
- Payments are recorded in **money** (not shots). `balance = consumed amount - paid amount` (both payment kinds count as paid). The interface says "You owe X" or "Credit X", never a minus sign. Credit is consumed at the snapshot price of each later coffee; there is no conversion between shots and money.
- If no price is in effect, scans record nothing and show a "not configured yet" page; the app never falls back to zero.
- "Shots this month" (scan result page, account, site) is the net number of shots in the current local calendar month (`LOCAL_TIMEZONE`); reversals net out.

## Local development

Python 3.12 or newer.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
# edit .env for local use: ENVIRONMENT=development, PUBLIC_BASE_URL=http://localhost:8000,
# DATABASE_URL=sqlite:///./data/coffee.db (secrets and mail may stay as they are in development)
mkdir -p data
alembic upgrade head
python -m app.cli set-price --cents 50
uvicorn app.main:app --port 8000
```

`ENVIRONMENT=development` allows an `http://` base URL, built-in development secrets and the `console` mail backend (mails are not sent; only recipient and subject are logged). For flows that need the mail link set `MAIL_BACKEND=file` and `MAIL_FILE_DIR=./mails` and open the `.eml` file written there. Create the first admin with `python -m app.cli create-admin --username me --role global`, then a chair at `/admin/chairs`.

Tests (file-based SQLite, no external services, no real mail):

```bash
python -m pytest -q
```

The end-to-end browser test needs Chromium (`playwright install chromium`); it is skipped when no browser can be launched. Dependency audit: `pip-audit -r requirements.txt`.

## Configuration

Set in `.env` (see `.env.example`, which documents each one). The defaults are the application's. **There is no setting for the mail login**: it is entered with `setup-mail` (see [Mail login](#mail-login)).

| Variable | Default | Meaning |
| --- | --- | --- |
| `ENVIRONMENT` | `development` | `production` enforces https, secure cookies, HSTS, the smtp mail backend and hides the API docs; Compose forces it |
| `PUBLIC_BASE_URL` | `http://localhost:8000` | public address; content of the QR codes and mailed links; https in production |
| `DATABASE_URL` | `sqlite:///./data/coffee.db` | SQLite only; Compose forces `sqlite:////data/coffee.db` |
| `SECRET_KEY` | dev value | signs tokens and cookies and derives the mail-login key; random, at least 32 characters in production; changing it makes the stored mail login unreadable (run `setup-mail` again) and invalidates admin recovery codes |
| `TRUSTED_PROXY_IPS` | empty | IPs/CIDRs whose `X-Forwarded-*` are trusted |
| `SESSION_LIFETIME_DAYS` | `180` | user browser session lifetime |
| `ADMIN_SESSION_HOURS` | `12` | admin session lifetime |
| `ADMIN_BOOTSTRAP_USERNAME`, `ADMIN_BOOTSTRAP_PASSWORD` | empty | creates the first head admin at start, ignored once any admin exists; `setup` is the preferred way |
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
| `MAIL_BACKEND` | `console` (dev), `smtp` (production) | `smtp`, `console`, `memory` or `file`; production requires `smtp` (Compose sets it) |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY` | `postout.lrz.de`, `587`, `starttls` | outgoing mail server; `starttls` with 587 or `ssl` with 465; certificate and host name are always verified, there is no plaintext fallback |
| `MAIL_FROM` | empty | sender address, must belong to the mailbox; required in production |
| `MAIL_FILE_DIR` | empty | target directory for `MAIL_BACKEND=file` (development and browser tests) |
| `SECRETS_DIR` | `/secrets` | directory of the encrypted mail login (the `secrets` volume) |
| `MAIL_MAX_PER_HOUR` | `30` | cap on outgoing mails per hour |
| `ALLOWED_EMAIL_DOMAINS` | `tum.de,mytum.de,*.tum.de` | email domains accepted for members; `*.tum.de` matches subdomains only |
| `VERIFICATION_TTL_HOURS` | `24` | validity of the email verification link |
| `GUEST_APPROVAL_TTL_DAYS` | `7` | how long a guest request waits for its sponsor |
| `RESET_TTL_MINUTES` | `60` | validity of a password reset link |
| `PASSWORD_MIN_LENGTH` | `10` | minimum user password length (maximum is 128); administrators created on the command line need 12 |
| `STEPUP_WINDOW_SECONDS` | `300` | validity of an admin step-up confirmation |
| `BALANCE_TOTP_REQUIRED` | `false` (dev), `true` (production) | require TOTP: admins must enrol once, and balance changes need a step-up |
| `ARGON2_TIME_COST`, `ARGON2_MEMORY_COST_KIB`, `ARGON2_PARALLELISM` | `3`, `65536`, `4` | Argon2id cost; keep the defaults in production (tests lower them) |
| `LOG_LEVEL` | `INFO` | stdout logging level |
| `BACKUP_HOST_DIR` | `./backups` | Compose only: host directory mounted at `/backups` |

In production the app **refuses to start** when `PUBLIC_BASE_URL` is not https, `SECRET_KEY` is missing, short or a placeholder, `MAIL_FROM` is not a real address, the mail backend is not `smtp`, or `SMTP_SECURITY` and `SMTP_PORT` do not match.

## First-time setup

On a Linux host with Docker Compose, a DNS name, ports 80/443 and a reverse proxy.

```bash
git clone <repository-url> coffee-ledger && cd coffee-ledger
cp .env.example .env
python3 -c "import secrets; print(secrets.token_urlsafe(48))"   # use as SECRET_KEY
chmod 600 .env
mkdir -p backups && sudo chown 10001 backups      # backup directory, writable by the container user
```

Edit `.env`: set `PUBLIC_BASE_URL` (https), `SECRET_KEY`, `MAIL_FROM`, `OPERATOR_CONTACT` and `TRUSTED_PROXY_IPS` (see [step 4 below](#4-trusted-proxy-addresses)). Then:

```bash
docker compose build
docker compose run --rm app alembic upgrade head           # explicit migration step; never run implicitly
docker compose run --rm -it app python -m app.cli setup    # guided: head admin, mail login, first price, test mail
docker compose up -d
curl -fsS http://127.0.0.1:8000/readyz                     # {"status":"ok","check":"ok"}
```

`python -m app.cli setup` walks through five steps, each skippable and each also a command of its own: the head administrator (`create-admin`, hidden password prompt, twice), a reminder that TOTP is enrolled at the first login, the mail login (`setup-mail`), the first price (`set-price`) and an optional test mail (`test-mail`). To run just the mail step later:

```bash
docker compose run --rm -it app python -m app.cli setup-mail
```

Then: sign in at `https://<host>/admin/login` and enrol TOTP immediately, create the chairs at `/admin/chairs`, print the four QR codes at `/admin/qr`, and work through the [post-deployment mail checklist](#post-deployment-mail-checklist) before announcing the site.

Alternative for the very first start: set `ADMIN_BOOTSTRAP_USERNAME` and `ADMIN_BOOTSTRAP_PASSWORD` (>= 12 characters) in `.env`; the app creates that head admin at startup while no administrator exists (also `python -m app.cli bootstrap-admin`) and ignores the variables afterwards; remove both lines once it worked.

Administrators are managed from the command line:

```bash
docker compose run --rm -it app python -m app.cli create-admin --username alice --role global
docker compose run --rm app python -m app.cli list-admins
```

Further commands: `reset-admin-password --username U` (command-line admins only; a group admin's password is the account password and is reset through `/forgot`), `reset-admin-totp --username U` (the admin enrols again; for a lost phone without recovery codes), `disable-admin --username U [--enable]`. All are audited. Passwords are never taken from the command line; `--password-stdin` exists for scripting. `create-admin` refuses a username that a user account holds, and registration refuses a username that a command-line admin holds.

First price (nothing can be recorded until one exists):

```bash
docker compose run --rm app python -m app.cli set-price --cents 50
docker compose run --rm app python -m app.cli set-price --cents 60 --from 2027-01-01T00:00   # scheduled change
```

`--from` is an ISO 8601 date/time (no offset means local time) and cannot be in the past.

## Production deployment

### 1. What Compose runs

One `app` service, **one** replica, with `env_file: .env`, `restart: unless-stopped`, the port published on `127.0.0.1:8000` only, no capabilities and `no-new-privileges`. Volumes:

| Volume | Mounted at | Contents |
| --- | --- | --- |
| `coffee_data` (named) | `/data` | the SQLite database |
| `secrets` (named) | `/secrets` | the encrypted mail login; mounted **only** into the app container; directory mode 0700 owned by the non-root app user (the Dockerfile creates it, the volume inherits it) |
| `./backups` (bind, `BACKUP_HOST_DIR`) | `/backups` | database backups written by `scripts/backup.sh` |

Compose passes `MAIL_BACKEND=smtp` and `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY`, `MAIL_FROM` from `.env`. No mail login appears in the compose file, `.env`, the Dockerfile or the image. The image runs as a non-root user, runs a single uvicorn worker with `--proxy-headers`, and has a `HEALTHCHECK` on `/healthz`. Validate the file with `docker compose config`.

### 2. Reverse proxy and TLS

Use `deploy/Caddyfile` (automatic certificates) or `deploy/nginx.conf` + `deploy/nginx-proxy.conf` (certificates e.g. from certbot). Both: redirect to https, HSTS, request body limit of 64 KiB, `Host` forwarded unchanged (the app compares it with the `Origin` of form posts), `X-Forwarded-For` **overwritten** with the connecting address, no caching of dynamic pages, redaction of one-time tokens in logs (see [Proxy log redaction](#proxy-log-redaction)) and an optional IP allowlist for `/admin`.

```bash
sudo cp deploy/Caddyfile /etc/caddy/Caddyfile      # edit the host name first
sudo systemctl reload caddy
```

**Restrict `/admin` to department or VPN addresses** by uncommenting the allowlist block in the proxy example. Passwords and TOTP protect the admin area, but there is no reason to expose its login page to the whole internet.

### 3. Firewall

Allow only SSH, 80 and 443 inbound (for example `ufw allow OpenSSH && ufw allow 80,443/tcp && ufw enable`). Do not publish port 8000 on a public interface; Docker's published ports bypass `ufw` rules, which is why the compose file binds to `127.0.0.1`.

### 4. Trusted proxy addresses

`TRUSTED_PROXY_IPS` is a comma-separated list of IPs or CIDR networks. The application (and uvicorn) believe `X-Forwarded-For` only from those peers; the client IP is used for rate limits and the audit log. With a proxy on the host and the port published on the loopback interface, the container sees the Docker bridge gateway as the peer, not `127.0.0.1`:

```bash
docker network inspect "$(basename "$PWD")_default" --format '{{ (index .IPAM.Config 0).Subnet }}'
```

Put that subnet (for example `172.18.0.0/16`) into `TRUSTED_PROXY_IPS`, then `docker compose up -d`. Leave it empty if nothing proxies in front. To check it: fail one admin login and confirm the audit log shows your address as the source IP, not a `172.x` address.

### 5. Check the instance

```bash
scripts/smoke.sh --health-only https://coffee.example.org     # /healthz, /readyz, security headers, HSTS; writes nothing
scripts/smoke.sh https://coffee.example.org                   # adds /register, /login, anonymous /overview, /coffee/single
SMOKE_USERNAME='<test account>' SMOKE_PASSWORD='<its password>' scripts/smoke.sh https://coffee.example.org
```

The public run checks that `/register` and `/login` answer 200, that an anonymous `/overview` redirects to `/login` with `Cache-Control: no-store`, that a GET of `/coffee/single` sets no cookie and writes nothing, and that `/admin` is not open. The signed-in run needs a price and an existing verified test account (register one through `/register`) and **writes to the ledger**: it scans without a session, signs in (which records the pending single), records a double, replays a POST, reads the site pages and undoes what the undo window allows. Deactivate that account afterwards in `/admin/users`.

### Without Docker

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
set -a; . ./.env; set +a
.venv/bin/alembic upgrade head
sh scripts/run.sh          # one uvicorn worker; run it under systemd or similar
```

Set `DATABASE_URL=sqlite:////var/lib/coffee/coffee.db` (absolute path, four slashes), `SECRETS_DIR=/var/lib/coffee-secrets` (a directory writable by the service user and readable by nobody else) and make the database directory writable by the service user. The scripts in `scripts/` accept `DB_PATH=/var/lib/coffee/coffee.db` for the same file.

## Mail login

Registration, guest approval and password reset send mail through one SMTP mailbox (`SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY`; certificate chain and host name are always verified, TLS 1.2 minimum, no plaintext fallback, the login is only attempted on an encrypted channel). Its username and password are asked for with hidden prompts and stored encrypted (Fernet, key derived from `SECRET_KEY`) in the `secrets` volume (`SECRETS_DIR`, directory mode 0700, file mode 0600). They are never in `.env`, the compose file, the image, the database, the backups, logs, error pages, the audit log or any admin page. There is no `--password` option, so the password never reaches the shell history or the process list:

```bash
docker compose run --rm -it app python -m app.cli setup-mail     # username and password prompts, password twice
docker compose run --rm app python -m app.cli mail-status        # configured yes/no, masked user, last send, last failure
docker compose run --rm app python -m app.cli test-mail you@example.org   # one real message through the configured server
docker compose run --rm app python -m app.cli clear-mail         # delete the stored login
```

- `setup-mail --password-stdin` is for scripted installs only: the first stdin line is the username (skipped when `--username` is given), the next the password.
- The command refuses to run, with a clear message, when `SECRETS_DIR` is not writable (mount the volume writable for the app user).
- `mail-status` and the head admin's dashboard card show only `mail configured: yes/no`, the masked user (`c***@lrz.de`), the last send that worked and the last failure category with its time (`connect`, `tls`, `auth`, `recipient_rejected`, `timeout`, `cap_exceeded`, `other`). `test-mail` prints the category on failure, never credentials. The status is kept as audit-log rows (`mail.send_ok`, at most one per 10 minutes, and `mail.send_failed` with the category only), so the command line and the server, two processes, see the same result.
- The dashboard shows a banner for the head admin only: "mail not configured", "mail failing: <category>", or "cap reached" when the hourly limit (`MAIL_MAX_PER_HOUR`) blocked sending (nothing is broken then; anonymous registration and reset requests can reach the cap, and mails go out again after the hour).
- Changing `SECRET_KEY` makes the stored login unreadable (`mail login unreadable: re-run setup-mail`); run `setup-mail` again. A restore onto a new server likewise needs `setup-mail`, because the secrets volume is not part of any backup.
- Use a dedicated or functional mailbox if TUM or LRZ offers one, not a personal account, and an app or service password if available. The password is then easy to rotate by re-running `setup-mail`. The encryption protects against a leaked volume snapshot or an accidentally shared file; it does not protect against someone who controls the running server.

## Post-deployment mail checklist

The automated tests simulate mail (an in-memory mailbox for the logic, a local fake SMTP server with generated certificates for the protocol). **What a simulation cannot show** is whether LRZ accepts the login from this server, accepts the chosen `From` address, allows automated mail from that mailbox, applies a sending quota, or files the mails under spam. Check once after deployment:

1. Confirm with TUM or LRZ that automated mail from that mailbox is allowed and that `MAIL_FROM` matches the account. Prefer a functional mailbox and an app password.
2. Run `docker compose run --rm -it app python -m app.cli setup-mail`.
3. Run `test-mail` to your own TUM address.
4. Open the message: check the headers (`From`, `Auto-Submitted: auto-generated`, no unexpected relay) and look in the **spam folder**.
5. Run one real guest request (register a guest with your own address as the sponsor) and approve it.
6. Run one real password reset (`/forgot`) and use the link.
7. Run `mail-status` and check `last send OK`, no failure category, and the dashboard card.

If mails stop later, the dashboard banner and `mail-status` show the failure category (`auth` after a password change: re-run `setup-mail`).

## Day-to-day operations

- **Logs:** stdout (`docker compose logs -f app`), level via `LOG_LEVEL`. The application logs each request itself, with one-time tokens redacted.
- **Purge expired sessions, pending scans, expired or used registration and reset links and old rate-limit rows** (database growth is small; weekly is plenty), for example from cron:
  ```bash
  docker compose run --rm app python -m app.cli purge-expired
  ```
- **Check ledger integrity** (exit code 1 on problems; also useful after a restore; includes group balance, remittance and correction rules):
  ```bash
  docker compose run --rm app python -m app.cli check-ledger
  ```
- **CSV exports** (users with balances, ledger by date range and chair, group balances) are in the admin area; they are formula-injection safe and audited.
- **Merging duplicate accounts, payments, corrections, reversals, set balance, deactivation:** admin area, user detail page (balance changes need the step-up). Merging never moves or edits ledger events.

## Backup and restore

`scripts/backup.sh` makes a consistent online copy of **the SQLite database only** with SQLite's backup API (the mechanism behind `sqlite3 .backup`; it needs only the Python standard library, so it runs inside the image where no `sqlite3` binary exists). It never reads `SECRETS_DIR`, and the `secrets` volume is not mounted into `/backups`, so **no backup contains the mail login**. It is safe while the app runs, verifies the copy (`PRAGMA integrity_check`, foreign keys, expected tables), writes `coffee-<UTC timestamp>.db` with mode 600, and keeps the newest `BACKUP_KEEP` (default 14).

```bash
docker compose exec -T app scripts/backup.sh          # writes to /backups = ./backups on the host
```

Nightly from cron (`crontab -e`), plus a copy off the machine, because backups on the same disk do not survive its loss:

```cron
17 3 * * * cd /opt/coffee-ledger && docker compose exec -T app scripts/backup.sh >> /var/log/coffee-backup.log 2>&1
47 3 * * * rsync -a --delete /opt/coffee-ledger/backups/ backup-host:/srv/coffee-ledger-backups/
```

Without Docker: `DB_PATH=/var/lib/coffee/coffee.db scripts/backup.sh /var/backups/coffee`. Backups contain every name, email address and balance: keep them readable only by the operator.

**Restore** (the app must be stopped; the script refuses to run while another process has the database open, verifies the backup first, and keeps the replaced database as `pre-restore-<timestamp>.db` next to the backups):

```bash
docker compose stop app
ls backups/                                            # pick a file
docker compose run --rm --no-deps app scripts/restore.sh /backups/coffee-20270101T031700Z.db --yes
docker compose run --rm app python -m app.cli check-ledger
docker compose up -d
curl -fsS http://127.0.0.1:8000/readyz
```

Everything recorded after the backup is lost; users can simply scan again.

**Restoring onto a new server:** install as in [First-time setup](#first-time-setup) with the **same `SECRET_KEY`**, restore the database as above, then **re-run `setup-mail`**, because the mail login is not in the backup. A different `SECRET_KEY` makes any stored mail login unreadable (and makes the administrators' recovery codes stop working: after `reset-admin-totp` the admin enrols again and gets new ones). Keep `SECRET_KEY` and `.env` safe separately from the off-site backups. Run the [mail checklist](#post-deployment-mail-checklist) again.

**Test your restore** once on a copy (for example in a scratch directory with `DB_PATH=/tmp/test.db scripts/restore.sh <backup> --yes`) so you know it works before you need it.

## Proxy log redaction

`/verify/<token>` and `/reset/<token>` carry a single-use secret in the URL. The application container does not print them (`--no-access-log`, own access log with the paths redacted), and the reverse proxy must redact the same two prefixes in the request URI and in the `Referer` header. The examples in `deploy/Caddyfile` and `deploy/nginx.conf` do this; the reasoning and the details are in [`deploy/README.md`](deploy/README.md). Other proxies, CDNs and load balancers need the equivalent setting.

## Upgrade notes

**v1 to v2:** v2 changed the schema in the initial migration (one revision, `0001_initial_schema`), so **a database created by v1 cannot be upgraded**. Start with a fresh database. Nothing was deployed with v1, so there is nothing to migrate: remove the old `coffee_data` volume (or use a new host), run `alembic upgrade head`, and set up as described above. Cookies and signed tokens from earlier test builds are invalid.

**Later upgrades:**

```bash
docker compose exec -T app scripts/backup.sh              # 1. backup
git pull                                                   # 2. new code
docker compose build                                       # 3. new image
docker compose stop app                                    # 4. brief downtime avoids old code on a new schema
docker compose run --rm app alembic upgrade head           # 5. migrate explicitly
docker compose up -d                                       # 6. start
curl -fsS http://127.0.0.1:8000/readyz                     # 7. ready?
scripts/smoke.sh https://coffee.example.org               # 8. optional check (public pages, no ledger writes)
```

Read the release notes and `.env.example` for new variables first. If something goes wrong, restore the backup from step 1 and start the previous image. `/readyz` returns 503 (`"check":"migrations"`) while the database is behind the code; migrations are never run at container start. Do not downgrade a production database except from a backup.

## Security considerations

- HTTPS only in production (startup refuses otherwise), HSTS, Secure/HttpOnly/SameSite cookies, strict CSP (`default-src 'self'`, no inline scripts or styles, `frame-ancestors 'none'`), `X-Content-Type-Options`, `Referrer-Policy: same-origin`, request size limit (64 KiB, also at the proxy), no stack traces and no API docs in production, redirects only to fixed internal paths, `Cache-Control: no-store` on dynamic pages.
- CSRF protection on every state-changing form, signed one-time scan tokens, step-up payloads signed and bound to a one-time nonce, `Sec-Fetch-Site`/`Origin` checks; verification, reset and scan links never change state on GET.
- Rate limits, stored in the database (so restarts do not reset them): registration, guest requests, username probes, sign-in, password reset requests, mail sending, admin login.
- No external services, CDNs, fonts, trackers or analytics. The only outbound connection is the SMTP connection to the mail server.
- Secrets: `SECRET_KEY` lives only in `.env` (mode 600, not in the image or the repository); the mail login only encrypted in the `secrets` volume; tokens, passwords and TOTP secrets are never logged. Keys for signing, CSRF and mail-login encryption are derived separately (HKDF).
- Keep the host patched, the proxy as the only public listener, `/admin` restricted by IP where possible, and backups readable only by the operator.
- Dependencies: run `pip-audit -r requirements.txt` before each release.

## Known limitations

- Identity is a verified TUM email (members) or a member's vouching (guests), plus a password. It does not prove the user's real-world identity (see [Trust and identity model](#trust-and-identity-model)).
- **Single process:** run exactly one app process (one uvicorn worker, one container). SQLite's single write lock and the in-process mail status assume it. Do not scale out and do not raise `--workers`.
- **Cookie jars:** phone cameras, in-app QR scanners and home-screen web apps may use a different cookie jar than the browser where the user signed in, so the scan looks like a new browser. The recovery path is to sign in (`/login`): the scanned coffee is kept for one hour and recorded after sign-in. A member who confirms the email link in a different browser than the scan loses a coffee scanned before registering after one hour and scans again; registration never records a coffee.
- **No erasure tooling.** Deactivating an account is the only removal mechanism; ledger rows and the audit log are append-only and are not deleted or anonymized. `/privacy` says so.
- **Duplicate people:** different TUM aliases can create two accounts for one person; this cannot be detected automatically. Admins can merge them (balance-changing action, step-up applies).
- **The mail login is not in backups.** A restore onto a new server, or a changed `SECRET_KEY`, needs `setup-mail` again. Until then registration and recovery pages say "temporarily unavailable".
- **Shared sponsor trust:** a sponsor receives every reset mail of their guests and could use such a link themselves. This is accepted as part of vouching; the head admin can reassign a guest to another sponsor.
- **Sponsor typos:** a guest who mistypes the sponsor's address gets the same neutral page and no mail (this keeps the form from revealing who is a member).
- **Open site:** every signed-in account sees everyone's balance and history (see [the privacy section](#the-open-site-and-its-privacy-implications)).
- Mail depends on the LRZ mailbox: quotas, spam filtering and policy are outside the app (see the mail checklist).
- SQLite on one server; no high availability. Back up regularly and copy backups off the machine. Network or shared-cache filesystems (NFS, some cloud volume types) are not supported for the SQLite file; use a local disk.
- Docker, the compose file and the proxy examples have not been run end to end in the build environment (no Docker daemon); verify them on your host with `scripts/smoke.sh` and the [mail checklist](#post-deployment-mail-checklist).

## Out of scope

Erasure or anonymization tooling, a public JSON API, API keys, passkeys or SSO, mail other than the registration, approval and reset mails (no balance reminders), self-service change of username or email address, per-user data export, cached aggregates, PostgreSQL deployment, payment processing, and separate prices for single and double (a double is always 2 x the per-shot price). None of these is built; the design (identity separate from the ledger, integer cents, immutable events) does not make them impossible.
