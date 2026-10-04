# Task 6.1: ops and docs for v2

Status: done. Commit "ops: v2 compose secrets volume, env, backup, smoke, README, architecture (task 6.1)".

## What changed
- `docker-compose.yml`: named volume `secrets` mounted only into `app` at `/secrets` (`SECRETS_DIR=/secrets`); backup bind mount unchanged (`/backups`, database backups only). Passes `MAIL_BACKEND: smtp`, `SMTP_HOST/PORT/SECURITY`, `MAIL_FROM` (interpolated from `.env`, defaults `postout.lrz.de`, 587, starttls). No mail login anywhere. `docker compose config` renders (CLI v5.5.1 exists here; no daemon, so no build or run was done or claimed).
- `Dockerfile`: `mkdir -m 0700 /secrets && chown app:app /secrets` before `USER app` (a named volume inherits owner and mode on first mount), `SECRETS_DIR=/secrets`.
- `.env.example`: rewritten, every `Settings` field present (commented where the default is right), mail section (host postout.lrz.de, 587/starttls or 465/ssl, `MAIL_FROM` empty so production refuses to start until set), explicit "mail login is never entered here, use `setup-mail`". `SECRET_KEY` placeholder is the refused one. No `ACCESS_CODE`/`ADMIN_TOTP_REQUIRED`.
- `scripts/backup.sh`, `restore.sh`: header and restore message state that only the database is backed up and that `setup-mail` must be re-run on a new server; the scripts never touch `SECRETS_DIR` (tested). `scripts/smoke.sh` rewritten for v2: `--health-only` (healthz, readyz, CSP/nosniff/Referrer-Policy, HSTS over https); default run adds `/register` 200, `/login` 200 (+ link to register), anonymous `/overview` 303 to `/login` with `Cache-Control: no-store`, `GET /coffee/single` 200 with no Set-Cookie, `/admin` not 200; with `SMOKE_USERNAME` and `SMOKE_PASSWORD` the signed-in ledger-writing flow (as before) plus `/overview`, `/overview/people`, `/privacy`. Run live against a dev uvicorn (http): all three modes passed (HSTS branch not exercised, needs https).
- `README.md` rewritten for v2 (all topics of the brief; new identity sentence; configuration table complete; setup, mail checklist, restores, proxy log redaction linking `deploy/README.md`, upgrade notes, limitations, out of scope). `docs/ARCHITECTURE.md` rewritten as built (points to V2-CONTRACT for interfaces). `docs/PROGRESS.md` rewritten with the per-task list.
- Tests: `tests/test_ops_v2.py` (16 new: compose volume, no mail login in compose/Dockerfile/.env.example, `docker compose config` when the CLI exists, Dockerfile secrets dir, `.env.example` parses as production Settings and covers every field, backup on a temp dir with a fake secrets file (also with the secrets dir inside the data dir), smoke syntax and argument handling, README and architecture content). `tests/test_ops_scripts.py`: the pinned sentence replaced by the new one; CLI example test also requires the setup/mail commands.

## Later tasks must know
- 6.2 (real compose run): check that the `secrets` volume is writable by uid 10001 (`docker compose run --rm -it app python -m app.cli setup-mail` must not hit the "SECRETS_DIR not writable" refusal) and that `./backups` ownership still needs `chown 10001`. The 0700/owner inheritance of a fresh named volume is Docker behaviour I could not test.
- Changing `SECRET_KEY` also invalidates admin recovery codes (MAC key, task F4 L6); documented in the README.
- ACCEPTANCE.md still describes v1 (task 7.3).
- Not verified: Docker build/run, HSTS over TLS, nginx example, real LRZ mail.
- Known-broken tests: none.
