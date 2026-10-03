# Status: ops

## Done
- Dockerfile, .dockerignore, docker-compose.yml, .env.example, scripts/run.sh (single uvicorn worker, --proxy-headers, TRUSTED_PROXY_IPS)
- scripts/backup.sh, restore.sh, smoke.sh, dbtool.py, _common.sh
- deploy/Caddyfile, deploy/nginx.conf, deploy/nginx-proxy.conf
- README.md (PROMPT §13 sections, verbatim limitation sentence, admin request items applied)
- tests/test_ops_scripts.py (8 tests: backup, retention, restore, in-use guard, bad backups, README CLI/env consistency)

## Next
- nothing; on a real host run `docker compose build`, the README deployment steps and `scripts/smoke.sh`

## Notes/Blockers
- No Docker daemon, nginx or sqlite3 CLI in the sandbox. Backups use Python's sqlite3 backup API (same mechanism as `.backup`), so they also work inside the image.
- Full suite: 452 passed (`python -m pytest -q`); pip-audit -r requirements.txt: no known vulnerabilities.
- Chairs have no CLI command (admin page only); README says so.

## Verified / not verified
| Item | Status |
| --- | --- |
| backup.sh while a connection has unflushed WAL (row present in backup) | verified (test) |
| retention, mode 600, missing DB failure | verified (test) |
| restore round trip, pre-restore copy, stale -wal removal, check-ledger afterwards | verified (test + live run) |
| restore refuses while the DB is open (live uvicorn and test connection); stale -shm of a stopped app does not block | verified |
| restore rejects garbage / empty / non-ledger backups, requires --yes | verified (test) |
| shellcheck -x on all scripts | verified, clean (shellcheck-py 0.11) |
| smoke.sh full scan against a live uvicorn (direct and via Caddy) | verified, dev mode |
| scripts/run.sh, alembic, /healthz, /readyz, no /docs in production mode from an image-like directory (only COPY'd paths) | verified |
| deploy/Caddyfile: caddy validate; HSTS, no-store (single header), 64KB limit -> 413, /admin allowlist -> 403, spoofed X-Forwarded-For ignored, source IP in audit log | verified (Caddy 2.8.4 local run) |
| docker compose config | verified (renders) |
| README CLI examples parse with the real argparse; every Settings variable documented | verified (test) |
| docker build, HEALTHCHECK, non-root user, volume ownership, bind mount ./backups permissions | NOT verified (no daemon) |
| docker compose up / run migration inside a container | NOT verified |
| TRUSTED_PROXY_IPS guidance for the Docker bridge gateway | NOT verified |
| deploy/nginx.conf and nginx-proxy.conf (no nginx binary) | NOT verified |
| HSTS over real TLS from the app in production (only checked via middleware code and Caddy) | NOT verified |
| sqlite3 CLI variant of backup (not used; Python API only) | n/a |
