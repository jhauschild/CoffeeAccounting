# Brief 04 — ops (agent name: `ops`)

Dir: `/home/claude/wt/ops` (git worktree, branch `ops`). Read `docs/agents/00-protocol.md`, `docs/ARCHITECTURE.md`, and PROMPT §1, §9, §11, §13, §14. You do not edit application code.

## Build (files marked **O**)

1. `Dockerfile` (python 3.12-slim, non-root user, minimal layers, no dev deps, `HEALTHCHECK` on `/healthz`, data volume at `/data`), `.dockerignore`, `docker-compose.yml` (one `app` service, named volume, `env_file: .env`, restart policy, **explicit migration command documented and available as `docker compose run --rm app alembic upgrade head`**), `.env.example` (every variable in PROMPT §11, placeholders only, comments), run command with a single uvicorn worker and `--proxy-headers` honoring `TRUSTED_PROXY_IPS`.
2. `scripts/backup.sh` (consistent SQLite backup via `sqlite3 .backup`/`VACUUM INTO`, timestamped, keeps N copies, usable from cron and from inside/outside the container), `scripts/restore.sh` (stops/guards, verifies integrity with `PRAGMA integrity_check`, swaps file), `scripts/smoke.sh` (health, readiness, a full scan against a running instance with curl using a cookie jar; useful for acceptance).
3. `deploy/Caddyfile` and `deploy/nginx.conf` examples: TLS, HSTS, forwarded headers, request size limit, optional IP allowlist for `/admin`, no caching of dynamic pages.
4. `README.md` per PROMPT §13 (all listed sections, including the verbatim limitation sentence, the access-code rotation, single-process requirement, cookie-jar caveat, no erasure tooling, price-history model, first-admin + TOTP + first-price steps, backup/restore, upgrade procedure, security considerations, out-of-scope list). Command examples must be copy-pasteable and consistent with the real CLI (read `app/cli.py` on `main` for the names; if a command doesn't exist yet, file a request instead of guessing).
5. Verify what you can: `docker build` and `docker compose config` if a Docker daemon is reachable; otherwise run `shellcheck`-style review of scripts and test backup/restore against a real SQLite file in a temp dir (this you must actually run). State clearly what you could not run.

## Done when

Scripts tested as far as possible, committed on branch `ops`, `docs/status/ops.md` updated with a "verified / not verified" table.
