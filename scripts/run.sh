#!/bin/sh
# Container entrypoint: one uvicorn worker (required, see README "Single process").
# --proxy-headers/--forwarded-allow-ips make uvicorn trust X-Forwarded-* only from TRUSTED_PROXY_IPS
# (comma-separated IPs or CIDR networks; the application applies the same list to X-Forwarded-For).
# --no-access-log: uvicorn's access log would print one-time tokens (/verify/<token>, /reset/<token>);
# the application logs requests itself with those paths redacted (app/web/accesslog.py).
# Schema: scripts/migrate_on_start.sh runs before uvicorn. If the DB exists and is behind the
# image head it backs up first (scripts/backup.sh) then runs `alembic upgrade head`; a failed
# backup aborts startup. Fresh DBs are created without a backup. Already-at-head is a no-op.
set -eu
bash "$(dirname "$0")/migrate_on_start.sh"
level=$(printf '%s' "${LOG_LEVEL:-info}" | tr '[:upper:]' '[:lower:]')
exec uvicorn app.main:app \
  --host "${HOST:-0.0.0.0}" --port "${PORT:-8000}" \
  --workers 1 \
  --proxy-headers --forwarded-allow-ips "${TRUSTED_PROXY_IPS:-127.0.0.1}" \
  --no-server-header --no-access-log --log-level "$level"
