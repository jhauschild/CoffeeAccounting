#!/bin/sh
# Container entrypoint: one uvicorn worker (required, see README "Single process").
# --proxy-headers/--forwarded-allow-ips make uvicorn trust X-Forwarded-* only from TRUSTED_PROXY_IPS
# (comma-separated IPs or CIDR networks; the application applies the same list to X-Forwarded-For).
# Migrations are NOT run here: use `docker compose run --rm app alembic upgrade head`.
set -eu
level=$(printf '%s' "${LOG_LEVEL:-info}" | tr '[:upper:]' '[:lower:]')
exec uvicorn app.main:app \
  --host "${HOST:-0.0.0.0}" --port "${PORT:-8000}" \
  --workers 1 \
  --proxy-headers --forwarded-allow-ips "${TRUSTED_PROXY_IPS:-127.0.0.1}" \
  --no-server-header --log-level "$level"
