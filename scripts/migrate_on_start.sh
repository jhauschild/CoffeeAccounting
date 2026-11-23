#!/usr/bin/env bash
# Apply Alembic migrations before the app starts. If an existing database is behind the
# image head, take a full SQLite backup first (scripts/backup.sh) and refuse to migrate
# when that backup fails. Fresh databases (no file yet) are created with no backup.
#
# Called from scripts/run.sh. Safe to run repeatedly: a DB already at head is a no-op.
set -euo pipefail
# shellcheck source=scripts/_common.sh
. "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

db="$(resolve_db_path)"

db_at_head() {
  "$PY" - "$db" <<'PY'
import sys
from pathlib import Path

from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine

db_path = Path(sys.argv[1])
if not db_path.is_file():
    raise SystemExit(1)

# Prefer DATABASE_URL when set (compose); else open the resolved file path.
import os
url = os.environ.get("DATABASE_URL") or f"sqlite:///{db_path.resolve()}"
cfg = Config("alembic.ini")
heads = set(ScriptDirectory.from_config(cfg).get_heads())
engine = create_engine(url)
with engine.connect() as conn:
    current = set(MigrationContext.configure(conn).get_current_heads())
raise SystemExit(0 if current == heads else 1)
PY
}

if db_at_head; then
  echo "migrate_on_start: database already at alembic head"
  exit 0
fi

if [ -f "$db" ]; then
  echo "migrate_on_start: database behind head; backing up before migration"
  if ! bash "$SCRIPT_DIR/backup.sh"; then
    echo "migrate_on_start: backup failed; refusing to migrate" >&2
    exit 1
  fi
else
  echo "migrate_on_start: no database yet; applying migrations"
fi

"$PY" -m alembic upgrade head
echo "migrate_on_start: migrations applied"
