#!/usr/bin/env bash
# Apply Alembic migrations before the app starts. If an existing database is behind the
# image head, take a full SQLite backup first (scripts/backup.sh) and refuse to migrate
# when that backup fails. Fresh databases (no file yet) are created with no backup.
#
# Called from scripts/run.sh. Safe to run repeatedly: a DB already at head is a no-op.
set -euo pipefail
# shellcheck source=scripts/_common.sh
. "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

# #region agent log
_DEBUG_LOG="${SCRIPT_DIR}/../.cursor/debug-fb7e03.log"
_dbg() {
  local hyp="$1" msg="$2" data="${3:-{}}"
  mkdir -p "$(dirname "$_DEBUG_LOG")" 2>/dev/null || true
  printf '{"sessionId":"fb7e03","hypothesisId":"%s","location":"scripts/migrate_on_start.sh","message":"%s","data":%s,"timestamp":%s}\n' \
    "$hyp" "$msg" "$data" "$(date +%s)000" >>"$_DEBUG_LOG" 2>/dev/null || true
}
# #endregion

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
  # #region agent log
  _dbg "H2" "already_at_head" "{\"db_exists\":true}"
  # #endregion
  exit 0
fi

if [ -f "$db" ]; then
  echo "migrate_on_start: database behind head; backing up before migration"
  # #region agent log
  _dbg "H3" "backup_before_migrate" "{\"db_exists\":true}"
  # #endregion
  if ! bash "$SCRIPT_DIR/backup.sh"; then
    echo "migrate_on_start: backup failed; refusing to migrate" >&2
    # #region agent log
    _dbg "H4" "backup_failed_abort" "{\"db_exists\":true}"
    # #endregion
    exit 1
  fi
else
  echo "migrate_on_start: no database yet; applying migrations"
  # #region agent log
  _dbg "H1" "fresh_db_no_backup" "{\"db_exists\":false}"
  # #endregion
fi

"$PY" -m alembic upgrade head
echo "migrate_on_start: migrations applied"
# #region agent log
_dbg "H1-H3" "migrate_done" "{\"db_exists\":$([ -f "$db" ] && echo true || echo false)}"
# #endregion
