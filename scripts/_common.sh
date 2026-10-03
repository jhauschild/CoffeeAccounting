# Shared helpers for backup.sh and restore.sh (sourced, not executed).
# shellcheck shell=bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() { echo "error: $*" >&2; exit 1; }

# Python with the standard-library sqlite3 module (the container image has `python`, hosts usually `python3`).
find_python() {
  local candidate
  for candidate in "${PYTHON:-}" python3 python; do
    if [ -n "$candidate" ] && command -v "$candidate" >/dev/null 2>&1; then
      echo "$candidate"
      return 0
    fi
  done
  die "python3 not found (needed for the SQLite backup API)"
}

PY="$(find_python)"
dbtool() { "$PY" "$SCRIPT_DIR/dbtool.py" "$@"; }

# Database file: DB_PATH, else derived from DATABASE_URL (sqlite:///relative or sqlite:////absolute),
# else the application default ./data/coffee.db.
resolve_db_path() {
  if [ -n "${DB_PATH:-}" ]; then
    printf '%s\n' "$DB_PATH"
  elif [ -n "${DATABASE_URL:-}" ]; then
    case "$DATABASE_URL" in
      sqlite:///*) printf '%s\n' "${DATABASE_URL#sqlite:///}" ;;
      *) die "DATABASE_URL is not a sqlite:/// URL; set DB_PATH to the database file" ;;
    esac
  else
    printf '%s\n' "./data/coffee.db"
  fi
}
