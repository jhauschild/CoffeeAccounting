#!/usr/bin/env bash
# Restore the SQLite database from a backup made by backup.sh.
#
#   scripts/restore.sh BACKUP_FILE --yes
#
# STOP THE APP FIRST. The script refuses to run while another process has the database open, verifies the
# backup (PRAGMA integrity_check, foreign_key_check, expected tables), keeps a consistent copy of the current
# database as pre-restore-<timestamp>.db, then swaps the file in and removes stale -wal/-shm files.
#
#   Docker:  docker compose stop app
#            docker compose run --rm --no-deps app scripts/restore.sh /backups/coffee-<stamp>.db --yes
#            docker compose up -d
#
# Environment: DB_PATH or DATABASE_URL (as for backup.sh), BACKUP_DIR (where pre-restore copies go,
# default: next to the database).
set -euo pipefail
umask 077
# shellcheck source=scripts/_common.sh
. "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

usage() { echo "usage: $0 BACKUP_FILE --yes" >&2; exit 2; }
[ "$#" -eq 2 ] || usage
backup_file="$1"
[ "$2" = "--yes" ] || usage

db="$(resolve_db_path)"
[ -f "$backup_file" ] || die "backup file not found: $backup_file"
db_dir="$(dirname "$db")"
mkdir -p "$db_dir"
safety_dir="${BACKUP_DIR:-$db_dir}"
mkdir -p "$safety_dir"

dbtool check "$backup_file" >/dev/null || die "backup failed verification: $backup_file"
if [ -e "$db" ]; then
  dbtool inuse "$db" || die "stop the application before restoring"
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
incoming="$db_dir/.restore-$stamp.partial"
trap 'rm -f "$incoming"' EXIT
dbtool backup "$backup_file" "$incoming" # private copy on the target filesystem, so the final mv is atomic
dbtool check "$incoming" >/dev/null || die "copy failed verification"

if [ -e "$db" ]; then
  safety="$safety_dir/pre-restore-$stamp.db"
  dbtool backup "$db" "$safety"
  echo "current database saved as $safety"
fi

rm -f -- "$db-wal" "$db-shm"
mv "$incoming" "$db"
dbtool check "$db" >/dev/null || die "restored database failed verification (previous one is in $safety_dir)"
echo "restored $db from $backup_file; start the application and open /readyz"
