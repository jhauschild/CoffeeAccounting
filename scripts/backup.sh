#!/usr/bin/env bash
# Consistent online backup of the SQLite database (safe while the app is running).
#
# The backup contains ONLY the SQLite database. SECRETS_DIR (the encrypted mail login) is never read,
# copied or archived by this script, and the compose file does not mount the secrets volume into /backups.
# After restoring onto a new server run `python -m app.cli setup-mail` again.
#
#   scripts/backup.sh [BACKUP_DIR]
#
# Environment: DB_PATH or DATABASE_URL (the container sets DATABASE_URL), BACKUP_DIR (default ./backups,
# in the container /backups), BACKUP_KEEP (copies to keep, default 14). Cron-friendly: silent except for
# one line on success, non-zero exit and a message on stderr on failure.
#
#   Docker:  docker compose exec -T app sh -c 'BACKUP_DIR=/backups scripts/backup.sh'
#   Cron:    17 3 * * *  cd /opt/coffee-ledger && docker compose exec -T app scripts/backup.sh
set -euo pipefail
umask 077
# shellcheck source=scripts/_common.sh
. "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

db="$(resolve_db_path)"
dir="${1:-${BACKUP_DIR:-./backups}}"
keep="${BACKUP_KEEP:-14}"
case "$keep" in '' | *[!0-9]*) die "BACKUP_KEEP must be a positive integer" ;; esac
[ "$keep" -ge 1 ] || die "BACKUP_KEEP must be at least 1"
[ -f "$db" ] || die "database not found: $db"

mkdir -p "$dir"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
final="$dir/coffee-$stamp.db"
partial="$dir/.coffee-$stamp.db.partial"
trap 'rm -f "$partial"' EXIT

dbtool backup "$db" "$partial"
dbtool check "$partial" >/dev/null
chmod 600 "$partial"
mv "$partial" "$final"

# Retention: names sort chronologically; remove the oldest beyond BACKUP_KEEP.
shopt -s nullglob
backups=("$dir"/coffee-*.db)
excess=$((${#backups[@]} - keep))
if [ "$excess" -gt 0 ]; then
  rm -f -- "${backups[@]:0:excess}"
fi

echo "backup ok: $final ($(wc -c <"$final") bytes, keeping ${keep})"
