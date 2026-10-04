#!/bin/bash
# Acceptance run (task 7.3): backup retention (BACKUP_KEEP) and the README "test your restore on a copy" command.
#   bash docs/status/repro/acceptance_backup_extra.sh WORKDIR
W="$(cd "$1" && pwd)"
ROOT="$(pwd)"
export PATH="/home/claude/venv/bin:$PATH"
DB="$W/dev/data/coffee.db"
D="$W/scratch/bk"; rm -rf "$D"; mkdir -p "$D"
for i in 1 2 3 4; do
  DB_PATH="$DB" BACKUP_KEEP=2 bash "$ROOT/scripts/backup.sh" "$D"
  sleep 1.1   # backup names carry a one-second timestamp
done
echo "files kept (BACKUP_KEEP=2 after 4 backups):"; ls "$D"
newest="$(ls "$D"/coffee-*.db | tail -n1)"
echo "restore onto a copy, as the README suggests:"
DB_PATH="$W/scratch/test.db" bash "$ROOT/scripts/restore.sh" "$newest" --yes
python -m app.cli --help > /dev/null 2>&1
DATABASE_URL="sqlite:///$W/scratch/test.db" python - <<EOF
import sqlite3
c = sqlite3.connect("$W/scratch/test.db")
print("restored copy: integrity", c.execute("pragma integrity_check").fetchone()[0], "events", c.execute("select count(*) from consumption_events").fetchone()[0])
EOF
echo "restore of a garbage file is refused:"
echo "not a database" > "$W/scratch/garbage.db"
DB_PATH="$W/scratch/test2.db" bash "$ROOT/scripts/restore.sh" "$W/scratch/garbage.db" --yes; echo "[exit $?]"
echo "restore without --yes is refused:"
DB_PATH="$W/scratch/test2.db" bash "$ROOT/scripts/restore.sh" "$newest"; echo "[exit $?]"
