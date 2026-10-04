#!/bin/bash
# Acceptance run (task 7.3): README command checks that need no browser. Output is the evidence (read it).
#
#   bash docs/status/repro/acceptance_cli.sh WORKDIR     # after acceptance_up.sh; uses WORKDIR/dev (development instance)
#
# alembic upgrade / downgrade / check on a scratch database, bootstrap-admin on a scratch database, the admin and
# price commands, qr --out (and that the SVGs are valid and four), check-ledger, purge-expired, `docker compose config`
# on .env.example, pip-audit -r requirements.lock.
W="$(cd "$1" && pwd)"
ROOT="$(pwd)"
PY="${PY:-/home/claude/venv/bin/python}"
export PATH="$(dirname "$PY"):$PATH"
export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost
PTY="$ROOT/docs/status/repro/pty_run.py"
run() { echo; echo "\$ $*"; "$@"; echo "[exit $?]"; }

echo "===== alembic on a scratch database (clean git-archive copy) ====="
cd "$W/dev"
SCR="$W/scratch"; rm -rf "$SCR"; mkdir -p "$SCR"
export DATABASE_URL="sqlite:///$SCR/m.db"
run alembic upgrade head
"$PY" - <<EOF
import sqlite3
c = sqlite3.connect("$SCR/m.db")
print("objects after upgrade:", dict(c.execute("select type, count(*) from sqlite_master where name not like 'sqlite_%' group by type").fetchall()))
print("tables:", sorted(r[0] for r in c.execute("select name from sqlite_master where type='table' and name not like 'sqlite_%'")))
EOF
run alembic current
run alembic check
run alembic downgrade base
"$PY" - <<EOF
import sqlite3
c = sqlite3.connect("$SCR/m.db")
print("objects after downgrade base:", c.execute("select type, name from sqlite_master where name not like 'sqlite_%'").fetchall())
EOF
run alembic upgrade head
run alembic check
run alembic upgrade head

echo; echo "===== bootstrap-admin on a fresh scratch database ====="
rm -f "$SCR/b.db"; export DATABASE_URL="sqlite:///$SCR/b.db"
alembic upgrade head > /dev/null 2>&1
ADMIN_BOOTSTRAP_USERNAME=boot ADMIN_BOOTSTRAP_PASSWORD=short run "$PY" -m app.cli bootstrap-admin
ADMIN_BOOTSTRAP_USERNAME=boot ADMIN_BOOTSTRAP_PASSWORD='Bootstrap-Password-12' run "$PY" -m app.cli bootstrap-admin
ADMIN_BOOTSTRAP_USERNAME=other ADMIN_BOOTSTRAP_PASSWORD='Bootstrap-Password-12' run "$PY" -m app.cli bootstrap-admin
run "$PY" -m app.cli list-admins
unset DATABASE_URL

echo; echo "===== admin commands on the development instance ====="
cd "$W/dev"
run "$PY" -m app.cli list-admins
run "$PY" -m app.cli create-admin --username x1 --role global --password-stdin <<< 'Another-Long-Password-1'
run "$PY" -m app.cli create-admin --username x1 --role global --password-stdin <<< 'Another-Long-Password-1'
run "$PY" -m app.cli create-admin --username x3 --role chair --password-stdin <<< 'Another-Long-Password-1'
run "$PY" -m app.cli reset-admin-password --username x1 --password-stdin <<< 'Changed-Long-Password-2'
"$PY" "$PTY" --script '[["New password: ","Pty-Admin-Password-33"],["Repeat password: ","Pty-Admin-Password-33"]]' --secret Pty-Admin-Password-33 -- "$PY" -m app.cli reset-admin-password --username x1
run "$PY" -m app.cli reset-admin-totp --username x1
run "$PY" -m app.cli disable-admin --username x1
run "$PY" -m app.cli list-admins
run "$PY" -m app.cli disable-admin --username x1 --enable
run "$PY" -m app.cli reset-admin-password --username alice --password-stdin <<< 'Changed-Long-Password-2'

echo; echo "===== prices ====="
run "$PY" -m app.cli set-price --cents 55
run "$PY" -m app.cli set-price --cents 60 --from 2020-01-01T00:00
run "$PY" -m app.cli set-price --cents 70 --from 2027-01-01T00:00
run "$PY" -m app.cli set-price --cents abc
run "$PY" -m app.cli set-price --cents -5

echo; echo "===== qr --out ====="
rm -rf "$SCR/qr"
run "$PY" -m app.cli qr --out "$SCR/qr"
ls -l "$SCR/qr"
for f in "$SCR"/qr/*.svg; do head -c 60 "$f" | tr '\n' ' '; echo " ($f)"; done

echo; echo "===== check-ledger and purge-expired ====="
run "$PY" -m app.cli check-ledger
run "$PY" -m app.cli purge-expired
run "$PY" -m app.cli check-ledger

echo; echo "===== docker compose config (no daemon: validation only) ====="
cd "$W/dev"
cp .env.example "$SCR/compose.env"
( cd "$SCR" && rm -rf compose && mkdir compose && cp "$W/dev/docker-compose.yml" compose/ && cp "$SCR/compose.env" compose/.env && cd compose && docker compose config > config.out 2> config.err; echo "[exit $?]"; head -c 600 config.err; grep -nE "127.0.0.1:8000|MAIL_BACKEND|SECRETS_DIR|secrets:|BACKUP_DIR|ENVIRONMENT|SMTP_HOST" config.out | head -20 )
docker info > "$SCR/docker_info.txt" 2>&1; echo "[docker info exit $?]"; tail -3 "$SCR/docker_info.txt"

echo; echo "===== pip-audit -r requirements.lock ====="
cd "$W/dev"
run pip-audit -r requirements.lock
