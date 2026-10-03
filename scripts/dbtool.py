"""SQLite helper used by backup.sh and restore.sh (standard library only).

  dbtool.py backup SRC DEST   consistent online copy via SQLite's backup API (same mechanism as `.backup`)
  dbtool.py check FILE        PRAGMA integrity_check + foreign_key_check + expected ledger tables present
  dbtool.py inuse FILE        exit 1 when another process currently has the database open

Exit codes: 0 success / not in use, 1 failure / in use, 2 usage error.
"""

from __future__ import annotations

import fcntl
import os
import sqlite3
import sys
from pathlib import Path

REQUIRED_TABLES = {"alembic_version", "users", "chairs", "prices", "consumption_events", "payment_events", "audit_log"}
SHM_DMS_OFFSET = 128  # SQLite's "dead man switch" byte in the -shm file: held shared by every open connection


def backup(src: str, dest: str) -> int:
    if not Path(src).is_file():
        print(f"error: database not found: {src}", file=sys.stderr)
        return 1
    if Path(dest).exists():
        print(f"error: refusing to overwrite {dest}", file=sys.stderr)
        return 1
    source = sqlite3.connect(src, timeout=30)
    target = sqlite3.connect(dest)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()
    return 0


def check(path: str) -> int:
    if not Path(path).is_file():
        print(f"error: not a file: {path}", file=sys.stderr)
        return 1
    # immutable=1: never writes (no -wal/-shm files are created next to a backup).
    uri = f"file:{Path(path).resolve().as_posix()}?immutable=1"
    try:
        conn = sqlite3.connect(uri, uri=True)
        try:
            integrity = [row[0] for row in conn.execute("PRAGMA integrity_check")]
            fk = conn.execute("PRAGMA foreign_key_check").fetchall()
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            conn.close()
    except sqlite3.DatabaseError as exc:
        print(f"error: not a usable SQLite database: {exc}", file=sys.stderr)
        return 1
    problems = []
    if integrity != ["ok"]:
        problems.append("integrity_check: " + "; ".join(integrity[:5]))
    if fk:
        problems.append(f"foreign_key_check: {len(fk)} violation(s)")
    missing = REQUIRED_TABLES - tables
    if missing:
        problems.append("missing tables: " + ", ".join(sorted(missing)))
    if problems:
        print("error: " + " | ".join(problems), file=sys.stderr)
        return 1
    print("ok")
    return 0


def inuse(path: str) -> int:
    """True when a live SQLite connection holds the database (checked through the -shm lock).

    Without an -shm file nobody has the WAL database open. With one, try to take the exclusive
    byte lock that every open connection holds shared; failing means the application is running.
    A stale -shm left by a stopped/crashed process is not locked and counts as not in use.
    """
    shm = Path(path + "-shm")
    if not shm.exists():
        return 0
    fd = os.open(shm, os.O_RDWR)
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 1, SHM_DMS_OFFSET)
    except OSError:
        print(f"database is in use by another process: {path}", file=sys.stderr)
        return 1
    finally:
        os.close(fd)  # also releases the lock
    return 0


def main(argv: list[str]) -> int:
    commands = {"backup": (backup, 2), "check": (check, 1), "inuse": (inuse, 1)}
    if len(argv) < 2 or argv[1] not in commands or len(argv) - 2 != commands[argv[1]][1]:
        print(__doc__, file=sys.stderr)
        return 2
    return commands[argv[1]][0](*argv[2:])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
