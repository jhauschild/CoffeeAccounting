"""Backup/restore scripts (scripts/backup.sh, restore.sh, dbtool.py) against a real migrated SQLite file."""

from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")


def _env(db: Path, **extra) -> dict:
    env = {k: v for k, v in os.environ.items() if k not in ("DB_PATH", "DATABASE_URL", "BACKUP_DIR", "BACKUP_KEEP")}
    env.update(DATABASE_URL=f"sqlite:///{db}", ENVIRONMENT="development", PYTHON=sys.executable,
               PYTHONPATH=str(ROOT), **extra)
    return env


def _run(args, env, **kw):
    return subprocess.run(args, env=env, cwd=ROOT, capture_output=True, text=True, timeout=120, **kw)


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "data" / "coffee.db"
    path.parent.mkdir()
    env = _env(path)
    assert _run([sys.executable, "-m", "alembic", "upgrade", "head"], env).returncode == 0
    done = _run([sys.executable, "-m", "app.cli", "set-price", "--cents", "50"], env)
    assert done.returncode == 0, done.stderr
    return path


def _prices(path: Path) -> int:
    conn = sqlite3.connect(path)
    try:
        return conn.execute("SELECT count(*) FROM prices").fetchone()[0]
    finally:
        conn.close()


def _add_price(path: Path, cents: int) -> None:
    done = _run([sys.executable, "-m", "app.cli", "set-price", "--cents", str(cents)], _env(path))
    assert done.returncode == 0, done.stderr


def test_backup_is_consistent_while_a_connection_has_unflushed_wal(db, tmp_path):
    live = sqlite3.connect(db)
    live.execute("PRAGMA wal_autocheckpoint=0")
    live.execute("INSERT INTO chairs (id, full_name, short_name, active, created_at) "
                 "VALUES ('c1', 'Chair of Tests', 'TST', 1, '2026-01-01 00:00:00')")
    live.commit()
    assert (db.parent / "coffee.db-wal").stat().st_size > 0  # the new row lives only in the WAL
    out = tmp_path / "bk"
    done = _run(["bash", str(SCRIPTS / "backup.sh"), str(out)], _env(db))
    live.close()
    assert done.returncode == 0, done.stderr
    (backup,) = out.glob("coffee-*.db")
    assert oct(backup.stat().st_mode & 0o777) == "0o600"
    conn = sqlite3.connect(backup)
    try:
        assert conn.execute("SELECT short_name FROM chairs").fetchall() == [("TST",)]
        assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    finally:
        conn.close()
    assert not list(out.glob(".*partial"))


def test_backup_retention_keeps_newest_n_and_ignores_other_files(db, tmp_path):
    out = tmp_path / "bk"
    out.mkdir()
    for stamp in ("20200101T000000Z", "20200102T000000Z", "20200103T000000Z"):
        (out / f"coffee-{stamp}.db").write_text("old")
    (out / "pre-restore-20200101T000000Z.db").write_text("keep me")
    done = _run(["bash", str(SCRIPTS / "backup.sh"), str(out)], _env(db, BACKUP_KEEP="2"))
    assert done.returncode == 0, done.stderr
    names = sorted(p.name for p in out.iterdir())
    assert names[0] == "coffee-20200103T000000Z.db" and len(names) == 3 and "pre-restore-20200101T000000Z.db" in names
    assert any(n.startswith("coffee-2") and n > "coffee-2026" for n in names)  # the fresh backup survived


def test_backup_fails_cleanly_without_database(tmp_path):
    done = _run(["bash", str(SCRIPTS / "backup.sh"), str(tmp_path / "bk")], _env(tmp_path / "missing.db"))
    assert done.returncode == 1 and "database not found" in done.stderr


def test_restore_round_trip(db, tmp_path):
    out = tmp_path / "bk"
    assert _run(["bash", str(SCRIPTS / "backup.sh"), str(out)], _env(db)).returncode == 0
    (backup,) = out.glob("coffee-*.db")
    _add_price(db, 60)
    assert _prices(db) == 2
    (db.parent / "coffee.db-wal").write_bytes(b"stale")  # leftovers of the replaced database must be removed
    done = _run(["bash", str(SCRIPTS / "restore.sh"), str(backup), "--yes"], _env(db, BACKUP_DIR=str(out)))
    assert done.returncode == 0, done.stderr
    assert _prices(db) == 1
    assert not (db.parent / "coffee.db-wal").exists() or (db.parent / "coffee.db-wal").read_bytes() != b"stale"
    (safety,) = out.glob("pre-restore-*.db")
    assert _prices(safety) == 2  # the replaced database was preserved
    # the restored database is a working ledger: the application CLI accepts it
    assert _run([sys.executable, "-m", "app.cli", "check-ledger"], _env(db)).returncode == 0


def test_restore_refuses_while_database_is_open(db, tmp_path):
    out = tmp_path / "bk"
    assert _run(["bash", str(SCRIPTS / "backup.sh"), str(out)], _env(db)).returncode == 0
    (backup,) = out.glob("coffee-*.db")
    live = sqlite3.connect(db)
    try:
        live.execute("PRAGMA journal_mode=WAL")
        live.execute("SELECT count(*) FROM prices").fetchone()
        done = _run(["bash", str(SCRIPTS / "restore.sh"), str(backup), "--yes"], _env(db))
    finally:
        live.close()
    assert done.returncode == 1 and "stop the application" in done.stderr
    assert _prices(db) == 1


def test_restore_rejects_bad_backups_and_missing_confirmation(db, tmp_path):
    garbage = tmp_path / "garbage.db"
    garbage.write_bytes(b"not a database" * 100)
    empty = tmp_path / "empty.db"
    sqlite3.connect(empty).close()
    other = tmp_path / "other.db"
    conn = sqlite3.connect(other)
    conn.execute("CREATE TABLE t (x)")
    conn.commit()
    conn.close()
    for bad in (garbage, empty, other):
        done = _run(["bash", str(SCRIPTS / "restore.sh"), str(bad), "--yes"], _env(db))
        assert done.returncode == 1 and "failed verification" in done.stderr, bad
    assert _prices(db) == 1
    assert _run(["bash", str(SCRIPTS / "restore.sh"), str(garbage)], _env(db)).returncode == 2


def test_readme_cli_examples_match_the_real_parser():
    import re

    from app.cli import build_parser

    parser = build_parser()
    readme = (ROOT / "README.md").read_text()
    commands = re.findall(r"python -m app\.cli ([a-z-]+[^\n`]*)", readme)
    assert len(commands) >= 10
    seen = set()
    for line in commands:
        line = line.split("#")[0].strip()
        line = re.sub(r"\s+\(.*$", "", line)  # prose in parentheses after an example
        argv = [a for a in line.split() if a not in ("...",)]
        argv = [a.strip("[]") if a.startswith("[") else a for a in argv]
        if "SHORT" in " ".join(argv) or "U" in argv:
            argv = [{"SHORT": "x", "U": "u"}.get(a, a) for a in argv]
        argv = [a for a in argv if not a.endswith("]") or not a.startswith("[")]
        args = parser.parse_args(argv)  # raises SystemExit on an unknown command or flag
        seen.add(args.command)
    assert {"create-admin", "set-price", "check-ledger", "purge-expired", "qr", "list-admins", "setup",
            "setup-mail", "mail-status", "test-mail", "clear-mail"} <= seen
    for name in ("reset-admin-password", "reset-admin-totp", "disable-admin", "bootstrap-admin"):
        assert name in readme


def test_readme_documents_every_environment_variable_and_the_required_sentence():
    from app.config import Settings

    readme = (ROOT / "README.md").read_text()
    env_example = (ROOT / ".env.example").read_text()
    for field in Settings.model_fields:
        assert f"`{field.upper()}`" in readme, field
        assert field.upper() in env_example, field
    assert ("Identity is a verified TUM email (members) or a member's vouching (guests), plus a password. "
            "It does not prove the user's real-world identity. This is intentional for a low-stakes, "
            "trust-based departmental coffee ledger.") in readme
    assert "voluntary profile selection" not in readme
    assert "Normal-user identity is based on" not in readme
