"""Admin CLI commands (`python -m app.cli ...`)."""

from __future__ import annotations

import io

import pytest
from sqlalchemy import select

from app import cli
from app.db import read_session, write_session
from app.models import AdminUser, AuditLog
from app.services import admin_auth
from tests.admin_support import NEW_PASSWORD, PASSWORD, fast_hasher, make_real_admin  # noqa: F401


def run(*argv, stdin=None, monkeypatch=None):
    if stdin is not None:
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    return cli.main(list(argv))


def test_create_admin_via_stdin_and_prompt(chair, monkeypatch, capsys):
    assert run("create-admin", "--username", "boss", "--role", "global", "--password-stdin",
               stdin=PASSWORD + "\n", monkeypatch=monkeypatch) == 0
    answers = iter([PASSWORD, PASSWORD])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    assert run("create-admin", "--username", "boss2", "--role", "chair", "--chair", chair.short_name) == 0
    with read_session() as r:
        a = admin_auth.get_by_username(r, "boss2")
        assert a.role == "chair" and [c.id for c in a.chairs] == [chair.id]
        assert admin_auth.verify_password(a.password_hash, PASSWORD)
        assert r.scalars(select(AuditLog).where(AuditLog.action == "admin.created")).first().actor_type == "system"
    out = capsys.readouterr()
    assert PASSWORD not in out.out + out.err


def test_create_admin_rejects_weak_password_unknown_chair_and_mismatch(monkeypatch, capsys):
    assert run("create-admin", "--username", "x", "--role", "global", "--password-stdin", stdin="short\n",
               monkeypatch=monkeypatch) == 1
    assert run("create-admin", "--username", "x", "--role", "chair", "--chair", "NOPE", "--password-stdin",
               stdin=PASSWORD + "\n", monkeypatch=monkeypatch) == 1
    answers = iter([PASSWORD, NEW_PASSWORD])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    assert run("create-admin", "--username", "x", "--role", "global") == 1
    assert "error:" in capsys.readouterr().err
    with read_session() as r:
        assert admin_auth.list_admins(r) == []


def test_management_commands(chair, other_chair, monkeypatch, capsys):
    make_real_admin(role="chair", chairs=[chair], username="cadmin")
    assert run("set-admin-chairs", "--username", "cadmin", "--chair", other_chair.short_name) == 0
    assert run("reset-admin-password", "--username", "cadmin", "--password-stdin", stdin=NEW_PASSWORD + "\n",
               monkeypatch=monkeypatch) == 0
    assert run("reset-admin-totp", "--username", "cadmin") == 0
    assert run("disable-admin", "--username", "cadmin") == 0
    assert run("disable-admin", "--username", "missing") == 1
    with read_session() as r:
        a = admin_auth.get_by_username(r, "cadmin")
        assert [c.id for c in a.chairs] == [other_chair.id] and not a.active and not a.totp_enabled
        assert admin_auth.verify_password(a.password_hash, NEW_PASSWORD)
        actions = [x.action for x in r.scalars(select(AuditLog))]
    assert {"admin.chairs_set", "admin.password_reset", "admin.totp_reset", "admin.disabled"} <= set(actions)
    assert run("disable-admin", "--username", "cadmin", "--enable") == 0
    assert run("list-admins") == 0
    assert "cadmin\tchair\tchairs=CHB\tactive\ttotp=off" in capsys.readouterr().out


def test_bootstrap_command(monkeypatch):
    from tests.conftest import reload_settings
    assert run("bootstrap-admin") == 0  # variables unset: nothing happens
    monkeypatch.setenv("ADMIN_BOOTSTRAP_USERNAME", "first")
    monkeypatch.setenv("ADMIN_BOOTSTRAP_PASSWORD", PASSWORD)
    reload_settings()
    assert run("bootstrap-admin") == 0 and run("bootstrap-admin") == 0
    with read_session() as r:
        assert [a.username for a in admin_auth.list_admins(r)] == ["first"]


def test_qr_command_writes_files(tmp_path, capsys):
    assert run("qr", "--out", str(tmp_path / "qr")) == 0
    assert (tmp_path / "qr" / "coffee-single.svg").exists()
    assert "http://testserver/coffee/double" in capsys.readouterr().out
