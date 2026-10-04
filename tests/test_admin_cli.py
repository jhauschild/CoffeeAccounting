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


def test_create_admin_via_stdin_and_prompt(monkeypatch, capsys):
    assert run("create-admin", "--username", "boss", "--role", "global", "--password-stdin",
               stdin=PASSWORD + "\n", monkeypatch=monkeypatch) == 0
    answers = iter([PASSWORD, PASSWORD])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    assert run("create-admin", "--username", "boss2", "--role", "global") == 0
    with read_session() as r:
        a = admin_auth.get_by_username(r, "boss2")
        assert a.role == "global" and a.user_id is None and not a.totp_enabled
        assert admin_auth.verify_password(a.password_hash, PASSWORD)
        assert r.scalars(select(AuditLog).where(AuditLog.action == "admin.created")).first().actor_type == "system"
    out = capsys.readouterr()
    assert PASSWORD not in out.out + out.err
    assert "enrolled once" in out.out


def test_create_admin_rejects_weak_password_group_role_and_mismatch(monkeypatch, capsys):
    assert run("create-admin", "--username", "x", "--role", "global", "--password-stdin", stdin="short\n",
               monkeypatch=monkeypatch) == 1
    # group admins are promoted members (task 4.3); the CLI cannot create them
    assert run("create-admin", "--username", "x", "--role", "chair", "--password-stdin",
               stdin=PASSWORD + "\n", monkeypatch=monkeypatch) == 1
    answers = iter([PASSWORD, NEW_PASSWORD])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    assert run("create-admin", "--username", "x", "--role", "global") == 1
    assert "error:" in capsys.readouterr().err
    with read_session() as r:
        assert admin_auth.list_admins(r) == []


def test_create_admin_refuses_a_username_held_by_a_user(db, chair, monkeypatch, capsys):
    from tests import factories
    factories.make_member(db, username="Alice", chair=chair)
    assert run("create-admin", "--username", "alice", "--role", "global", "--password-stdin",
               stdin=PASSWORD + "\n", monkeypatch=monkeypatch) == 1
    assert "already exists" in capsys.readouterr().err
    with read_session() as r:
        assert admin_auth.list_admins(r) == []


def test_set_admin_chairs_command_is_removed(monkeypatch):
    with pytest.raises(SystemExit):
        run("set-admin-chairs", "--username", "x", "--chair", "A")


def test_management_commands(monkeypatch, capsys):
    make_real_admin(username="cadmin")
    assert run("reset-admin-password", "--username", "cadmin", "--password-stdin", stdin=NEW_PASSWORD + "\n",
               monkeypatch=monkeypatch) == 0
    assert run("reset-admin-totp", "--username", "cadmin") == 0
    assert run("disable-admin", "--username", "cadmin") == 0
    assert run("disable-admin", "--username", "missing") == 1
    with read_session() as r:
        a = admin_auth.get_by_username(r, "cadmin")
        assert not a.active and not a.totp_enabled
        assert admin_auth.verify_password(a.password_hash, NEW_PASSWORD)
        actions = [x.action for x in r.scalars(select(AuditLog))]
    assert {"admin.password_reset", "admin.totp_reset", "admin.disabled"} <= set(actions)
    assert run("disable-admin", "--username", "cadmin", "--enable") == 0
    assert run("list-admins") == 0
    assert "cadmin\tglobal\tchairs=-\tactive\ttotp=off" in capsys.readouterr().out


def test_reset_admin_password_is_refused_for_a_group_admin(chair, monkeypatch, capsys):
    make_real_admin(role="chair", chairs=[chair], username="gadmin", totp=False)
    assert run("reset-admin-password", "--username", "gadmin", "--password-stdin", stdin=NEW_PASSWORD + "\n",
               monkeypatch=monkeypatch) == 1
    assert "account password" in capsys.readouterr().err
    assert run("list-admins") == 0
    assert f"gadmin\tchair\tchairs={chair.short_name}\tactive\ttotp=off" in capsys.readouterr().out


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
    for kind in ("register", "single", "double", "website"):
        assert (tmp_path / "qr" / f"coffee-{kind}.svg").exists()
    out = capsys.readouterr().out
    assert "http://testserver/overview" in out and "http://testserver/coffee/double" in out
