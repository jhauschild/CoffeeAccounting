"""Task 4.5: CLI `setup-mail`, `mail-status`, `test-mail`, `clear-mail`, `setup`; cross-process mail status."""

from __future__ import annotations

import io
import logging
import os
import stat
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from app import cli
from app.db import read_session, write_session
from app.models import AdminUser, AuditLog, Price
from app.services import mail, mail_credentials, mail_status
from app.timeutil import utcnow
from tests.admin_support import NEW_PASSWORD, PASSWORD, fast_hasher  # noqa: F401
from tests.conftest import ROOT, reload_settings
from tests.test_platform_smtp import (  # noqa: F401  (fixtures and constants of the fake SMTP server)
    LOGIN, PASSWORD as SMTP_PASSWORD, configure, pki, server_ctx, start_relay,
)

SMTP_USER = "coffee@lrz.test"
SECRET_PW = "Hunter2-very-secret-mail-pw"


@pytest.fixture(autouse=True)
def secrets_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path / "secrets"))
    monkeypatch.setenv("MAIL_BACKEND", "memory")
    reload_settings()
    mail.reset_status()
    mail.clear_outbox()
    yield
    mail.reset_status()
    mail.clear_outbox()


def run(*argv, stdin=None, monkeypatch=None):
    if stdin is not None:
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    return cli.main(list(argv))


def script_getpass(monkeypatch, *answers):
    queue = iter(answers)
    prompts = []

    def fake(prompt=""):
        prompts.append(prompt)
        return next(queue)

    monkeypatch.setattr("getpass.getpass", fake)
    return prompts


def script_input(monkeypatch, *answers):
    queue = iter(answers)
    monkeypatch.setattr("builtins.input", lambda prompt="": next(queue))


def audit_actions() -> list[str]:
    with read_session() as r:
        return [a.action for a in r.scalars(select(AuditLog).order_by(AuditLog.id))]


def no_secret(*texts):
    blob = "\n".join(texts)
    for secret in (SECRET_PW, SMTP_PASSWORD, PASSWORD):
        assert secret not in blob
    assert SMTP_USER not in blob  # the username shows masked only


# ----- setup-mail -----------------------------------------------------------------------------------------------


def test_setup_mail_prompts_hidden_and_stores_encrypted(monkeypatch, capsys, caplog, tmp_path):
    caplog.set_level(logging.DEBUG)
    prompts = script_getpass(monkeypatch, SMTP_USER, SECRET_PW, SECRET_PW)
    assert run("setup-mail") == 0
    out = capsys.readouterr()
    assert len(prompts) == 3  # username, password, repeat: all through getpass (hidden)
    assert "c***@lrz.test" in out.out
    no_secret(out.out, out.err, caplog.text)
    creds = mail_credentials.load_credentials()
    assert (creds.username, creds.password) == (SMTP_USER, SECRET_PW)
    path = mail_credentials.credentials_path()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert SECRET_PW.encode() not in path.read_bytes()  # encrypted
    assert "mail.login_saved" in audit_actions()
    with read_session() as r:
        dump = " ".join(str(a.meta) for a in r.scalars(select(AuditLog)))
    assert SECRET_PW not in dump and SMTP_USER not in dump


def test_setup_mail_password_mismatch_stores_nothing(monkeypatch, capsys):
    script_getpass(monkeypatch, SMTP_USER, SECRET_PW, SECRET_PW + "x")
    assert run("setup-mail") == 1
    out = capsys.readouterr()
    assert "do not match" in out.err
    no_secret(out.out, out.err)
    assert not mail_credentials.credentials_path().exists()


def test_setup_mail_empty_password_is_refused_without_echo(monkeypatch, capsys):
    script_getpass(monkeypatch, SMTP_USER, "", "")
    assert run("setup-mail") == 1
    assert not mail_credentials.credentials_path().exists()


@pytest.mark.parametrize("argv", [
    ("setup-mail", "--password", "x"),
    ("setup-mail", "--password"),  # not an abbreviation of --password-stdin either
    ("setup-mail", "--pass", "x"),
    ("setup-mail", "--password=x"),
    ("create-admin", "--username", "a", "--role", "global", "--password", "x"),
    ("create-admin", "--username", "a", "--role", "global", "--password"),
    ("reset-admin-password", "--username", "a", "--password", "x"),
])
def test_password_option_does_not_exist(argv, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(list(argv))
    assert exc.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err
    assert not mail_credentials.credentials_path().exists()


def test_no_command_has_a_password_option():
    parser = cli.build_parser()
    for action in parser._subparsers._group_actions[0].choices.values():
        options = [opt for a in action._actions for opt in a.option_strings]
        assert "--password" not in options, action.prog


def test_setup_mail_password_stdin_for_scripted_installs(monkeypatch, capsys):
    assert run("setup-mail", "--password-stdin", stdin=f"{SMTP_USER}\n{SECRET_PW}\n", monkeypatch=monkeypatch) == 0
    out = capsys.readouterr()
    no_secret(out.out, out.err)
    assert mail_credentials.load_credentials().password == SECRET_PW
    # with --username the stdin carries the password only
    assert run("setup-mail", "--username", "other@lrz.test", "--password-stdin", stdin="second-secret-pw\n",
               monkeypatch=monkeypatch) == 0
    creds = mail_credentials.load_credentials()
    assert (creds.username, creds.password) == ("other@lrz.test", "second-secret-pw")


def test_setup_mail_via_subprocess_keeps_password_out_of_argv_and_output(tmp_path):
    env = dict(os.environ)
    proc = subprocess.run([sys.executable, "-m", "app.cli", "setup-mail", "--password-stdin"], cwd=ROOT, env=env,
                          input=f"{SMTP_USER}\n{SECRET_PW}\n", capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    no_secret(proc.stdout, proc.stderr)
    assert "c***@lrz.test" in proc.stdout
    assert mail_credentials.load_credentials().password == SECRET_PW
    status = subprocess.run([sys.executable, "-m", "app.cli", "mail-status"], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=60)
    assert status.returncode == 0 and "mail configured: yes, user c***@lrz.test" in status.stdout
    no_secret(status.stdout, status.stderr)


def test_setup_mail_refuses_when_secrets_dir_is_not_writable(monkeypatch, capsys, tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("a file, not a directory")
    monkeypatch.setenv("SECRETS_DIR", str(blocker / "secrets"))
    reload_settings()

    def must_not_prompt(prompt=""):
        raise AssertionError("must not prompt before the directory check")

    monkeypatch.setattr("getpass.getpass", must_not_prompt)
    assert run("setup-mail") == 1
    err = capsys.readouterr().err
    assert "SECRETS_DIR" in err and "not writable" in err and "README" in err


def test_setup_mail_refuses_when_the_directory_rejects_writes(monkeypatch, capsys):
    def refuse(*args, **kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr("app.cli_setup.tempfile.mkstemp", refuse)  # a read-only mount, even when running as root
    script_getpass(monkeypatch, SMTP_USER, SECRET_PW, SECRET_PW)
    assert run("setup-mail") == 1
    assert "not writable" in capsys.readouterr().err
    assert not mail_credentials.credentials_path().exists()


# ----- mail-status ----------------------------------------------------------------------------------------------


def persist(category, minutes_ago=0):
    with write_session() as w:
        return mail_status.persist(w, category, now=utcnow() - timedelta(minutes=minutes_ago))


def test_mail_status_not_configured(capsys):
    assert run("mail-status") == 0
    out = capsys.readouterr().out
    assert "mail configured: no" in out and "last send OK: never" in out and "last failure: none" in out


def test_mail_status_configured_masked_and_last_results(capsys):
    mail_credentials.save_credentials(SMTP_USER, SECRET_PW)
    persist("auth", minutes_ago=30)
    persist(None, minutes_ago=5)
    assert run("mail-status") == 0
    out = capsys.readouterr()
    assert "mail configured: yes, user c***@lrz.test" in out.out
    assert "last failure: auth at " in out.out and "last send OK: never" not in out.out
    assert "state: ok" in out.out
    no_secret(out.out, out.err)


def test_mail_status_failing_and_cap_reached_states(capsys):
    mail_credentials.save_credentials(SMTP_USER, SECRET_PW)
    persist(None, minutes_ago=20)
    persist("connect", minutes_ago=10)
    run("mail-status")
    assert "state: mail failing: connect" in capsys.readouterr().out
    persist("cap_exceeded", minutes_ago=1)
    run("mail-status")
    out = capsys.readouterr().out
    assert "state: cap reached" in out and "nothing is broken" in out and "mail failing" not in out
    persist(None)  # a success after the cap clears it
    run("mail-status")
    assert "state: ok" in capsys.readouterr().out


def test_mail_status_unreadable_after_key_change(monkeypatch, capsys):
    mail_credentials.save_credentials(SMTP_USER, SECRET_PW)
    monkeypatch.setenv("SECRET_KEY", "a-completely-different-secret-key-0123456789")
    reload_settings()
    assert run("mail-status") == 0
    out = capsys.readouterr().out
    assert "mail login unreadable: re-run setup-mail" in out and "mail configured: no" in out
    no_secret(out)


def test_mail_status_smtp_backend_shows_host_and_banner_state(monkeypatch, capsys):
    monkeypatch.setenv("MAIL_BACKEND", "smtp")
    reload_settings()
    run("mail-status")
    out = capsys.readouterr().out
    assert "backend: smtp (postout.lrz.de:587, starttls)" in out and "state: mail not configured" in out


def test_mail_status_works_across_processes(tmp_path):
    """A send recorded by one process (here: this one, through test-mail) is what a fresh process reads."""
    assert run("test-mail", "alice@tum.de") == 0
    status = subprocess.run([sys.executable, "-m", "app.cli", "mail-status"], cwd=ROOT, env=dict(os.environ),
                            capture_output=True, text=True, timeout=60)
    assert status.returncode == 0 and "last send OK: never" not in status.stdout, status.stdout


# ----- persisted status rows ------------------------------------------------------------------------------------


def test_persist_writes_category_only_and_coalesces_within_ten_minutes():
    assert persist("auth", 30) and not persist("auth", 25)  # same failure inside 10 minutes of the last row
    assert persist("auth", 15)  # older than 10 minutes: written again
    assert persist("tls", 14)  # another category is always written
    assert persist(None, 13) and not persist(None, 12) and not persist(None, 4)
    assert persist("timeout", 3) and persist(None, 2)  # state flips are always written
    with read_session() as r:
        rows = list(r.scalars(select(AuditLog).where(AuditLog.action.like("mail.send_%")).order_by(AuditLog.id)))
        assert [(a.action, (a.meta or {}).get("category")) for a in rows] == [
            ("mail.send_failed", "auth"), ("mail.send_failed", "auth"), ("mail.send_failed", "tls"),
            ("mail.send_ok", None), ("mail.send_failed", "timeout"), ("mail.send_ok", None)]
        assert all(a.actor_type == "system" and a.source_ip is None and a.target_id is None for a in rows)
        assert all(set(a.meta or {}) <= {"category"} for a in rows)


def test_persist_maps_unknown_category_to_other():
    persist("Connection refused by alice@tum.de")
    with read_session() as r:
        assert mail_status.read_status(r).last_failure_category == "other"
        assert "alice" not in " ".join(str(a.meta) for a in r.scalars(select(AuditLog)))


def test_send_in_background_persists_status(monkeypatch):
    msg = mail.build_message(to="alice@tum.de", subject="Hi", body="Hello")
    assert mail.send_in_background(msg) is None
    with read_session() as r:
        assert mail_status.read_status(r).last_ok_at is not None
    monkeypatch.setattr(mail.MemoryMailer, "send", lambda self, m: (_ for _ in ()).throw(mail.MailError("connect")))
    assert mail.send_in_background(mail.build_message(to="bob@tum.de", subject="Hi", body="Hello")) == "connect"
    with read_session() as r:
        status = mail_status.read_status(r)
        assert status.last_failure_category == "connect"
        assert "bob@tum.de" not in " ".join(str(a.meta) for a in r.scalars(select(AuditLog)))


def test_send_in_background_survives_a_broken_status_store(monkeypatch):
    monkeypatch.setattr(mail_status, "persist", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db gone")))
    assert mail.send_in_background(mail.build_message(to="alice@tum.de", subject="Hi", body="Hello")) is None
    assert len(mail.get_outbox()) == 1


# ----- test-mail ------------------------------------------------------------------------------------------------


def test_test_mail_memory_backend_sends_and_records(capsys):
    assert run("test-mail", "Alice@TUM.de") == 0
    out = capsys.readouterr().out
    assert "Test mail sent to alice@tum.de" in out
    assert [m.to for m in mail.get_outbox()] == ["alice@tum.de"]
    assert mail.get_outbox()[0].subject == "Coffee ledger test mail"
    assert mail.get_status().last_ok_at is not None  # in-process status
    with read_session() as r:
        assert mail_status.read_status(r).last_ok_at is not None  # persisted status


def test_test_mail_invalid_address(capsys):
    assert run("test-mail", "not an address") == 2
    assert "not a valid e-mail address" in capsys.readouterr().err
    assert mail.get_outbox() == []


def test_test_mail_failure_prints_category_only(monkeypatch, capsys):
    monkeypatch.setattr(mail.MemoryMailer, "send", lambda self, m: (_ for _ in ()).throw(mail.MailError("tls")))
    assert run("test-mail", "alice@tum.de") == 1
    err = capsys.readouterr().err
    assert "test mail failed: tls" in err and "Traceback" not in err
    with read_session() as r:
        assert mail_status.read_status(r).last_failure_category == "tls"


def test_test_mail_smtp_without_login_or_with_unreadable_login(monkeypatch, capsys):
    monkeypatch.setenv("MAIL_BACKEND", "smtp")
    reload_settings()
    assert run("test-mail", "alice@tum.de") == 1
    assert "not configured" in capsys.readouterr().err
    mail_credentials.save_credentials(SMTP_USER, SECRET_PW)
    monkeypatch.setenv("SECRET_KEY", "a-completely-different-secret-key-0123456789")
    reload_settings()
    assert run("test-mail", "alice@tum.de") == 1
    err = capsys.readouterr().err
    assert "mail login unreadable: re-run setup-mail" in err
    no_secret(err)


@pytest.fixture
def relay_env(tmp_path, monkeypatch, pki):
    import ssl

    monkeypatch.setenv("MAIL_BACKEND", "smtp")
    monkeypatch.setenv("MAIL_FROM", "Coffee Ledger <coffee@example.org>")
    monkeypatch.setenv("SMTP_HOST", "localhost")
    reload_settings()
    monkeypatch.setattr(mail, "ssl_context_factory", lambda: ssl.create_default_context(cadata=pki["ca_pem"]))


def test_test_mail_through_the_fake_smtp_server(relay_env, start_relay, monkeypatch, capsys, caplog):
    caplog.set_level(logging.DEBUG)
    relay, port = start_relay("starttls")
    configure(monkeypatch, port=port, security="starttls")
    mail_credentials.save_credentials(LOGIN, SMTP_PASSWORD)
    assert run("test-mail", "alice@tum.de") == 0
    out = capsys.readouterr()
    assert len(relay.messages) == 1 and relay.auth_attempts == [(LOGIN, SMTP_PASSWORD)]
    assert relay.sessions == [(True, True)]
    assert SMTP_PASSWORD not in out.out + out.err + "".join(r.getMessage() for r in caplog.records
                                                            if r.name.startswith("app."))
    run("mail-status")
    status = capsys.readouterr().out
    assert "last send OK: never" not in status and "state: ok" in status


def test_test_mail_wrong_password_prints_auth_category_not_credentials(relay_env, start_relay, monkeypatch, capsys):
    relay, port = start_relay("starttls")
    configure(monkeypatch, port=port, security="starttls")
    mail_credentials.save_credentials(LOGIN, "wrong-password-xyz")
    assert run("test-mail", "alice@tum.de") == 1
    out = capsys.readouterr()
    assert "test mail failed: auth" in out.err and relay.messages == []
    assert "wrong-password-xyz" not in out.out + out.err and LOGIN not in out.out + out.err
    run("mail-status")
    status = capsys.readouterr().out
    assert "last failure: auth at " in status and "state: mail failing: auth" in status
    assert "wrong-password-xyz" not in status


def test_test_mail_connection_refused_is_category_connect(relay_env, monkeypatch, capsys):
    configure(monkeypatch, port=1, security="starttls", host="127.0.0.1")
    mail_credentials.save_credentials(LOGIN, SMTP_PASSWORD)
    assert run("test-mail", "alice@tum.de") == 1
    assert "test mail failed: connect" in capsys.readouterr().err


# ----- clear-mail -----------------------------------------------------------------------------------------------


def test_clear_mail(monkeypatch, capsys):
    mail_credentials.save_credentials(SMTP_USER, SECRET_PW)
    script_input(monkeypatch, "n")
    assert run("clear-mail") == 0 and mail_credentials.credentials_path().exists()
    script_input(monkeypatch, "y")
    assert run("clear-mail") == 0 and not mail_credentials.credentials_path().exists()
    assert "mail.login_cleared" in audit_actions()
    assert run("clear-mail", "--yes") == 0
    assert "No mail login was stored" in capsys.readouterr().out


# ----- setup (guided) -------------------------------------------------------------------------------------------


def test_setup_runs_every_step(monkeypatch, capsys):
    script_input(monkeypatch,
                 "", "boss",   # create the head admin: default yes, username
                 "",           # store the mail login: default yes
                 "", "0.50",   # first price: default yes, amount
                 "y", "alice@tum.de")  # test mail
    script_getpass(monkeypatch, PASSWORD, PASSWORD,  # admin password twice
                   SMTP_USER, SECRET_PW, SECRET_PW)  # mail login
    assert run("setup") == 0
    out = capsys.readouterr()
    assert "Setup finished" in out.out and "enrolled once, at the first login" in out.out
    no_secret(out.out, out.err)
    with read_session() as r:
        admin = r.scalars(select(AdminUser)).one()
        assert (admin.username, admin.role, admin.totp_enabled) == ("boss", "global", False)
        assert r.scalars(select(Price)).one().price_per_shot_cents == 50
    assert mail_credentials.status().configured
    assert [m.to for m in mail.get_outbox()] == ["alice@tum.de"]


def test_setup_every_step_is_skippable(monkeypatch, capsys):
    script_input(monkeypatch, "n", "n", "n", "n")  # admin, mail, price, test mail
    script_getpass(monkeypatch)
    assert run("setup") == 0
    assert "Setup finished" in capsys.readouterr().out
    with read_session() as r:
        assert r.scalars(select(AdminUser)).first() is None and r.scalars(select(Price)).first() is None
    assert not mail_credentials.credentials_path().exists() and mail.get_outbox() == []


def test_setup_reports_a_failed_step_and_continues(monkeypatch, capsys):
    script_input(monkeypatch, "", "boss", "n", "n", "n")
    script_getpass(monkeypatch, PASSWORD, NEW_PASSWORD)  # mismatch
    assert run("setup") == 1
    out = capsys.readouterr()
    assert "passwords do not match" in out.err and "Not completed: 1. Head administrator" in out.out
    with read_session() as r:
        assert r.scalars(select(AdminUser)).first() is None


def test_setup_stops_cleanly_without_a_terminal(monkeypatch):
    def eof(prompt=""):
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    with pytest.raises(SystemExit) as exc:
        run("setup")
    assert "interactive terminal" in str(exc.value)


def test_each_setup_step_also_exists_alone(capsys):
    commands = cli.build_parser()._subparsers._group_actions[0].choices
    assert {"create-admin", "setup-mail", "set-price", "test-mail", "mail-status", "clear-mail", "setup"} <= set(commands)
    # existing commands keep working
    assert run("list-admins") == 0 and run("bootstrap-admin") == 0


def test_readme_mentions_the_docker_invocation():
    readme = (Path(ROOT) / "README.md").read_text()
    assert "docker compose run --rm -it app python -m app.cli setup-mail" in readme
    assert "--password-stdin" in readme and "mail-status" in readme and "test-mail" in readme
