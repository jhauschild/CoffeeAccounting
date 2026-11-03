"""v2 ops: compose secrets volume, no mail login in deployment files, .env.example, backup without secrets,
smoke script, README and architecture content (task 6.1). No Docker daemon is needed (or used)."""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")

# Setting names that would carry the mail LOGIN (as opposed to host, port, security, sender).
LOGIN_NAMES = re.compile(r"(SMTP|MAIL)_(USER|USERNAME|LOGIN|PASSWORD|PASS|SECRET|TOKEN)\b", re.IGNORECASE)


def _text(name: str) -> str:
    return (ROOT / name).read_text()


# ----- compose -------------------------------------------------------------------------------------
def _compose() -> dict:
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load(_text("docker-compose.yml"))


def test_compose_has_a_dedicated_secrets_volume_mounted_only_into_the_app():
    compose = _compose()
    assert set(compose["volumes"]) == {"coffee_data", "secrets"}
    assert list(compose["services"]) == ["app"]  # one service, one replica
    app = compose["services"]["app"]
    mounts = {v.split(":")[0]: v.split(":")[1] for v in app["volumes"]}
    assert mounts["secrets"] == "/secrets"
    assert mounts["coffee_data"] == "/data"
    assert app["environment"]["SECRETS_DIR"] == "/secrets"
    # the secrets volume is mounted exactly once, and the backup bind mount is a different target
    assert [v for v in app["volumes"] if v.startswith("secrets:")] == ["secrets:/secrets"]
    backup_mounts = [v for v in app["volumes"] if "/backups" in v]
    assert len(backup_mounts) == 1 and "secrets" not in backup_mounts[0]
    assert app["environment"]["BACKUP_DIR"] == "/backups"
    assert "deploy" not in app  # no replicas


def test_compose_passes_mail_settings_but_no_mail_login():
    app = _compose()["services"]["app"]
    env = app["environment"]
    assert env["MAIL_BACKEND"] == "smtp" and env["ENVIRONMENT"] == "production"
    for name in ("SMTP_HOST", "SMTP_PORT", "SMTP_SECURITY", "MAIL_FROM"):
        assert name in env, name
    assert "postout.lrz.de" in env["SMTP_HOST"] and "587" in env["SMTP_PORT"]
    assert app["env_file"] == ".env"
    compose_text = _text("docker-compose.yml")
    assert not LOGIN_NAMES.search(compose_text)
    # comments excluded, no assignment of a login-like value anywhere
    for line in compose_text.splitlines():
        code = line.split("#", 1)[0]
        assert "password" not in code.lower() and "SMTP_USER" not in code, line


def test_compose_config_renders_with_the_example_env(tmp_path):
    if shutil.which("docker") is None:
        pytest.skip("docker CLI not available")
    shutil.copy(ROOT / "docker-compose.yml", tmp_path / "docker-compose.yml")
    shutil.copy(ROOT / ".env.example", tmp_path / ".env")
    done = subprocess.run(["docker", "compose", "config", "--format", "json"], cwd=tmp_path, capture_output=True,
                          text=True, timeout=60)
    if done.returncode != 0 and "compose" in done.stderr.lower() and "not a docker command" in done.stderr.lower():
        pytest.skip("docker compose plugin not available")
    assert done.returncode == 0, done.stderr
    config = json.loads(done.stdout)
    app = config["services"]["app"]
    targets = {v["target"]: v for v in app["volumes"]}
    assert targets["/secrets"]["type"] == "volume" and targets["/secrets"]["source"] == "secrets"
    assert targets["/backups"]["type"] == "bind"
    assert app["environment"]["MAIL_BACKEND"] == "smtp"
    assert app["environment"]["SMTP_HOST"] == "postout.lrz.de"
    assert app["environment"]["SECRETS_DIR"] == "/secrets"
    assert set(config["volumes"]) == {"coffee_data", "secrets"}


def test_dockerfile_creates_a_private_secrets_dir_and_holds_no_mail_login():
    dockerfile = _text("Dockerfile")
    assert "mkdir -m 0700 /secrets" in dockerfile
    assert "chown app:app /secrets" in dockerfile
    assert dockerfile.index("/secrets") < dockerfile.index("USER app")  # created before dropping to the app user
    assert "SECRETS_DIR=/secrets" in dockerfile
    assert not LOGIN_NAMES.search(dockerfile)
    assert "COPY secrets" not in dockerfile and "COPY .env" not in dockerfile
    assert "workers" not in dockerfile.replace("Exactly one worker", "")  # worker count lives in scripts/run.sh
    ignore = _text(".dockerignore").split()
    for needed in (".env", ".env.*", "backups", "data"):
        assert needed in ignore


# ----- .env.example --------------------------------------------------------------------------------
def test_env_example_documents_the_mail_section_without_a_mail_login():
    env = _text(".env.example")
    assert not LOGIN_NAMES.search(re.sub(r"(?m)^\s*#.*$", "", env)), "a mail login setting is defined"
    for name in ("SMTP_HOST=postout.lrz.de", "SMTP_PORT=587", "SMTP_SECURITY=starttls", "MAIL_FROM="):
        assert re.search(rf"(?m)^{re.escape(name)}", env), name
    assert "465" in env  # the implicit-TLS alternative is explained
    assert "setup-mail" in env
    assert re.search(r"never entered here", env, re.IGNORECASE)
    assert "secrets" in env.lower()


def test_env_example_parses_as_settings_and_covers_every_setting():
    from app.config import Settings

    env = _text(".env.example")
    names = set(re.findall(r"(?m)^#?\s*([A-Z][A-Z0-9_]+)=", env))
    for field in Settings.model_fields:
        assert field.upper() in names, field
    assert "ACCESS_CODE" not in env and "ADMIN_TOTP_REQUIRED" not in env  # removed in v2
    # the file with a real secret and sender is a valid production configuration
    values = {}
    for line in env.splitlines():
        m = re.match(r"([A-Z][A-Z0-9_]+)=(.*)$", line)
        if m:
            values[m.group(1)] = m.group(2).strip().strip('"')
    values["SECRET_KEY"] = "x" * 8 + "Zq7Lw3Vn9Pd2Rk5Tb8Yc1Hf4Jg6Ms0Xa"
    values["MAIL_FROM"] = "Coffee Ledger <coffee@example.org>"
    values["PUBLIC_BASE_URL"] = "https://coffee.example.org"
    values["DATABASE_URL"] = "sqlite:////data/coffee.db"
    values = {k: v for k, v in values.items() if v != "" or k in ("MAIL_FROM", "TRUSTED_PROXY_IPS")}
    values.pop("ADMIN_BOOTSTRAP_USERNAME", None)
    values.pop("ADMIN_BOOTSTRAP_PASSWORD", None)
    settings = Settings(_env_file=None, **{k.lower(): v for k, v in values.items()})
    assert settings.is_production and settings.mail_backend == "smtp"
    assert settings.smtp_host == "postout.lrz.de" and settings.smtp_port == 587
    assert settings.balance_totp_required is True


def test_env_example_secret_is_a_refused_placeholder():
    from app.config import Settings

    env = _text(".env.example")
    secret = re.search(r"(?m)^SECRET_KEY=(.*)$", env).group(1)
    with pytest.raises(ValueError, match="SECRET_KEY"):
        Settings(_env_file=None, environment="production", public_base_url="https://c.example.org", secret_key=secret,
                 mail_from="Coffee <coffee@example.org>")
    with pytest.raises(ValueError, match="MAIL_FROM"):  # the empty sender in the example is refused too
        Settings(_env_file=None, environment="production", public_base_url="https://c.example.org",
                 secret_key="Zq7Lw3Vn9Pd2Rk5Tb8Yc1Hf4Jg6Ms0XaQw2Er4Ty6", mail_from="")


# ----- backup excludes the secrets -------------------------------------------------------------------
def _env(db: Path, secrets: Path, **extra) -> dict:
    env = {k: v for k, v in os.environ.items() if k not in ("DB_PATH", "DATABASE_URL", "BACKUP_DIR", "BACKUP_KEEP",
                                                           "SECRETS_DIR")}
    env.update(DATABASE_URL=f"sqlite:///{db}", ENVIRONMENT="development", PYTHON=sys.executable,
               PYTHONPATH=str(ROOT), SECRETS_DIR=str(secrets), **extra)
    return env


def _run(args, env):
    return subprocess.run(args, env=env, cwd=ROOT, capture_output=True, text=True, timeout=120)


@needs_bash
def test_backup_contains_only_the_database_never_the_secrets(tmp_path):
    secrets = tmp_path / "secrets"
    secrets.mkdir(mode=0o700)
    marker = b"FAKE-MAIL-LOGIN-3f9a1c-do-not-leak"
    (secrets / "mail-login.enc").write_bytes(b"gAAAA" + marker)
    (secrets / "other.txt").write_text("secret too")
    data = tmp_path / "data"
    data.mkdir()
    db = data / "coffee.db"
    env = _env(db, secrets)
    assert _run([sys.executable, "-m", "alembic", "upgrade", "head"], env).returncode == 0
    out = tmp_path / "bk"
    done = _run(["bash", str(SCRIPTS / "backup.sh"), str(out)], env)
    assert done.returncode == 0, done.stderr
    # the backup directory holds one SQLite database and nothing else
    entries = sorted(p.name for p in out.rglob("*"))
    assert len(entries) == 1 and re.fullmatch(r"coffee-\d{8}T\d{6}Z\.db", entries[0]), entries
    (backup,) = out.glob("coffee-*.db")
    assert marker not in backup.read_bytes()
    conn = sqlite3.connect(backup)
    try:
        assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    finally:
        conn.close()
    assert "secret" not in done.stdout.lower() and marker.decode() not in done.stdout + done.stderr
    # the secrets directory is untouched (nothing added, removed or re-moded)
    assert sorted(p.name for p in secrets.iterdir()) == ["mail-login.enc", "other.txt"]
    assert oct(secrets.stat().st_mode & 0o777) == "0o700"


@needs_bash
def test_backup_with_the_secrets_directory_next_to_the_database_still_excludes_it(tmp_path):
    """Worst case for a non-Docker install: SECRETS_DIR is a sibling inside the database directory."""
    data = tmp_path / "data"
    secrets = data / "secrets"
    secrets.mkdir(parents=True, mode=0o700)
    (secrets / "mail-login.enc").write_bytes(b"gAAAA-sibling-secret-bytes")
    db = data / "coffee.db"
    env = _env(db, secrets)
    assert _run([sys.executable, "-m", "alembic", "upgrade", "head"], env).returncode == 0
    out = data / "backups"
    assert _run(["bash", str(SCRIPTS / "backup.sh"), str(out)], env).returncode == 0
    assert [p.suffix for p in out.rglob("*")] == [".db"]
    (backup,) = out.glob("coffee-*.db")
    assert b"sibling-secret-bytes" not in backup.read_bytes()


def test_backup_and_restore_scripts_state_that_secrets_are_not_included():
    backup, restore = _text("scripts/backup.sh"), _text("scripts/restore.sh")
    assert "ONLY the SQLite database" in backup and "setup-mail" in backup
    assert "setup-mail" in restore and "SECRET_KEY" in restore
    for script in (backup, restore, _text("scripts/_common.sh"), _text("scripts/dbtool.py")):
        assert "SECRETS_DIR" not in re.sub(r"(?m)^\s*#.*$", "", script), "scripts must not touch SECRETS_DIR in code"


# ----- smoke ---------------------------------------------------------------------------------------
@needs_bash
def test_smoke_script_is_valid_bash_and_keeps_health_only():
    assert subprocess.run(["bash", "-n", str(SCRIPTS / "smoke.sh")], capture_output=True).returncode == 0
    smoke = _text("scripts/smoke.sh")
    assert "--health-only" in smoke
    for needle in ("/healthz", "/readyz", "/register", "/login", "/overview", "/coffee/single",
                   "strict-transport-security", "content-security-policy", "no-store"):
        assert needle in smoke, needle
    # the v1 profile flow is gone
    for gone in ("/profiles", "/join", "ACCESS_CODE", "SMOKE_ACCESS_CODE"):
        assert gone not in smoke, gone


@needs_bash
def test_smoke_script_argument_handling():
    # half a credential pair is a usage error, before any request is made
    env = {**os.environ, "SMOKE_USERNAME": "only-user", "SMOKE_PASSWORD": ""}
    done = subprocess.run(["bash", str(SCRIPTS / "smoke.sh"), "http://127.0.0.1:9"], env=env, capture_output=True,
                          text=True, timeout=30)
    assert done.returncode == 2 and "both SMOKE_USERNAME and SMOKE_PASSWORD" in done.stderr
    # an unreachable instance fails cleanly (curl error), also in --health-only mode
    clean = {k: v for k, v in os.environ.items() if not k.startswith("SMOKE_")}
    if shutil.which("curl"):
        done = subprocess.run(["bash", str(SCRIPTS / "smoke.sh"), "--health-only", "http://127.0.0.1:9"], env=clean,
                              capture_output=True, text=True, timeout=60)
        assert done.returncode == 1 and "FAIL" in done.stderr


# ----- docs ----------------------------------------------------------------------------------------
def test_readme_covers_the_v2_operations_topics():
    readme = _text("README.md")
    must = [
        "docker compose run --rm -it app python -m app.cli setup-mail",
        "python -m app.cli setup",
        "postout.lrz.de",
        "What a simulation cannot show",
        "test-mail",
        "mail-status",
        "spam folder",
        "functional mailbox",
        "app password",
        "deploy/README.md",
        "a database created by v1 cannot be upgraded",
        "fresh database",
        "not legal advice",
        "data protection contact",
        "four permanent codes",
        "Step-up",
        "remittances",
        "sponsor",
        "re-run `setup-mail`",
        "single process",
    ]
    lowered = readme.lower()
    for needle in must:
        assert needle.lower() in lowered, needle
    # known limitations and out-of-scope lists exist
    assert "## Known limitations" in readme and "## Out of scope" in readme
    for limitation in ("cookie jar", "No full erasure", "TUM aliases", "mail login is not in backups",
                       "sponsor trust"):
        assert limitation.lower() in lowered, limitation
    # removed v1 concepts are not documented as current
    for gone in ("ACCESS_CODE", "/join", "/profiles", "set-admin-chairs", "ADMIN_TOTP_REQUIRED"):
        assert gone not in readme, gone
    assert "deploy/README.md" in readme and (ROOT / "deploy" / "README.md").exists()


def test_readme_post_deployment_checklist_is_in_order():
    readme = _text("README.md")
    section = readme[readme.index("## Post-deployment mail checklist"):readme.index("## Day-to-day operations")]
    order = ["allowed", "setup-mail", "test-mail", "headers", "guest request", "password reset", "mail-status"]
    pos = [section.lower().index(word.lower()) for word in order]
    assert pos == sorted(pos), pos


def test_readme_never_tells_the_operator_to_put_the_mail_login_into_env():
    readme = _text("README.md")
    assert not LOGIN_NAMES.search(readme)
    assert "There is no setting for the mail login" in readme


def test_architecture_and_progress_describe_v2():
    arch, progress = _text("docs/ARCHITECTURE.md"), _text("docs/PROGRESS.md")
    assert "V2-CONTRACT.md" in arch and "v2" in arch.lower()
    for module in ("registration.py", "mail_credentials.py", "groups.py", "overview.py", "stepup.py", "cli_setup.py"):
        assert module in arch, module
        assert list(ROOT.glob(f"app/**/{module}")), f"{module} does not exist"
    for table in ("group_remittances", "pending_registrations", "password_reset_tokens", "used_nonces"):
        assert table in arch, table
    assert "gate.py" not in re.sub(r"Removed from v1:[^\n]*", "", arch)
    assert "secrets" in arch and "/overview" in arch
    for task in ("1.1", "2.5", "4.5", "5.2", "6.1"):
        assert task in progress, task
    assert "776 tests passing" not in progress.split("## Superseded")[0]
