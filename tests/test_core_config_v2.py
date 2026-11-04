"""v2 settings: defaults, parsing and production validation."""
import pytest
from pydantic import ValidationError

from app.config import DEV_SECRET_KEY, Settings, public_config_rows

PROD = dict(
    _env_file=None,
    environment="production",
    public_base_url="https://coffee.example.org",
    secret_key="Zq3v8K1mR7tXw2pL9sD4fG6hJ0kN5bVc",
    mail_from="Coffee Ledger <coffee@example.org>",
)


def dev(**kw) -> Settings:
    return Settings(_env_file=None, **kw)


def test_development_defaults():
    s = dev()
    assert s.mail_backend == "console" and s.smtp_host == "postout.lrz.de" and s.smtp_port == 587
    assert s.smtp_security == "starttls" and s.secrets_dir == "/secrets" and s.mail_max_per_hour == 30
    assert s.verification_ttl_hours == 24 and s.guest_approval_ttl_days == 7 and s.reset_ttl_minutes == 60
    assert s.password_min_length == 10 and s.stepup_window_seconds == 300
    assert s.balance_totp_required is False and not hasattr(s, "admin_totp_required")
    assert s.allowed_email_domain_list == ["tum.de", "mytum.de", "*.tum.de"]


def test_production_defaults_to_smtp_and_totp_balance():
    s = Settings(**PROD)
    assert s.mail_backend == "smtp" and s.balance_totp_required is True


def test_the_v1_access_code_setting_is_gone(monkeypatch):
    monkeypatch.setenv("ACCESS_CODE", "left-over-from-v1")  # an old .env line is ignored, not an error
    s = Settings(**PROD)
    assert not hasattr(s, "access_code")


def test_allowed_domains_parsing():
    s = dev(allowed_email_domains=" TUM.de , *.Tum.de ,,")
    assert s.allowed_email_domain_list == ["tum.de", "*.tum.de"]


def test_head_admin_notify_emails_parsing():
    assert dev().head_admin_notify_emails == []
    s = dev(head_admin_notify_email=" Alice@Example.org , bob@example.org ,,")
    assert s.head_admin_notify_emails == ["alice@example.org", "bob@example.org"]
    assert s.head_admin_notify_email == "alice@example.org,bob@example.org"


def test_head_admin_notify_email_invalid_refused():
    with pytest.raises(ValidationError):
        dev(head_admin_notify_email="alice@example.org,not-an-email")


@pytest.mark.parametrize("override", [
    dict(mail_backend="console"), dict(mail_backend="memory"), dict(mail_backend="file", mail_file_dir="/tmp/x"),
    dict(mail_from=""), dict(mail_from="no-at-sign"), dict(smtp_host=" "),
    dict(smtp_port=0), dict(smtp_port=70000), dict(smtp_security="ssl"),
    dict(smtp_security="ssl", smtp_port=587), dict(smtp_security="starttls", smtp_port=465),
    dict(password_min_length=4),
])
def test_production_refuses(override):
    with pytest.raises(ValidationError):
        Settings(**{**PROD, **override})


def test_production_ssl_465_ok():
    assert Settings(**{**PROD, "smtp_security": "ssl", "smtp_port": 465}).smtp_security == "ssl"


@pytest.mark.parametrize("override", [
    dict(mail_backend="smtp2"), dict(smtp_security="tls"), dict(smtp_port=0), dict(mail_backend="file"),
    dict(allowed_email_domains=""), dict(allowed_email_domains="tum"), dict(allowed_email_domains="a@tum.de"),
    dict(verification_ttl_hours=0), dict(reset_ttl_minutes=0), dict(password_min_length=129),
    dict(argon2_memory_cost_kib=4),
])
def test_invalid_values_refused_everywhere(override):
    with pytest.raises(ValidationError):
        dev(**override)


def test_errors_never_echo_input():
    secret = "Sup3r-Secret-Key-Value-0123456789abcdef"
    with pytest.raises(ValidationError) as exc:
        Settings(**{**PROD, "secret_key": secret, "mail_backend": "console", "smtp_port": 70000,
                    "mail_from": "leak-me@example.org", "smtp_host": "leak.example.org", "smtp_security": "ssl"})
    text = str(exc.value)
    assert secret not in text and "leak-me" not in text and "input_value" not in text
    assert "MAIL_BACKEND" in text and "SMTP_PORT" in text


def test_public_config_rows_redacts_secrets():
    secret = "Sup3r-Secret-Key-Value-0123456789abcdef"
    s = Settings(**{**PROD, "secret_key": secret, "admin_bootstrap_username": "boot",
                    "admin_bootstrap_password": "boot-pass-word"})
    by_name = {row["name"]: row["value"] for row in public_config_rows(s)}
    assert by_name["SECRET_KEY"] == f"set ({len(secret)} characters)"
    assert by_name["ADMIN_BOOTSTRAP_USERNAME"] == "set"
    assert by_name["ADMIN_BOOTSTRAP_PASSWORD"] == "set"
    assert by_name["ENVIRONMENT"] == "production"
    assert by_name["IS_PRODUCTION"] == "true"
    assert by_name["BALANCE_TOTP_REQUIRED"] == "true"
    joined = " ".join(by_name.values())
    assert secret not in joined and "boot" not in joined and "boot-pass-word" not in joined
    dev_rows = public_config_rows(dev(secret_key=DEV_SECRET_KEY, public_base_url="http://localhost:8000"))
    assert dev_rows[0] == {"name": "SECRET_KEY", "value": "using published DEV key"}
    assert DEV_SECRET_KEY not in " ".join(r["value"] for r in dev_rows)
