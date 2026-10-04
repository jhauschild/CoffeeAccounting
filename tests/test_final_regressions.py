"""Regressions from the acceptance run: HEAD on health routes, and no secret echo in config errors."""
import pytest
from pydantic import ValidationError

from app.config import Settings


def test_head_on_health_and_home(client):
    for path in ("/healthz", "/readyz", "/"):
        assert client.head(path, follow_redirects=False).status_code != 405, path


def test_invalid_production_config_does_not_echo_the_secret_key(monkeypatch):
    """A wrong setting (http base URL) must not make pydantic print the valid SECRET_KEY."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://coffee.example.org")
    monkeypatch.setenv("SECRET_KEY", "GoodSecret-9f8e7d6c5b4a39281706f5e4d3c2b1a0")
    with pytest.raises(ValidationError) as exc:
        Settings(_env_file=None)
    assert "GoodSecret-9f8e7d6c5b4a39281706f5e4d3c2b1a0" not in str(exc.value) and "input_value" not in str(exc.value)
