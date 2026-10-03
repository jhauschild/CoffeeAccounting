"""Regressions from the acceptance run: HEAD on health routes, and no secret echo in config errors."""
import pytest
from pydantic import ValidationError

from app.config import Settings


def test_head_on_health_and_home(client):
    for path in ("/healthz", "/readyz", "/"):
        assert client.head(path, follow_redirects=False).status_code != 405, path


def test_invalid_production_config_does_not_echo_access_code(monkeypatch):
    """A wrong setting (http base URL) must not make pydantic print the valid ACCESS_CODE."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://coffee.example.org")
    monkeypatch.setenv("SECRET_KEY", "x" * 40)
    monkeypatch.setenv("ACCESS_CODE", "GoodCode-12345")
    with pytest.raises(ValidationError) as exc:
        Settings(_env_file=None)
    assert "GoodCode-12345" not in str(exc.value) and "input_value" not in str(exc.value)
