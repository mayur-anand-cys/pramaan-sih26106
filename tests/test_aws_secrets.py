"""Tests for backend.secrets.aws â€” AWS Secrets Manager wrapper."""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import backend.secrets.aws as secrets_module
from backend.secrets.aws import aws_secrets_enabled, get_secret_value


@pytest.fixture(autouse=True)
def _reset_env_and_cache(monkeypatch):
    """Clear env vars and the lru_cache before each test."""
    monkeypatch.delenv("PRAMAAN_USE_AWS_SECRETS", raising=False)
    monkeypatch.delenv("AWS_REGION", raising=False)
    _clear_secret_cache()
    yield
    _clear_secret_cache()


def _clear_secret_cache():
    """Safely clear get_secret's lru_cache if it still has one."""
    fn = secrets_module.get_secret
    if hasattr(fn, "cache_clear"):
        fn.cache_clear()


def test_aws_disabled_by_default(monkeypatch):
    monkeypatch.delenv("PRAMAAN_USE_AWS_SECRETS", raising=False)
    assert aws_secrets_enabled() is False


def test_aws_enabled_case_insensitive(monkeypatch):
    monkeypatch.setenv("PRAMAAN_USE_AWS_SECRETS", "TRUE")
    assert aws_secrets_enabled() is True


def test_get_secret_value_falls_back_to_env_when_aws_disabled(monkeypatch):
    """When AWS is off, get_secret_value returns the env var."""
    monkeypatch.setenv("PRAMAAN_USE_AWS_SECRETS", "false")
    monkeypatch.setenv("MY_TEST_VAR", "from-env")
    val = get_secret_value("pramaan/test", "key", "MY_TEST_VAR", "default")
    assert val == "from-env"


def test_get_secret_value_uses_default_when_no_env(monkeypatch):
    monkeypatch.setenv("PRAMAAN_USE_AWS_SECRETS", "false")
    monkeypatch.delenv("NONEXISTENT_VAR", raising=False)
    val = get_secret_value("pramaan/test", "key", "NONEXISTENT_VAR", "fallback")
    assert val == "fallback"


def test_get_secret_value_uses_aws_when_enabled(monkeypatch):
    """When AWS is on and returns a value, that value wins over env."""
    monkeypatch.setenv("PRAMAAN_USE_AWS_SECRETS", "true")
    monkeypatch.setenv("MY_TEST_VAR", "from-env")

    # Simulate boto3 returning a secret
    def fake_get_secret(name):
        return {"key": "from-aws"}

    monkeypatch.setattr(secrets_module, "get_secret", fake_get_secret)

    val = get_secret_value("pramaan/test", "key", "MY_TEST_VAR", "default")
    assert val == "from-aws"


def test_get_secret_value_falls_back_when_aws_returns_none(monkeypatch):
    """If AWS lookup fails silently, env var is used."""
    monkeypatch.setenv("PRAMAAN_USE_AWS_SECRETS", "true")
    monkeypatch.setenv("MY_TEST_VAR", "from-env")

    monkeypatch.setattr(secrets_module, "get_secret", lambda name: None)

    val = get_secret_value("pramaan/test", "key", "MY_TEST_VAR", "default")
    assert val == "from-env"


def test_get_secret_value_falls_back_when_key_missing(monkeypatch):
    """If AWS returns a dict without the requested key, env var is used."""
    monkeypatch.setenv("PRAMAAN_USE_AWS_SECRETS", "true")
    monkeypatch.setenv("MY_TEST_VAR", "from-env")

    monkeypatch.setattr(secrets_module, "get_secret", lambda name: {"other_key": "x"})

    val = get_secret_value("pramaan/test", "key", "MY_TEST_VAR", "default")
    assert val == "from-env"


def test_anchor_rpc_url_uses_new_default(monkeypatch):
    """The default fallback should now point at Alchemy, not publicnode."""
    monkeypatch.delenv("PRAMAAN_USE_AWS_SECRETS", raising=False)
    monkeypatch.delenv("BLOCKCHAIN_RPC_URL", raising=False)
    _clear_secret_cache()

    # Reload anchor to pick up new default
    import importlib
    import blockchain.anchor as anchor
    importlib.reload(anchor)

    assert "alchemy" in anchor.BLOCKCHAIN_RPC_URL.lower() or "alchemy" in anchor.BLOCKCHAIN_RPC_URL

