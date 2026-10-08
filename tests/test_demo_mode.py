"""Tests for DEMO_MODE fixtures."""
import importlib
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Ensure tests start with demo mode off unless they set it."""
    monkeypatch.delenv("PRAMAAN_DEMO_MODE", raising=False)
    yield


def test_demo_mode_disabled_by_default(monkeypatch):
    monkeypatch.setenv("PRAMAAN_DEMO_MODE", "false")
    import backend.demo.fixtures as fx
    importlib.reload(fx)
    assert fx.demo_mode_enabled() is False


def test_demo_mode_enabled_case_insensitive(monkeypatch):
    monkeypatch.setenv("PRAMAAN_DEMO_MODE", "TRUE")
    import backend.demo.fixtures as fx
    importlib.reload(fx)
    assert fx.demo_mode_enabled() is True


def test_get_demo_geo_known_ip():
    from backend.demo.fixtures import get_demo_geo
    result = get_demo_geo("8.8.8.8")
    assert result["ip"] == "8.8.8.8"
    assert result["status"] == "success"
    assert result["asn"] == "AS15169"
    assert "Google" in result["isp"]


def test_get_demo_geo_unknown_ip_returns_default():
    from backend.demo.fixtures import get_demo_geo
    result = get_demo_geo("99.99.99.99")
    assert result["ip"] == "99.99.99.99"
    assert result["status"] == "success"
    assert result["country"] == "Unknown"


def test_geolocate_uses_fixture_when_demo(monkeypatch):
    monkeypatch.setenv("PRAMAAN_DEMO_MODE", "true")
    # Reload fixtures to pick up new env value
    import backend.demo.fixtures as fx
    importlib.reload(fx)
    import threat_intel
    importlib.reload(threat_intel)

    result = threat_intel.geolocate_ip_cached("8.8.8.8")
    # Fixture value — this is a static value from fixtures_geo.json
    assert result["city"] == "Mountain View"
    assert result["isp"] == "Google"  # not "Google LLC" (real API response)


def test_geolocate_hits_api_when_not_demo(monkeypatch):
    """With demo mode off, the code path bypasses fixtures.

    We can't assert on the real API result (network is flaky), but we can
    assert that the function returns a dict with the expected keys.
    """
    monkeypatch.setenv("PRAMAAN_DEMO_MODE", "false")
    import backend.demo.fixtures as fx
    importlib.reload(fx)
    import threat_intel
    importlib.reload(threat_intel)

    # Just confirm it returns without raising — don't assert on network content
    result = threat_intel.geolocate_ip_cached("127.0.0.1")
    assert "ip" in result
    assert "status" in result