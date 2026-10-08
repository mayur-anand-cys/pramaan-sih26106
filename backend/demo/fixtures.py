"""DEMO_MODE fixtures — return pre-computed telemetry instead of calling external APIs.

When PRAMAAN_DEMO_MODE=true, the geolocation functions in app.py and
threat_intel.py call get_demo_geo(ip) instead of hitting ip-api.com.
This keeps demos deterministic, offline-friendly, and free of rate limits.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

_FIXTURE_PATH = Path(__file__).parent / "fixtures_geo.json"
_CACHE: Optional[Dict[str, Any]] = None


def _load_fixtures() -> Dict[str, Any]:
    """Lazy-load the fixtures file once per process."""
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    try:
        with open(_FIXTURE_PATH, "r", encoding="utf-8") as f:
            _CACHE = json.load(f)
    except Exception:
        _CACHE = {}
    return _CACHE


def demo_mode_enabled() -> bool:
    """True when PRAMAAN_DEMO_MODE env var is set to 'true' (case-insensitive)."""
    return os.getenv("PRAMAAN_DEMO_MODE", "false").lower() == "true"


def get_demo_geo(ip: str) -> Dict[str, Any]:
    """Return a fixture geolocation for the given IP, or a safe default."""
    fixtures = _load_fixtures()
    if ip in fixtures and isinstance(fixtures[ip], dict):
        return dict(fixtures[ip])

    # Unknown IP — return a neutral placeholder so nothing crashes in demo mode
    return {
        "ip": ip,
        "status": "success",
        "country": "Unknown",
        "city": "Unknown",
        "isp": "Unknown",
        "asn": "AS0",
        "lat": 37.7749,
        "lon": -122.4194,
    }