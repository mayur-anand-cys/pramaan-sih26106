"""Tests for backend.reporting.soar_export."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


def _find_bash():
    """Locate a bash interpreter, preferring PATH."""
    b = shutil.which("bash")
    if b:
        return b
    # Windows fallbacks (Git for Windows)
    for candidate in (
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files (x86)\Git\bin\bash.exe",
    ):
        if os.path.isfile(candidate):
            return candidate
    return None
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.reporting.soar_export import (
    generate_firewall_rules,
    generate_pfsense_rules,
    generate_csv,
)


def test_firewall_rules_valid_bash_syntax(tmp_path):
    """Generated bash script parses without error (skipped if bash unavailable)."""
    bash = _find_bash()
    if bash is None:
        pytest.skip("bash not installed on this system")

    script = generate_firewall_rules(["203.0.113.5", "198.51.100.7"])
    path = tmp_path / "block.sh"
    path.write_text(script, newline="\n")
    result = subprocess.run([bash, "-n", str(path)], capture_output=True, text=True)
    assert result.returncode == 0, f"bash -n failed: {result.stderr}"
    assert "203.0.113.5" in script
    assert "198.51.100.7" in script

def test_firewall_rules_dedupe():
    script = generate_firewall_rules(["1.1.1.1", "1.1.1.1", "", "  ", "2.2.2.2"])
    assert script.count("ipset add") == 2


def test_pfsense_rules_format():
    out = generate_pfsense_rules(["203.0.113.5", "198.51.100.7"])
    assert "pfctl -t PRAMAAN_BLOCK -T add 203.0.113.5" in out
    assert "pfctl -t PRAMAAN_BLOCK -T add 198.51.100.7" in out


def test_pfsense_custom_alias():
    out = generate_pfsense_rules(["1.2.3.4"], alias_name="CUSTOM")
    assert "pfctl -t CUSTOM -T add 1.2.3.4" in out


def test_csv_header_and_rows():
    records = [
        {"source_ip": "203.0.113.5", "asn": "AS12345", "country": "RU", "risk_score": 85},
        {"source_ip": "198.51.100.7", "asn": "AS67890", "country": "US", "risk_score": 42},
    ]
    out = generate_csv(records)
    assert out.splitlines()[0] == "IP,ASN,Country,Risk Score"
    assert "203.0.113.5,AS12345,RU,85" in out
    assert "198.51.100.7,AS67890,US,42" in out


def test_csv_empty():
    out = generate_csv([])
    assert out.splitlines() == ["IP,ASN,Country,Risk Score"]