# tests/test_xai.py
"""
Test suite for Explainable AI (XAI) Contradiction Detection Engine.
Validates contradiction detection rules, SHAP explanations, analyst flagging,
audit logging, and defensive handling of malformed inputs.
"""

import sqlite3
import pytest
from unittest.mock import patch, MagicMock

from backend.detection import xai


# ---------------------------------------------------------------------------
# Test Rule 1: legit ML + all auth fail -> CRITICAL
# ---------------------------------------------------------------------------

def test_rule_1_legit_ml_all_auth_fail_critical_dict():
    """Rule 1 fires when AI says legitimate but SPF, DKIM, and DMARC all fail."""
    ml_result = {
        "prediction": "legitimate",
        "probability": 0.08,
        "confidence": 92.0,
        "threat_score": 15.0
    }
    auth_result = {
        "spf": {"dns_result": "fail", "header_result": "fail"},
        "dkim": {"dns_result": "fail", "header_result": "fail"},
        "dmarc": {"dns_result": "fail", "spf_alignment": False, "dkim_alignment": False},
        "header_trust_score": 0
    }

    result = xai.detect_contradictions(ml_result, auth_result)

    assert result["has_contradiction"] is True
    assert result["severity"] == "CRITICAL"
    assert result["requires_analyst_review"] is True
    assert any(a["rule_id"] == "RULE_1_LEGIT_AUTH_FAIL" for a in result["alerts"])


def test_rule_1_legit_ml_all_auth_fail_critical_str():
    """Rule 1 fires when auth results are passed as simple strings."""
    ml_result = {
        "prediction": "legitimate",
        "probability": 0.12,
        "confidence": 88.0,
        "threat_score": 20.0
    }
    auth_result = {
        "spf": "fail",
        "dkim": "fail",
        "dmarc": "fail"
    }

    result = xai.detect_contradictions(ml_result, auth_result)

    assert result["has_contradiction"] is True
    assert result["severity"] == "CRITICAL"
    assert result["requires_analyst_review"] is True


# ---------------------------------------------------------------------------
# Test Rule 2: phishing ML + all auth pass -> HIGH
# ---------------------------------------------------------------------------

def test_rule_2_phishing_ml_all_auth_pass_high_dict():
    """Rule 2 fires when AI says phishing but SPF, DKIM, and DMARC all pass."""
    ml_result = {
        "prediction": "phishing",
        "probability": 0.94,
        "confidence": 94.0,
        "threat_score": 60.0
    }
    auth_result = {
        "spf": {"dns_result": "pass", "header_result": "pass"},
        "dkim": {"dns_result": "pass", "header_result": "pass"},
        "dmarc": {"dns_result": "pass", "spf_alignment": True, "dkim_alignment": True},
        "header_trust_score": 100
    }

    result = xai.detect_contradictions(ml_result, auth_result)

    assert result["has_contradiction"] is True
    assert result["severity"] == "HIGH"
    assert result["requires_analyst_review"] is True
    assert any(a["rule_id"] == "RULE_2_PHISHING_AUTH_PASS" for a in result["alerts"])


def test_rule_2_phishing_ml_all_auth_pass_high_str():
    """Rule 2 fires when auth results are simple string passes."""
    ml_result = {
        "prediction": "phishing",
        "probability": 0.85,
        "confidence": 85.0,
        "threat_score": 50.0
    }
    auth_result = {
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass"
    }

    result = xai.detect_contradictions(ml_result, auth_result)

    assert result["has_contradiction"] is True
    assert result["severity"] == "HIGH"
    assert result["requires_analyst_review"] is True


# ---------------------------------------------------------------------------
# Test Rule 3: conf < 60 and score > 80 -> AMBER
# ---------------------------------------------------------------------------

def test_rule_3_low_conf_high_threat_amber():
    """Rule 3 fires when AI confidence is low (<60%) and threat score is high (>80)."""
    ml_result = {
        "confidence": 55.0,
        "threat_score": 85.0,
        "probability": 0.52
    }
    # Mixed auth so Rules 1 and 2 do not trigger
    auth_result = {
        "spf": {"dns_result": "pass"},
        "dkim": {"dns_result": "fail"},
        "dmarc": {"dns_result": "none"}
    }

    result = xai.detect_contradictions(ml_result, auth_result)

    assert result["has_contradiction"] is True
    assert result["severity"] == "AMBER"
    assert result["requires_analyst_review"] is False
    assert any(a["rule_id"] == "RULE_3_LOW_CONF_HIGH_THREAT" for a in result["alerts"])


def test_rule_3_low_conf_alias_keys():
    """Rule 3 handles alias keys 'conf' and 'score' properly."""
    ml_result = {
        "conf": 58.0,
        "score": 88.0,
        "prob": 0.54
    }
    auth_result = {
        "spf": "pass",
        "dkim": "fail",
        "dmarc": "none"
    }

    result = xai.detect_contradictions(ml_result, auth_result)

    assert result["has_contradiction"] is True
    assert result["severity"] == "AMBER"
    assert result["requires_analyst_review"] is False


# ---------------------------------------------------------------------------
# Test: No rule fires when signals agree
# ---------------------------------------------------------------------------

def test_no_rule_fires_when_signals_agree_phishing():
    """When ML indicates phishing and auth fails, signals agree and no contradiction fires."""
    ml_result = {
        "prediction": "phishing",
        "probability": 0.95,
        "confidence": 95.0,
        "threat_score": 75.0
    }
    auth_result = {
        "spf": {"dns_result": "fail"},
        "dkim": {"dns_result": "fail"},
        "dmarc": {"dns_result": "fail"}
    }

    result = xai.detect_contradictions(ml_result, auth_result)

    assert result["has_contradiction"] is False
    assert result["severity"] == "NONE"
    assert result["requires_analyst_review"] is False
    assert len(result["alerts"]) == 0


def test_no_rule_fires_when_signals_agree_legitimate():
    """When ML indicates legitimate and auth passes, signals agree and no contradiction fires."""
    ml_result = {
        "prediction": "legitimate",
        "probability": 0.05,
        "confidence": 95.0,
        "threat_score": 10.0
    }
    auth_result = {
        "spf": {"dns_result": "pass"},
        "dkim": {"dns_result": "pass"},
        "dmarc": {"dns_result": "pass"}
    }

    result = xai.detect_contradictions(ml_result, auth_result)

    assert result["has_contradiction"] is False
    assert result["severity"] == "NONE"
    assert result["requires_analyst_review"] is False
    assert len(result["alerts"]) == 0


# ---------------------------------------------------------------------------
# Test: detect_contradictions returns the full dict shape
# ---------------------------------------------------------------------------

def test_detect_contradictions_full_dict_shape():
    """Verify that detect_contradictions returns the complete expected schema."""
    ml_result = {"probability": 0.2, "threat_score": 30.0}
    auth_result = {"header_trust_score": 80}

    result = xai.detect_contradictions(ml_result, auth_result)

    assert "has_contradiction" in result
    assert "severity" in result
    assert "requires_analyst_review" in result
    assert "alerts" in result
    assert "summary" in result
    assert "signals" in result

    signals = result["signals"]
    assert "ml_label" in signals
    assert "ml_probability" in signals
    assert "ml_confidence" in signals
    assert "threat_score" in signals
    assert "auth_status" in signals


# ---------------------------------------------------------------------------
# Test: flag_for_analyst_review True for CRITICAL/HIGH, False for AMBER
# ---------------------------------------------------------------------------

def test_flag_for_analyst_review():
    """Verify analyst review requirement for CRITICAL, HIGH, AMBER, and NONE."""
    assert xai.flag_for_analyst_review({"severity": "CRITICAL"}) is True
    assert xai.flag_for_analyst_review({"severity": "HIGH"}) is True
    assert xai.flag_for_analyst_review({"severity": "AMBER"}) is False
    assert xai.flag_for_analyst_review({"severity": "NONE"}) is False
    assert xai.flag_for_analyst_review({}) is False
    assert xai.flag_for_analyst_review(None) is False


# ---------------------------------------------------------------------------
# Test: log_contradiction_to_audit writes to ledger (mock the ledger)
# ---------------------------------------------------------------------------

@patch("backend.detection.xai.sqlite3.connect")
def test_log_contradiction_to_audit_mock(mock_connect):
    """Test that log_contradiction_to_audit executes SQLite insertions with mock."""
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_connect.return_value = mock_conn
    mock_conn.cursor.return_value = mock_cursor

    contradiction_result = {
        "severity": "CRITICAL",
        "requires_analyst_review": True,
        "alerts": [{"rule_id": "RULE_1"}],
        "summary": "Critical contradiction detected."
    }

    xai.log_contradiction_to_audit(contradiction_result, email_id="test_hash_12345")

    mock_connect.assert_called_once()
    assert mock_cursor.execute.call_count >= 2
    mock_conn.commit.assert_called_once()
    mock_conn.close.assert_called_once()


def test_log_contradiction_to_audit_in_memory_db(monkeypatch, tmp_path):
    """Verify real database execution against a temp SQLite file."""
    import sqlite3

    db_file = str(tmp_path / "ledger.db")
    monkeypatch.setattr(xai, "LEDGER_DB_FILE", db_file)

    contradiction_result = {
        "severity": "HIGH",
        "requires_analyst_review": True,
        "alerts": [{"rule_id": "RULE_2"}],
        "summary": "High contradiction detected.",
    }

    xai.log_contradiction_to_audit(contradiction_result, email_id="sha256_abcdef")

    conn = sqlite3.connect(db_file)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT email_id, severity, requires_analyst_review "
            "FROM contradiction_audit_ledger"
        )
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == "sha256_abcdef"
        assert row[1] == "HIGH"
        assert row[2] == 1
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Test: Malformed input does not raise
# ---------------------------------------------------------------------------

def test_malformed_input_does_not_raise():
    """Ensure all public functions handle malformed, missing, and invalid types gracefully."""
    # detect_contradictions
    res1 = xai.detect_contradictions(None, None)
    assert isinstance(res1, dict)
    assert res1["has_contradiction"] is False

    res2 = xai.detect_contradictions({}, {})
    assert isinstance(res2, dict)

    res3 = xai.detect_contradictions("invalid_type", 12345)
    assert isinstance(res3, dict)

    res4 = xai.detect_contradictions({"probability": "not_a_float", "threat_score": [1, 2]}, {"spf": 999})
    assert isinstance(res4, dict)

    # explain_prediction
    exp1 = xai.explain_prediction(None, None)
    assert isinstance(exp1, dict)
    assert "base_value" in exp1

    exp2 = xai.explain_prediction("", {})
    assert isinstance(exp2, dict)

    exp3 = xai.explain_prediction(12345, "invalid")
    assert isinstance(exp3, dict)

    # flag_for_analyst_review
    assert xai.flag_for_analyst_review(None) is False
    assert xai.flag_for_analyst_review([]) is False
    assert xai.flag_for_analyst_review("string") is False

    # log_contradiction_to_audit
    xai.log_contradiction_to_audit(None, "hash")
    xai.log_contradiction_to_audit({}, None)
    xai.log_contradiction_to_audit("not_a_dict", 123)
