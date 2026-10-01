from backend.detection.font_forensics import analyze_font_obfuscation
# backend/detection/xai.py
"""
Explainable AI (XAI) Contradiction Detection & Model Explanation Engine.
Implements rule-based contradiction detection between machine learning predictions
and cryptographic email authentication protocols, alongside SHAP feature attributions.

Part of PRAMAAN SOC Threat Intelligence Platform (Issue #4).
"""

import os
import sys
import json
import logging
import sqlite3
import datetime
import email
from email import policy
from typing import Dict, List, Any, Optional

import numpy as np

# Ensure project root is available for imports
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import model

logger = logging.getLogger(__name__)

LEDGER_DB_FILE = os.path.join(REPO_ROOT, "zkfv_ledger.db")

_SHAP_EXPLAINER_CACHE = None


def _get_shap_explainer(pipeline):
    """Lazily initialize and cache SHAP LinearExplainer on model pipeline."""
    global _SHAP_EXPLAINER_CACHE
    if _SHAP_EXPLAINER_CACHE is not None:
        return _SHAP_EXPLAINER_CACHE

    try:
        import shap
        tfidf = pipeline.named_steps["tfidf"]
        clf = pipeline.named_steps["clf"]
        bg_texts = [item[0] for item in model.DATASET]
        bg_features = tfidf.transform(bg_texts)
        masker = shap.maskers.Independent(bg_features)
        _SHAP_EXPLAINER_CACHE = (shap.LinearExplainer(clf, masker=masker), tfidf)
        return _SHAP_EXPLAINER_CACHE
    except Exception as exc:
        logger.warning("Could not initialize SHAP LinearExplainer: %s", exc)
        return None


def _extract_text_for_xai(raw_email: str) -> str:
    """Extract subject and plaintext body from raw email string."""
    if not raw_email or not isinstance(raw_email, str):
        return ""
    try:
        msg = email.message_from_string(raw_email, policy=policy.default)
        subject = str(msg.get("Subject", ""))
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body += payload.decode("utf-8", errors="replace") + "\n"
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode("utf-8", errors="replace")
            else:
                body = str(msg.get_payload() or "")
        combined = f"{subject}\n{body}".strip()
        return combined if combined else raw_email[:1500]
    except Exception:
        return raw_email[:1500]


def _check_protocol_fail(entry: Any, protocol: str) -> bool:
    """Check if an SPF, DKIM, or DMARC check failed."""
    if entry is None:
        return False
    if isinstance(entry, str):
        val = entry.strip().lower()
        return val in {"fail", "softfail", "permerror", "temperror", "reject"}
    if isinstance(entry, dict):
        dns_res = str(entry.get("dns_result", "")).strip().lower()
        hdr_res = str(entry.get("header_result", "")).strip().lower()
        if dns_res in {"fail", "softfail", "permerror", "temperror"}:
            return True
        if hdr_res in {"fail", "softfail", "permerror", "temperror"}:
            return True
        if protocol == "dmarc":
            if dns_res in {"fail", "none"} or hdr_res in {"fail"}:
                return True
            if entry.get("spf_alignment") is False and entry.get("dkim_alignment") is False:
                return True
        if dns_res == "fail" or hdr_res == "fail":
            return True
    return False


def _check_protocol_pass(entry: Any, protocol: str) -> bool:
    """Check if an SPF, DKIM, or DMARC check passed."""
    if entry is None:
        return False
    if isinstance(entry, str):
        return entry.strip().lower() == "pass"
    if isinstance(entry, dict):
        dns_res = str(entry.get("dns_result", "")).strip().lower()
        hdr_res = str(entry.get("header_result", "")).strip().lower()
        is_pass = dns_res == "pass" or (dns_res in {"", "none"} and hdr_res == "pass")
        if protocol == "dmarc":
            # If alignments are explicitly provided as False, it's not a full pass
            if entry.get("spf_alignment") is False and entry.get("dkim_alignment") is False:
                return False
        return is_pass
    return False


def detect_contradictions(ml_result: dict, auth_result: dict) -> dict:
    """
    Detect logical contradictions between ML predictions and authentication results.

    Rules implemented:
    - Rule 1 (CRITICAL): AI says 'legitimate' BUT SPF/DKIM/DMARC all FAIL
    - Rule 2 (HIGH): AI says 'phishing' BUT all auth PASS (AI may be overzealous)
    - Rule 3 (AMBER): AI confidence < 60% AND threat score > 80
    - Rule 4 (the Font Obfuscation alert)
    """
    if not isinstance(ml_result, dict):
        ml_result = {}
    if not isinstance(auth_result, dict):
        auth_result = {}

    # Extract ML metrics
    raw_prob = ml_result.get("probability", ml_result.get("ml_phishing_probability", ml_result.get("prob", 0.0)))
    try:
        ml_prob = float(raw_prob)
    except (TypeError, ValueError):
        ml_prob = 0.0

    raw_pred = ml_result.get("prediction", ml_result.get("label", ""))
    if raw_pred:
        prediction = str(raw_pred).strip().lower()
    else:
        prediction = "phishing" if ml_prob >= 0.5 else "legitimate"

    raw_conf = ml_result.get("confidence", ml_result.get("conf"))
    if raw_conf is not None:
        try:
            confidence = float(raw_conf)
            if 0.0 < confidence <= 1.0:
                confidence = confidence * 100.0
        except (TypeError, ValueError):
            confidence = round(max(ml_prob, 1.0 - ml_prob) * 100.0, 2)
    else:
        confidence = round(max(ml_prob, 1.0 - ml_prob) * 100.0, 2)

    raw_threat = ml_result.get("threat_score", ml_result.get("score", ml_result.get("risk_score", 0.0)))
    try:
        threat_score = float(raw_threat)
    except (TypeError, ValueError):
        threat_score = 0.0

    # Extract Auth metrics
    spf_entry = auth_result.get("spf")
    dkim_entry = auth_result.get("dkim")
    dmarc_entry = auth_result.get("dmarc")
    trust_score = auth_result.get("header_trust_score", 0)

    spf_fail = _check_protocol_fail(spf_entry, "spf")
    dkim_fail = _check_protocol_fail(dkim_entry, "dkim")
    dmarc_fail = _check_protocol_fail(dmarc_entry, "dmarc")

    spf_pass = _check_protocol_pass(spf_entry, "spf")
    dkim_pass = _check_protocol_pass(dkim_entry, "dkim")
    dmarc_pass = _check_protocol_pass(dmarc_entry, "dmarc")

    alerts = []

    # Rule 1: AI says "legitimate" BUT SPF/DKIM/DMARC all FAIL -> CRITICAL alert
    is_legitimate = (prediction in {"legitimate", "clean", "ham", "benign"}) or (ml_prob < 0.5)
    if is_legitimate and (spf_fail and dkim_fail and dmarc_fail):
        alerts.append({
            "rule_id": "RULE_1_LEGIT_AUTH_FAIL",
            "severity": "CRITICAL",
            "title": "CRITICAL: Legitimate AI Verdict with Complete Authentication Failure",
            "description": "AI classified email as legitimate, but SPF, DKIM, and DMARC cryptographic validations all failed.",
            "evidence": {
                "ai_prediction": prediction,
                "ml_probability": ml_prob,
                "spf": spf_entry,
                "dkim": dkim_entry,
                "dmarc": dmarc_entry
            }
        })

    # Rule 2: AI says "phishing" BUT all auth PASS -> HIGH alert (AI may be overzealous)
    is_phishing = (prediction in {"phishing", "spam", "malicious"}) or (ml_prob >= 0.5)
    if is_phishing and (spf_pass and dkim_pass and dmarc_pass):
        alerts.append({
            "rule_id": "RULE_2_PHISHING_AUTH_PASS",
            "severity": "HIGH",
            "title": "HIGH: Phishing AI Verdict with Complete Cryptographic Pass",
            "description": "AI flagged email as phishing, but all email authentication protocols (SPF, DKIM, DMARC) passed cryptographically. AI may be overzealous.",
            "evidence": {
                "ai_prediction": prediction,
                "ml_probability": ml_prob,
                "spf": spf_entry,
                "dkim": dkim_entry,
                "dmarc": dmarc_entry
            }
        })

    # Rule 3: AI confidence < 60% AND threat score > 80 -> AMBER alert
    if confidence < 60.0 and threat_score > 80.0:
        alerts.append({
            "rule_id": "RULE_3_LOW_CONF_HIGH_THREAT",
            "severity": "AMBER",
            "title": "AMBER: Low AI Confidence with High Threat Score Divergence",
            "description": f"AI model certainty is low ({confidence:.1f}%), yet the overall threat intelligence score is high ({threat_score:.1f}/100).",
            "evidence": {
                "confidence": confidence,
                "threat_score": threat_score,
                "ml_probability": ml_prob
            }
        })
    # Rule 4: Embedded font obfuscation (glyph substitution attack)
    raw_email_text = ml_result.get("raw_email", ml_result.get("raw_text", ""))
    if raw_email_text:
        try:
            font_info = analyze_font_obfuscation(raw_email_text, raw_email_text)
        except Exception:
            font_info = {"has_obfuscation": False}

        if font_info.get("has_obfuscation"):
            alerts.append({
                "rule_id": "RULE_4_FONT_OBFUSCATION",
                "severity": "HIGH",
                "title": "HIGH: Font Obfuscation - Glyph Substitution Detected",
                "description": (
                    "Embedded web font contains "
                    + str(font_info["mismatch_count"])
                    + " glyph mismatch(es). Raw HTML text does not match "
                    + "rendered text. Visually intended: '"
                    + str(font_info["visually_intended_text"][:80]) + "'"
                ),
                "evidence": {
                    "fonts_analyzed": font_info["fonts_found"],
                    "mismatches": font_info["mismatches"],
                    "visually_intended_text": font_info["visually_intended_text"],
                    "risk_modifier": font_info["risk_modifier"],
                }
            })


    # Determine highest severity
    has_critical = any(a["severity"] == "CRITICAL" for a in alerts)
    has_high = any(a["severity"] == "HIGH" for a in alerts)
    has_amber = any(a["severity"] == "AMBER" for a in alerts)

    if has_critical:
        severity = "CRITICAL"
    elif has_high:
        severity = "HIGH"
    elif has_amber:
        severity = "AMBER"
    else:
        severity = "NONE"

    result = {
        "has_contradiction": len(alerts) > 0,
        "severity": severity,
        "requires_analyst_review": False,
        "alerts": alerts,
        "summary": "",
        "signals": {
            "ml_label": prediction,
            "ml_probability": ml_prob,
            "ml_confidence": confidence,
            "threat_score": threat_score,
            "auth_status": {
                "spf_fail": spf_fail,
                "spf_pass": spf_pass,
                "dkim_fail": dkim_fail,
                "dkim_pass": dkim_pass,
                "dmarc_fail": dmarc_fail,
                "dmarc_pass": dmarc_pass,
                "header_trust_score": trust_score
            }
        }
    }

    result["requires_analyst_review"] = flag_for_analyst_review(result)

    if alerts:
        result["summary"] = f"Contradiction detected: {severity} ({len(alerts)} rule alert(s) triggered)."
    else:
        result["summary"] = "No contradictions detected between AI predictions and security signals."

    return result


def flag_for_analyst_review(contradiction_result: dict) -> bool:
    """
    Return True if contradiction requires human analyst review (CRITICAL or HIGH).
    Returns False for AMBER or when no contradictions exist.
    """
    if not isinstance(contradiction_result, dict):
        return False
    severity = str(contradiction_result.get("severity", "")).upper()
    if severity in {"CRITICAL", "HIGH"}:
        return True
    alerts = contradiction_result.get("alerts", [])
    if isinstance(alerts, list):
        for alert in alerts:
            if isinstance(alert, dict) and str(alert.get("severity", "")).upper() in {"CRITICAL", "HIGH"}:
                return True
    return False


def log_contradiction_to_audit(contradiction_result: dict, email_id: str) -> None:
    """
    Log contradiction event to the SQLite forensic audit ledger.
    """
    if not isinstance(contradiction_result, dict):
        return

    try:
        conn = sqlite3.connect(LEDGER_DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS contradiction_audit_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                email_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                requires_analyst_review INTEGER NOT NULL,
                alerts_count INTEGER NOT NULL,
                summary TEXT NOT NULL,
                contradiction_json TEXT NOT NULL
            )
        """)

        # Also ensure evidence_ledger exists so ZKFV queries display contradiction events
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS evidence_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                eml_sha256 TEXT NOT NULL,
                merkle_root TEXT NOT NULL,
                leaf_count INTEGER NOT NULL,
                status TEXT NOT NULL,
                raw_proof_json TEXT NOT NULL
            )
        """)

        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        severity = str(contradiction_result.get("severity", "NONE"))
        requires_review = 1 if contradiction_result.get("requires_analyst_review") else 0
        alerts = contradiction_result.get("alerts", [])
        alerts_count = len(alerts) if isinstance(alerts, list) else 0
        summary = str(contradiction_result.get("summary", ""))
        payload = json.dumps(contradiction_result)

        cursor.execute(
            """
            INSERT INTO contradiction_audit_ledger
            (timestamp, email_id, severity, requires_analyst_review, alerts_count, summary, contradiction_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (timestamp, str(email_id), severity, requires_review, alerts_count, summary, payload)
        )

        # Mirror entry to evidence_ledger with status CONTRADICTION_FLAGGED
        cursor.execute(
            """
            INSERT INTO evidence_ledger
            (timestamp, eml_sha256, merkle_root, leaf_count, status, raw_proof_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (timestamp, str(email_id), f"XAI_{severity}", alerts_count, f"CONTRADICTION_{severity}", payload)
        )

        conn.commit()
        conn.close()
    except Exception as exc:
        logger.error("Failed to log contradiction to audit ledger: %s", exc)


def explain_prediction(raw_email: str, ml_result: dict) -> dict:
    """
    Explain ML model prediction using SHAP (Shapley Additive exPlanations).
    Returns token attributions and waterfall visualization coordinates.
    """
    if not isinstance(ml_result, dict):
        ml_result = {}

    text = _extract_text_for_xai(raw_email)
    raw_prob = ml_result.get("probability", ml_result.get("ml_phishing_probability", ml_result.get("prob", 0.0)))
    try:
        ml_prob = float(raw_prob)
    except (TypeError, ValueError):
        ml_prob = 0.0

    try:
        pipeline = model.load_or_train_model()
        explainer_bundle = _get_shap_explainer(pipeline)

        if explainer_bundle is not None and text:
            explainer, tfidf = explainer_bundle
            X = tfidf.transform([text])
            feature_names = tfidf.get_feature_names_out()
            shap_values = explainer(X)

            vals = shap_values.values[0]
            if hasattr(vals, "toarray"):
                vals = vals.toarray()[0]
            elif isinstance(vals, np.ndarray) and vals.ndim > 1:
                vals = vals[0]

            expected_val = explainer.expected_value
            if isinstance(expected_val, (list, np.ndarray)):
                expected_val = float(expected_val[0])
            else:
                expected_val = float(expected_val)

            non_zero_idx = np.where(X.toarray()[0] > 0)[0]
            token_scores = []
            for idx in non_zero_idx:
                w = feature_names[idx]
                score = float(vals[idx])
                token_scores.append({"feature": w, "attribution": round(score, 4)})

            token_scores.sort(key=lambda item: abs(item["attribution"]), reverse=True)

            top_positive = [t for t in token_scores if t["attribution"] > 0][:8]
            top_negative = [t for t in token_scores if t["attribution"] < 0][:8]

            # Select top tokens for waterfall chart
            top_tokens = token_scores[:10]
            waterfall_labels = [t["feature"] for t in top_tokens]
            waterfall_values = [t["attribution"] for t in top_tokens]
            sum_attributions = sum(waterfall_values)
            final_pred_score = round(expected_val + sum_attributions, 4)

            return {
                "base_value": round(expected_val, 4),
                "prediction_probability": ml_prob,
                "top_positive_features": top_positive,
                "top_negative_features": top_negative,
                "all_features": token_scores[:20],
                "waterfall_data": {
                    "labels": waterfall_labels,
                    "values": waterfall_values,
                    "base_value": round(expected_val, 4),
                    "final_value": final_pred_score
                },
                "status": "success"
            }
    except Exception as exc:
        logger.warning("SHAP explanation generation encountered error: %s", exc)

    # Graceful fallback explanation if SHAP calculation encounters any issue
    return {
        "base_value": 0.0,
        "prediction_probability": ml_prob,
        "top_positive_features": [],
        "top_negative_features": [],
        "all_features": [],
        "waterfall_data": {
            "labels": [],
            "values": [],
            "base_value": 0.0,
            "final_value": ml_prob
        },
        "status": "fallback"
    }


__all__ = [
    "detect_contradictions",
    "explain_prediction",
    "flag_for_analyst_review",
    "log_contradiction_to_audit",
]
