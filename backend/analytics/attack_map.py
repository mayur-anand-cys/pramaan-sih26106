"""
MITRE ATT&CK technique mapping for PRAMAAN risk factors.

Maps internal risk categories (as produced by detection modules) to
official MITRE ATT&CK technique IDs and names. Used to enrich the
`risk_factors` list in the analyze pipeline so the UI can show a
technique badge next to each finding.

Ref: Issue #44

MITRE ATT&CK reference: https://attack.mitre.org/
"""

from typing import Any, Dict, List


ATTACK_MAPPINGS: Dict[str, Dict[str, str]] = {
    "Authentication":           {"id": "T1556",     "name": "Modify Authentication Process"},
    "Header Mismatch":          {"id": "T1036.005", "name": "Masquerading: Match Legitimate Name"},
    "Suspicious Keywords":      {"id": "T1566.002", "name": "Phishing: Spearphishing Link"},
    "URL Metrics":              {"id": "T1566.002", "name": "Phishing: Spearphishing Link"},
    "ML Classifier":            {"id": "T1566",     "name": "Phishing"},
    "Typosquat":                {"id": "T1583.001", "name": "Acquire Infrastructure: Domains"},
    "Thread Hijacking":         {"id": "T1534",     "name": "Internal Spearphishing"},
    "Header Injection":         {"id": "T1036",     "name": "Masquerading"},
    "Quishing":                 {"id": "T1566.002", "name": "Phishing: Spearphishing Link"},
    "Macro-Enabled Attachment": {"id": "T1204.002", "name": "User Execution: Malicious File"},
}

# Default when category isn't in the mapping table
DEFAULT_MAPPING = {"id": "T1566", "name": "Phishing"}


def map_to_attack(category: str) -> Dict[str, str]:
    """
    Return the MITRE ATT&CK mapping for a given risk category.

    Falls back to the default (T1566 - Phishing) if the category isn't
    in the mapping table.
    """
    return ATTACK_MAPPINGS.get(category, DEFAULT_MAPPING)


def enrich_risk_factors(risk_factors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Add `attack_id` and `attack_name` keys to each risk factor dict.

    Mutates in place AND returns the same list for convenience.
    """
    for f in risk_factors:
        category = f.get("category") or f.get("factor", "")
        m = map_to_attack(category)
        f["attack_id"] = m["id"]
        f["attack_name"] = m["name"]
    return risk_factors