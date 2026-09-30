import re
import email
from typing import Dict, List, Any, Tuple

# Thread hijacking detection (Issue #22)
from backend.detection.thread_hijack import detect_thread_hijacking

BRAND_KEYWORDS = {
    "paypal": "PayPal Inc.",
    "bank": "Financial Institution",
    "microsoft": "Microsoft 365",
    "google": "Google Services",
    "apple": "Apple ID",
    "netflix": "Netflix Inc.",
    "amazon": "Amazon",
    "stripe": "Stripe Payments"
}

URGENCY_KEYWORDS = [
    "urgent", "suspended", "verify", "unauthorized", "immediately",
    "action required", "account locked", "wire transfer", "security alert"
]

def detect_xai_contradictions(
    msg: email.message.EmailMessage,
    body_text: str,
    analyzed_urls: List[Dict[str, Any]],
    auth_info: Dict[str, str],
    domain_alignment: Dict[str, Any],
    ml_prob: float
) -> Dict[str, Any]:
    """
    Explainable AI (XAI) Contradiction Detection Engine.
    Identifies logical, structural, and linguistic contradictions between
    what an email claims (identity, intent, policy) vs technical forensic evidence.
    """
    contradictions = []

    # ── Thread hijacking analysis (Issue #22) ──
    try:
        _hijack = detect_thread_hijacking(msg)
        if _hijack.get("is_hijacked"):
            for anom in _hijack["anomalies"]:
                sev = anom.get("severity", "MEDIUM")
                contradictions.append({
                    "type": f"THREAD_{anom['type']}",
                    "severity": sev,
                    "field": "In-Reply-To/References",
                    "explanation": anom.get("explanation", ""),
                    "detail": anom,
                })
    except Exception:
        pass  # never break XAI on hijack errors

    subject = str(msg.get("Subject", "")).lower()
    from_header = str(msg.get("From", "")).lower()
    body_lower = body_text.lower()
    combined_text = f"{subject} {from_header} {body_lower}"

    # 1. Identity & Brand Contradiction
    claimed_brand = None
    for kw, brand_name in BRAND_KEYWORDS.items():
        if kw in from_header or kw in subject:
            claimed_brand = brand_name
            break

    from_domain = domain_alignment.get("from_domain", "")
    return_domain = domain_alignment.get("return_domain", "")

    if claimed_brand:
        # Check if domain matches brand name
        brand_kw = claimed_brand.split()[0].lower()
        if brand_kw not in from_domain:
            contradictions.append({
                "type": "Identity & Brand Contradiction",
                "severity": "CRITICAL",
                "claim": f"Sender claims to represent '{claimed_brand}' in Subject/Header.",
                "evidence": f"Actual sender domain is '{from_domain}' (Return-Path: '{return_domain}').",
                "explanation": f"High confidence brand spoofing detected: Email claims to be from {claimed_brand}, but is sent from unassociated domain '{from_domain}'."
            })

    if domain_alignment.get("is_spoofed"):
        contradictions.append({
            "type": "Envelope Domain Mismatch",
            "severity": "HIGH",
            "claim": f"Header From claims sender domain '{from_domain}'.",
            "evidence": f"Mail routing Return-Path points to domain '{return_domain}'.",
            "explanation": f"Routing contradiction: The visible sender domain '{from_domain}' does not match the actual mail server envelope domain '{return_domain}'."
        })

    # 2. Authentication vs Claim Contradiction
    spf_status = auth_info.get("spf", "UNKNOWN")
    dkim_status = auth_info.get("dkim", "UNKNOWN")
    dmarc_status = auth_info.get("dmarc", "UNKNOWN")

    if claimed_brand and (spf_status == "FAIL" or dkim_status == "FAIL"):
        contradictions.append({
            "type": "Authentication vs Brand Claim",
            "severity": "CRITICAL",
            "claim": f"Email claims official notification status from {claimed_brand}.",
            "evidence": f"Cryptographic authentication failed (SPF: {spf_status}, DKIM: {dkim_status}).",
            "explanation": f"Security assertion failed: Legitimate messages from {claimed_brand} pass SPF/DKIM authentication. This email failed authentication validation."
        })

    # 3. Destination URL vs Text Intent Contradiction
    found_urgency_words = [w for w in URGENCY_KEYWORDS if w in combined_text]

    for u_info in analyzed_urls:
        url_str = u_info.get("url", "")
        domain_str = u_info.get("domain", "")
        flags = u_info.get("flags", [])

        if u_info.get("is_ip"):
            contradictions.append({
                "type": "Destination URL vs Security Norm Contradiction",
                "severity": "CRITICAL",
                "claim": "Email text requests account login / verification action.",
                "evidence": f"Hyperlink points directly to unencrypted raw IP address '{url_str}'.",
                "explanation": f"Protocol contradiction: Legitimate organizations never route login links to raw numerical IP addresses ({domain_str})."
            })

        elif u_info.get("tld"):
            tld = u_info.get("tld")
            contradictions.append({
                "type": "Suspicious TLD Infrastructure Contradiction",
                "severity": "HIGH",
                "claim": f"Message claims official communication from {claimed_brand or 'trusted entity'}.",
                "evidence": f"Hyperlink targets high-risk disposable TLD '{tld}' ({domain_str}).",
                "explanation": f"Infrastructure contradiction: Destination link uses high-risk TLD '{tld}' commonly associated with phishing campaigns."
            })

    # 4. Social Engineering Urgency Contradiction
    if found_urgency_words and (ml_prob > 0.4 or spf_status == "FAIL"):
        contradictions.append({
            "type": "Social Engineering Urgency Contradiction",
            "severity": "HIGH",
            "claim": f"Urgency language prompts immediate action ({', '.join(found_urgency_words[:3])}).",
            "evidence": f"TF-IDF ML Classifier estimated {ml_prob * 100:.1f}% phishing probability with suspicious routing.",
            "explanation": "Psychological manipulation pattern: Artificial time pressure detected combined with unverified infrastructure flags."
        })

    critical_count = sum(1 for c in contradictions if c["severity"] == "CRITICAL")
    high_count = sum(1 for c in contradictions if c["severity"] == "HIGH")
    xai_score = min(100, critical_count * 35 + high_count * 20 + len(contradictions) * 10)

    return {
        "xai_contradiction_score": xai_score,
        "total_contradictions": len(contradictions),
        "critical_count": critical_count,
        "high_count": high_count,
        "contradictions": contradictions,
        "summary": f"Detected {len(contradictions)} logical contradiction(s) ({critical_count} Critical, {high_count} High Risk)."
    }
