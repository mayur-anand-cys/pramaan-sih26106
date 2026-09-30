"""
Thread Hijacking Detection for PRAMAAN (Issue #22).

Detects attackers injecting fake replies into legitimate email threads by
manipulating In-Reply-To and References headers.

Detection rules:
  1. In-Reply-To references Message-ID whose domain mismatches From domain
     -> CRITICAL (25 points)
  2. References header contains > 10 Message-IDs
     -> HIGH (15 points) - indicates injected thread history
  3. References chain has non-monotonic / suspicious domain switching
     -> HIGH (15 points) - fabricated thread
  4. In-Reply-To present but no References header at all
     -> MEDIUM (8 points) - incomplete thread context
"""
import re
from typing import Dict, Any, List, Optional
from email.message import EmailMessage
from email.utils import parsedate_to_datetime


# ── Regex for extracting Message-IDs ─────────────────────────

MSGID_RE = re.compile(r"<([^>]+)>")
EMAIL_DOMAIN_RE = re.compile(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")


# ── Scoring ──────────────────────────────────────────────────

SCORE_DOMAIN_MISMATCH = 25       # CRITICAL
SCORE_TOO_MANY_REFS = 15         # HIGH
SCORE_FABRICATED_CHAIN = 15      # HIGH
SCORE_MISSING_REFS = 8           # MEDIUM

MAX_RISK_MODIFIER = 40           # Cap total contribution


# ── Helpers ──────────────────────────────────────────────────

def _extract_domain(email_header: str) -> Optional[str]:
    """Extract domain from a From header like 'Name <user@example.com>'."""
    if not email_header:
        return None
    match = EMAIL_DOMAIN_RE.search(email_header.lower())
    return match.group(1) if match else None


def _extract_msgid_domain(msgid: str) -> Optional[str]:
    """Extract domain from a Message-ID like 'abc123@example.com'."""
    if not msgid or "@" not in msgid:
        return None
    return msgid.rsplit("@", 1)[1].strip().lower().rstrip(">")


def _parse_msgids(header_value: str) -> List[str]:
    """Extract all <...> Message-IDs from a header value."""
    if not header_value:
        return []
    return MSGID_RE.findall(header_value)


def _get_header_safe(msg, name: str) -> str:
    """Safely get a header value (handles str or EmailMessage)."""
    try:
        value = msg.get(name, "")
        return str(value) if value else ""
    except Exception:
        return ""


def _detect_fabricated_chain(references: List[str], from_domain: Optional[str]) -> bool:
    """
    Heuristic: a legitimate thread usually stays on one or two domains.
    If the References chain jumps between MANY distinct domains, it's likely
    fabricated. Also flags when the chain mixes the From domain with a
    wild foreign domain in a non-contiguous pattern.
    """
    if len(references) < 3:
        return False

    domains = [_extract_msgid_domain(m) for m in references]
    domains = [d for d in domains if d]

    if not domains:
        return False

    unique = set(domains)

    # Too many distinct domains (> 3) in a chain -> suspicious
    if len(unique) > 3:
        return True

    # If From domain is in the chain but appears, disappears, then reappears
    # (A, B, A) -> fabricated
    if from_domain and from_domain in domains:
        positions = [i for i, d in enumerate(domains) if d == from_domain]
        if len(positions) >= 2:
            # Check if there's a foreign domain between two From-domain hits
            for i in range(len(positions) - 1):
                between = domains[positions[i] + 1 : positions[i + 1]]
                if between and any(d != from_domain for d in between):
                    return True

    return False


# ── Main function ────────────────────────────────────────────

def detect_thread_hijacking(msg) -> Dict[str, Any]:
    """
    Analyze an email for thread hijacking anomalies.

    Accepts either an email.message.Message / EmailMessage or a dict with
    header keys.

    Returns:
        {
            "is_hijacked": bool,
            "anomalies": [ {type, severity, explanation, ...}, ... ],
            "risk_modifier": int,     # 0-40
            "thread_context": {       # extra info for debugging
                "in_reply_to": str,
                "references_count": int,
                "from_domain": str,
                "referenced_domains": [str, ...]
            }
        }
    """
    anomalies: List[Dict[str, Any]] = []
    risk = 0

    # ── Extract headers ──
    in_reply_to_raw = _get_header_safe(msg, "In-Reply-To")
    references_raw = _get_header_safe(msg, "References")
    from_header = _get_header_safe(msg, "From")

    in_reply_to_ids = _parse_msgids(in_reply_to_raw)
    references_ids = _parse_msgids(references_raw)

    from_domain = _extract_domain(from_header)

    # ── Rule 1: In-Reply-To domain mismatch (CRITICAL) ──
    if in_reply_to_ids and from_domain:
        in_reply_to_domain = _extract_msgid_domain(in_reply_to_ids[0])
        if in_reply_to_domain and in_reply_to_domain != from_domain:
            anomalies.append({
                "type": "DOMAIN_MISMATCH",
                "severity": "CRITICAL",
                "in_reply_to": in_reply_to_raw.strip(),
                "in_reply_to_domain": in_reply_to_domain,
                "from_domain": from_domain,
                "explanation": (
                    f"In-Reply-To references {in_reply_to_domain} "
                    f"but From is {from_domain}"
                ),
                "points": SCORE_DOMAIN_MISMATCH,
            })
            risk += SCORE_DOMAIN_MISMATCH

    # ── Rule 2: References header > 10 IDs ──
    if len(references_ids) > 10:
        anomalies.append({
            "type": "EXCESSIVE_REFERENCES",
            "severity": "HIGH",
            "references_count": len(references_ids),
            "explanation": (
                f"References header has {len(references_ids)} Message-IDs "
                f"(> 10 indicates injected thread history)"
            ),
            "points": SCORE_TOO_MANY_REFS,
        })
        risk += SCORE_TOO_MANY_REFS

    # ── Rule 3: Fabricated References chain ──
    if _detect_fabricated_chain(references_ids, from_domain):
        ref_domains = list({
            _extract_msgid_domain(m) for m in references_ids if _extract_msgid_domain(m)
        })
        anomalies.append({
            "type": "FABRICATED_CHAIN",
            "severity": "HIGH",
            "referenced_domains": ref_domains,
            "explanation": (
                f"References chain switches across {len(ref_domains)} domains "
                f"({', '.join(ref_domains[:5])}) - likely fabricated"
            ),
            "points": SCORE_FABRICATED_CHAIN,
        })
        risk += SCORE_FABRICATED_CHAIN

    # ── Rule 4: In-Reply-To without References ──
    if in_reply_to_ids and not references_ids:
        anomalies.append({
            "type": "MISSING_REFERENCES",
            "severity": "MEDIUM",
            "in_reply_to": in_reply_to_raw.strip(),
            "explanation": (
                "In-Reply-To present but References header is empty - "
                "incomplete thread context"
            ),
            "points": SCORE_MISSING_REFS,
        })
        risk += SCORE_MISSING_REFS

    # ── Cap risk modifier ──
    risk_modifier = min(risk, MAX_RISK_MODIFIER)

    referenced_domains = sorted({
        _extract_msgid_domain(m) for m in references_ids if _extract_msgid_domain(m)
    })

    return {
        "is_hijacked": len(anomalies) > 0,
        "anomalies": anomalies,
        "risk_modifier": risk_modifier,
        "thread_context": {
            "in_reply_to": in_reply_to_raw.strip(),
            "references_count": len(references_ids),
            "from_domain": from_domain,
            "referenced_domains": referenced_domains,
        },
    }


__all__ = ["detect_thread_hijacking"]
