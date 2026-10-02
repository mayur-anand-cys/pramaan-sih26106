"""
Detects attackers injecting fabricated email headers into the body text to
mimic forwarded messages and bypass header-only scanners.

Attackers bury lines like ``From:``, ``Received:``, ``Return-Path:`` inside
the body to make the email appear to originate from a trusted party.

Detection rules:
  1. Body embeds a From: header whose value differs from the real MIME From
     -> HIGH (20 points)
  2. Body embeds a Return-Path: that differs from the real MIME Return-Path
     -> HIGH (20 points)
  3. Body embeds a Reply-To: or Sender: that differs from MIME
     -> MEDIUM (10 points)
  4. Body contains > 5 embedded header-like lines
     -> MEDIUM (10 points) - indicates fabricated forwarding block
  5. Body Received: chain contains IDs absent from the real MIME headers
     -> HIGH (15 points) - fabricated routing history
  6. Body Subject: or Date: differs from MIME
     -> LOW (5 points) - cosmetic tampering in forwarded block
"""
import re
from typing import Dict, Any, List

# ── Regex & constants ────────────────────────────────────────

# Matches a header-like line at the start of a line in body text
EMBEDDED_HEADER_RE = re.compile(
    r"^(?P<name>From|To|Cc|Bcc|Return-Path|Reply-To|Sender|Received|"
    r"Subject|Date|Message-ID)\s*:\s*(?P<value>.+)$",
    re.IGNORECASE | re.MULTILINE,
)

EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")

# ── Scoring ──────────────────────────────────────────────────

SCORE_FROM_MISMATCH = 20        # HIGH
SCORE_RETURN_PATH_MISMATCH = 20 # HIGH
SCORE_REPLY_SENDER_MISMATCH = 10  # MEDIUM
SCORE_TOO_MANY_HEADERS = 10     # MEDIUM
SCORE_RECEIVED_MISMATCH = 15    # HIGH
SCORE_SUBJECT_DATE_MISMATCH = 5 # LOW

MAX_RISK_MODIFIER = 40          # Cap total contribution

MAX_EMBEDDED_HEADERS_BEFORE_FLAG = 5


# ── Helpers ──────────────────────────────────────────────────

def _normalize_value(value: str) -> str:
    """Strip whitespace, angle brackets, and lowercase for comparison."""
    if not value:
        return ""
    return value.strip().strip("<>").lower()


def _extract_emails(value: str) -> List[str]:
    """Pull every email address out of a header value."""
    return sorted({m.lower() for m in EMAIL_RE.findall(value or "")})


def _headers_equivalent(a: str, b: str) -> bool:
    """
    Return True if two header values are effectively the same.
    Compares normalized strings; if both contain emails, compares the
    set of emails (ignoring display names / formatting).
    """
    norm_a = _normalize_value(a)
    norm_b = _normalize_value(b)
    if norm_a == norm_b:
        return True
    emails_a = _extract_emails(a)
    emails_b = _extract_emails(b)
    if emails_a and emails_b:
        return emails_a == emails_b
    return False


def _get_mime_header(msg, name: str) -> str:
    """Safely fetch a MIME header value from a Message/dict-like object."""
    try:
        v = msg.get(name, "")
        return str(v) if v else ""
    except Exception:
        return ""


# ── Public API ───────────────────────────────────────────────

def extract_embedded_headers(body_text: str) -> Dict[str, List[str]]:
    """
    Find header-like lines inside the body text.

    Returns a dict mapping lowercased header name -> list of values
    (a header can appear multiple times, e.g. Received:).
    """
    found: Dict[str, List[str]] = {}
    if not body_text:
        return found

    for match in EMBEDDED_HEADER_RE.finditer(body_text):
        name = match.group("name").lower()
        value = match.group("value").strip()
        found.setdefault(name, []).append(value)
    return found


def cross_verify_headers(
    mime_headers: Dict[str, Any],
    body_headers: Dict[str, List[str]],
) -> Dict[str, Any]:
    """
    Cross-check body-embedded headers against real MIME headers.

    ``mime_headers`` can be a dict, an EmailMessage, or any object with ``.get``.

    Returns the JSON shape specified in issue #23:
        {
            "embedded_headers_found": int,
            "mismatches": [ {header, mime_value, body_claim, severity, risk_modifier}, ... ],
            "total_risk_modifier": int,
        }
    """
    mismatches: List[Dict[str, Any]] = []
    risk = 0

    total_embedded = sum(len(v) for v in body_headers.values())

    def mime(name: str) -> str:
        return _get_mime_header(mime_headers, name)

    def body_first(name: str) -> str:
        vals = body_headers.get(name.lower(), [])
        return vals[0] if vals else ""

    # ── Rule 1: From mismatch (HIGH) ──
    if body_first("from") and not _headers_equivalent(mime("From"), body_first("from")):
        mismatches.append({
            "header": "From",
            "mime_value": mime("From"),
            "body_claim": body_first("from"),
            "severity": "HIGH",
            "risk_modifier": SCORE_FROM_MISMATCH,
            "explanation": "Body claims a different From identity than MIME headers.",
        })
        risk += SCORE_FROM_MISMATCH

    # ── Rule 2: Return-Path mismatch (HIGH) ──
    if body_first("return-path") and not _headers_equivalent(
        mime("Return-Path"), body_first("return-path")
    ):
        mismatches.append({
            "header": "Return-Path",
            "mime_value": mime("Return-Path"),
            "body_claim": body_first("return-path"),
            "severity": "HIGH",
            "risk_modifier": SCORE_RETURN_PATH_MISMATCH,
            "explanation": "Body claims a different Return-Path than MIME headers.",
        })
        risk += SCORE_RETURN_PATH_MISMATCH

    # ── Rule 3: Reply-To / Sender mismatch (MEDIUM) ──
    for hdr in ("Reply-To", "Sender"):
        bv = body_first(hdr)
        if bv and not _headers_equivalent(mime(hdr), bv):
            mismatches.append({
                "header": hdr,
                "mime_value": mime(hdr),
                "body_claim": bv,
                "severity": "MEDIUM",
                "risk_modifier": SCORE_REPLY_SENDER_MISMATCH,
                "explanation": f"Body claims a different {hdr} than MIME headers.",
            })
            risk += SCORE_REPLY_SENDER_MISMATCH

    # ── Rule 4: Too many embedded header-like lines (MEDIUM) ──
    if total_embedded > MAX_EMBEDDED_HEADERS_BEFORE_FLAG:
        mismatches.append({
            "header": "(structural)",
            "mime_value": "",
            "body_claim": f"{total_embedded} embedded header lines",
            "severity": "MEDIUM",
            "risk_modifier": SCORE_TOO_MANY_HEADERS,
            "explanation": (
                f"Body contains {total_embedded} header-like lines "
                f"(> {MAX_EMBEDDED_HEADERS_BEFORE_FLAG}) — indicative of a fabricated "
                "forwarding block."
            ),
        })
        risk += SCORE_TOO_MANY_HEADERS

    # ── Rule 5: Received: chain not in MIME (HIGH) ──
    body_received = body_headers.get("received", [])
    if body_received:
        mime_received_raw = ""
        try:
            # EmailMessage can have multiple Received headers
            all_received = mime_headers.get_all("Received") if hasattr(
                mime_headers, "get_all"
            ) else None
            if all_received:
                mime_received_raw = " ".join(all_received)
            else:
                mime_received_raw = mime("Received")
        except Exception:
            mime_received_raw = mime("Received")

        # A body Received: is suspicious if its value isn't reflected in MIME
        novel = [
            r for r in body_received
            if _normalize_value(r) not in _normalize_value(mime_received_raw)
        ]
        if novel:
            mismatches.append({
                "header": "Received",
                "mime_value": mime_received_raw[:200],
                "body_claim": novel[0][:200],
                "severity": "HIGH",
                "risk_modifier": SCORE_RECEIVED_MISMATCH,
                "explanation": (
                    f"Body contains {len(novel)} Received: chain entr(y/ies) "
                    "not present in MIME headers — fabricated routing history."
                ),
            })
            risk += SCORE_RECEIVED_MISMATCH

    # ── Rule 6: Subject / Date mismatch (LOW) ──
    for hdr in ("Subject", "Date"):
        bv = body_first(hdr)
        if bv and not _headers_equivalent(mime(hdr), bv):
            mismatches.append({
                "header": hdr,
                "mime_value": mime(hdr),
                "body_claim": bv,
                "severity": "LOW",
                "risk_modifier": SCORE_SUBJECT_DATE_MISMATCH,
                "explanation": f"Body claims a different {hdr} than MIME headers.",
            })
            risk += SCORE_SUBJECT_DATE_MISMATCH

    return {
        "embedded_headers_found": total_embedded,
        "mismatches": mismatches,
        "total_risk_modifier": min(risk, MAX_RISK_MODIFIER),
    }


def detect_body_header_spoofing(msg) -> Dict[str, Any]:
    """
    Top-level entry point for xai_engine.py.

    Extracts the plain-text body from ``msg`` (an EmailMessage, Message,
    or dict-like) then runs extract + cross-verify.

    Returns the same JSON shape as cross_verify_headers, plus:
        ``"is_spoofed"`` - True if any mismatch was found.
    """
    # Pull the body
    body_text = ""
    try:
        if hasattr(msg, "get_body"):
            body_part = msg.get_body(preferencelist=("plain",))
            if body_part is not None:
                body_text = body_part.get_content()
        if not body_text and hasattr(msg, "get_payload"):
            payload = msg.get_payload(decode=True)
            if payload:
                try:
                    body_text = payload.decode("utf-8", errors="replace")
                except Exception:
                    body_text = str(payload)
        if not body_text:
            body_text = _get_mime_header(msg, "Body")
    except Exception:
        body_text = ""

    body_headers = extract_embedded_headers(body_text)
    result = cross_verify_headers(msg, body_headers)
    result["is_spoofed"] = len(result["mismatches"]) > 0
    return result


__all__ = [
    "extract_embedded_headers",
    "cross_verify_headers",
    "detect_body_header_spoofing",
]
