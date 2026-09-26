# backend/detection/auth_check.py
"""Email authentication verification module.
Implements live SPF, DKIM, DMARC, and ARC checks using dnspython,
pyspf, and dkimpy. Provides a unified header‑trust score (0‑100).
"""

import logging
import email
from email import policy
from typing import Dict, Any, Optional

import dns.resolver
import spf as pyspf  # pyspf wheel installs the module as spf.py
import dkim

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _parse_email(raw_email: str) -> email.message.EmailMessage:
    """Parse raw email string into an EmailMessage object.

    Returns a message even if the content is malformed; logs an error and
    returns an empty Message on failure.
    """
    try:
        return email.message_from_string(raw_email, policy=policy.default)
    except Exception as exc:  # pragma: no cover – defensive
        logger.error("Failed to parse email: %s", exc)
        return email.message.EmailMessage()

def _extract_header(msg: email.message.EmailMessage, name: str) -> str:
    """Return the first occurrence of *name* header or an empty string.
    Header‑lookup is case‑insensitive.
    """
    for h, v in msg.items():
        if h.lower() == name.lower():
            return v.strip()
    return ""

# ---------------------------------------------------------------------------
# SPF
# ---------------------------------------------------------------------------

def check_spf(raw_email: str, source_ip: Optional[str] = None) -> Dict[str, Any]:
    """Validate SPF for *raw_email*.

    Returns a dict with:
    - ``header_result`` – value reported in ``Received-SPF`` or
      ``Authentication-Results`` (``pass``, ``fail`` etc.) or ``"none"``.
    - ``dns_verified`` – ``True`` if the DNS query succeeded.
    - ``dns_result`` – result from ``pyspf.check2`` (``pass``/``fail``/…).
    - ``domain`` – the envelope‑from domain used for verification.
    - ``sender_ip`` – the IP supplied (or ``None``).
    - ``details`` – human‑readable explanation.
    """
    msg = _parse_email(raw_email)
    # Header result: Received-SPF format is "<result> (explanation...)"
    # Authentication-Results format is "...; spf=<result> ..."
    received_spf = _extract_header(msg, "Received-SPF")
    auth_results = _extract_header(msg, "Authentication-Results")
    header_result = "none"
    if received_spf:
        first_word = received_spf.strip().split()[0].lower().rstrip(";")
        if first_word in {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}:
            header_result = first_word
    elif auth_results:
        for part in auth_results.split(";"):
            part = part.strip()
            if part.lower().startswith("spf="):
                header_result = part.split("=", 1)[1].strip().lower().split()[0]
                break
    # Envelope‑from (MAIL FROM) – try ``Return-Path`` first, strip angle brackets
    mail_from = _extract_header(msg, "Return-Path") or _extract_header(msg, "Envelope-From")
    mail_from = mail_from.strip("<>")
    domain = ""
    if mail_from:
        if "@" in mail_from:
            domain = mail_from.split("@")[-1].strip().lower()
        else:
            domain = mail_from.strip().lower()
    result: Dict[str, Any] = {
        "header_result": header_result,
        "dns_verified": False,
        "dns_result": "none",
        "domain": domain,
        "sender_ip": source_ip,
        "details": "",
    }
    if not domain:
        result["details"] = "No domain found for SPF verification"
        return result
    # Perform live SPF check
    try:
        spf_result, explanation = pyspf.check2(i=source_ip or "0.0.0.0", s=mail_from or "", h=domain)
        result["dns_verified"] = True
        result["dns_result"] = spf_result.lower()
        result["details"] = explanation
    except Exception as exc:
        logger.error("SPF lookup failed: %s", exc)
        result["details"] = f"SPF lookup error: {exc}"
    return result

# ---------------------------------------------------------------------------
# DKIM
# ---------------------------------------------------------------------------

def check_dkim(raw_email: str) -> Dict[str, Any]:
    """Verify DKIM signature.

    Returns a dict with ``header_result`` (value from ``Authentication-Results``
    if present, otherwise ``"none"``), ``dns_verified`` indicating whether the
    cryptographic verification succeeded, ``dns_result`` (``pass``/``fail``),
    ``domain`` and ``selector`` extracted from the ``DKIM‑Signature`` header.
    """
    msg = _parse_email(raw_email)
    auth_hdr = _extract_header(msg, "Authentication-Results")
    header_result = "none"
    if auth_hdr and "dkim=" in auth_hdr.lower():
        for part in auth_hdr.split(";"):
            if "dkim=" in part.lower():
                header_result = part.split("=")[-1].strip().lower()
                break
    dkim_sig = _extract_header(msg, "DKIM-Signature")
    domain = selector = ""
    if dkim_sig:
        # Extract ``d=`` (domain) and ``s=`` (selector)
        for token in dkim_sig.split(";"):
            token = token.strip()
            if token.startswith("d="):
                domain = token[2:].strip()
            elif token.startswith("s="):
                selector = token[2:].strip()
    result: Dict[str, Any] = {
        "header_result": header_result,
        "dns_verified": False,
        "dns_result": "none",
        "domain": domain,
        "selector": selector,
        "details": "",
    }
    try:
        verified = dkim.verify(raw_email.encode())
        result["dns_verified"] = True
        result["dns_result"] = "pass" if verified else "fail"
        result["details"] = "DKIM signature verification succeeded" if verified else "DKIM verification failed"
    except Exception as exc:  # pragma: no cover – malformed signature / missing key
        logger.error("DKIM verification error: %s", exc)
        result["details"] = f"DKIM verification error: {exc}"
    return result

# ---------------------------------------------------------------------------
# DMARC
# ---------------------------------------------------------------------------

def _query_dmarc(domain: str) -> Optional[Dict[str, str]]:
    """Fetch the DMARC TXT record for *domain*.
    Returns a mapping of tag → value (e.g. ``{"p": "reject"}``) or ``None``.
    """
    dmarc_name = f"_dmarc.{domain}"
    try:
        answer = dns.resolver.resolve(dmarc_name, "TXT", lifetime=5)
        txt = b"".join(answer[0].strings).decode()
        # Split on ';' and strip whitespace
        tags = {kv.split("=")[0].strip(): kv.split("=")[1].strip() for kv in txt.split(";") if "=" in kv}
        return tags
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout) as exc:
        logger.warning("DMARC lookup failed for %s: %s", domain, exc)
        return None
    except Exception as exc:  # pragma: no cover – unexpected errors
        logger.error("DMARC query error: %s", exc)
        return None


def check_dmarc(
    raw_email: str,
    spf_result: Dict[str, Any],
    dkim_result: Dict[str, Any],
) -> Dict[str, Any]:
    """Perform DMARC alignment and policy lookup.

    ``spf_result`` and ``dkim_result`` are the dicts returned by the
    corresponding functions. The function checks domain alignment (strict) and
    returns a dict containing header and DNS results.
    """
    msg = _parse_email(raw_email)
    auth_hdr = _extract_header(msg, "Authentication-Results")
    header_result = "none"
    if auth_hdr and "dmarc=" in auth_hdr.lower():
        for part in auth_hdr.split(";"):
            if "dmarc=" in part.lower():
                header_result = part.split("=")[-1].strip().lower()
                break
    from_hdr = _extract_header(msg, "From")
    from_domain = ""
    if from_hdr:
        # Extract email address inside angle brackets if present
        if "<" in from_hdr and ">" in from_hdr:
            addr = from_hdr.split("<")[-1].split(">")[0]
        else:
            addr = from_hdr
        if "@" in addr:
            from_domain = addr.split("@")[-1].strip().lower()
    # DMARC policy lookup using the From domain (RFC recommends that domain)
    dmarc_tags = _query_dmarc(from_domain) if from_domain else None
    policy = dmarc_tags.get("p") if dmarc_tags else "none"
    # Alignment checks (strict)
    spf_aligned = spf_result.get("domain") == from_domain and spf_result.get("dns_result") == "pass"
    dkim_aligned = dkim_result.get("domain") == from_domain and dkim_result.get("dns_result") == "pass"
    result: Dict[str, Any] = {
        "header_result": header_result,
        "dns_verified": bool(dmarc_tags),
        "dns_result": "pass" if dmarc_tags else "none",
        "policy": policy,
        "spf_alignment": spf_aligned,
        "dkim_alignment": dkim_aligned,
        "domain": from_domain,
        "details": "",
    }
    if dmarc_tags:
        result["details"] = f"DMARC policy {policy} with spf_alignment={spf_aligned}, dkim_alignment={dkim_aligned}"
    else:
        result["details"] = "DMARC record not found"
    return result

# ---------------------------------------------------------------------------
# ARC
# ---------------------------------------------------------------------------

def check_arc(raw_email: str) -> Dict[str, Any]:
    """Validate ARC seals if present.

    Returns ``header_result`` (from Authentication‑Results if available),
    ``seal_verified`` (bool), ``dns_result`` (``pass``/``fail``/``none``) and a
    textual description.
    """
    msg = _parse_email(raw_email)
    auth_hdr = _extract_header(msg, "Authentication-Results")
    header_result = "none"
    if auth_hdr and "arc=" in auth_hdr.lower():
        for part in auth_hdr.split(";"):
            if "arc=" in part.lower():
                header_result = part.split("=")[-1].strip().lower()
                break
    # dkim.arc_verify expects the raw message bytes
    try:
        verified = dkim.arc_verify(raw_email.encode())
        dns_result = "pass" if verified else "fail"
        seal_verified = verified
    except Exception as exc:  # pragma: no cover – ARC not present or lib missing
        logger.info("ARC verification not performed: %s", exc)
        dns_result = "none"
        seal_verified = False
    return {
        "header_result": header_result,
        "seal_verified": seal_verified,
        "dns_result": dns_result,
        "details": "ARC verification succeeded" if seal_verified else "ARC not verified",
    }

# ---------------------------------------------------------------------------
# Header trust score
# ---------------------------------------------------------------------------

def compute_header_trust_score(
    spf: Dict[str, Any],
    dkim: Dict[str, Any],
    dmarc: Dict[str, Any],
    arc: Dict[str, Any],
) -> int:
    """Combine individual check results into a 0‑100 trust score.

    Simple heuristic (customisable): each PASS adds 25 points. Alignment and
    policy compliance provide additional bonuses.
    """
    score = 0
    if spf.get("dns_result") == "pass":
        score += 20
    if dkim.get("dns_result") == "pass":
        score += 20
    if dmarc.get("dns_result") == "pass":
        score += 20
        if dmarc.get("spf_alignment"):
            score += 5
        if dmarc.get("dkim_alignment"):
            score += 5
        if dmarc.get("policy") == "reject":
            score += 5
    if arc.get("seal_verified"):
        score += 15
    return min(max(score, 0), 100)

# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def verify_email_auth(raw_email: str, source_ip: Optional[str] = None) -> Dict[str, Any]:
    """Run the full authentication workflow and return a consolidated dict.
    The shape matches the specification in the design document.
    """
    spf_res = check_spf(raw_email, source_ip)
    dkim_res = check_dkim(raw_email)
    dmarc_res = check_dmarc(raw_email, spf_res, dkim_res)
    arc_res = check_arc(raw_email)
    trust_score = compute_header_trust_score(spf_res, dkim_res, dmarc_res, arc_res)
    return {
        "spf": spf_res,
        "dkim": dkim_res,
        "dmarc": dmarc_res,
        "arc": arc_res,
        "header_trust_score": trust_score,
    }

__all__ = [
    "check_spf",
    "check_dkim",
    "check_dmarc",
    "check_arc",
    "compute_header_trust_score",
    "verify_email_auth",
]
