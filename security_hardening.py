"""
PRAMAAN Security Hardening — Consolidated Defense Module.
"""
import os
import re
import sys
import gzip
import zipfile
import hashlib
import ipaddress
import unicodedata
import json
from io import BytesIO
from pathlib import Path
from typing import Dict, List, Any, Tuple
import email
from email import policy


MAX_UPLOAD_MB = 10
MAX_DECOMPRESSED_MB = 50
MAX_MIME_DEPTH = 20
MAX_MIME_PARTS = 500

BRAND_LOOKALIKES = {
    "microsoft": ["rnicrosoft", "micros0ft", "microsoft-", "-microsoft", "microsoftlogin"],
    "google": ["g00gle", "goog1e", "google-", "-google", "googlesecure"],
    "paypal": ["paypa1", "paypal-", "-paypal", "paypalsecure"],
    "sbi": ["sbi-", "-sbi", "sbisecure", "sbiin"],
    "hdfc": ["hdfc-", "-hdfc", "hdfcbank-", "hdfcsecure"],
    "icici": ["icici-", "-icici", "icicibank-"],
    "amazon": ["amaz0n", "amazon-", "-amazon"],
    "apple": ["app1e", "apple-", "-apple"],
}

TRUSTED_MTA_KEYWORDS = [
    "mail.protection.outlook.com",
    "google.com", "googlemail.com",
    "amazonses.com", "sendgrid.net", "mailgun.org",
]


def parse_email_safely(raw_bytes: bytes) -> email.message.EmailMessage:
    if len(raw_bytes) > MAX_UPLOAD_MB * 1024 * 1024:
        raise ValueError(f"Email exceeds {MAX_UPLOAD_MB}MB limit")

    old_limit = sys.getrecursionlimit()
    sys.setrecursionlimit(min(old_limit, 3000))

    try:
        msg = email.message_from_bytes(raw_bytes, policy=policy.default)
        part_count = 0
        for part in msg.walk():
            part_count += 1
            if part_count > MAX_MIME_PARTS:
                raise ValueError(f"MIME parts exceed {MAX_MIME_PARTS} limit")
        return msg
    except RecursionError:
        raise ValueError("Malicious MIME structure detected — depth exceeds safe limit")
    finally:
        sys.setrecursionlimit(old_limit)


def safe_attachment_scan(attachment_bytes: bytes) -> Dict[str, Any]:
    result = {"safe": True, "flags": [], "declared_size": len(attachment_bytes)}

    if attachment_bytes[:2] == b'\x1f\x8b':
        try:
            with gzip.open(BytesIO(attachment_bytes)) as gz:
                decompressed = gz.read(MAX_DECOMPRESSED_MB * 1024 * 1024 + 1)
                if len(decompressed) > MAX_DECOMPRESSED_MB * 1024 * 1024:
                    result["safe"] = False
                    result["flags"].append("GZIP_BOMB_DETECTED")
        except Exception:
            result["safe"] = False
            result["flags"].append("GZIP_PARSE_ERROR")

    if attachment_bytes[:2] == b'PK':
        try:
            with zipfile.ZipFile(BytesIO(attachment_bytes)) as z:
                total = sum(i.file_size for i in z.infolist())
                if total > MAX_DECOMPRESSED_MB * 1024 * 1024:
                    result["safe"] = False
                    result["flags"].append("ZIP_BOMB_DETECTED")
                    result["declared_size"] = total
        except Exception:
            result["safe"] = False
            result["flags"].append("ZIP_PARSE_ERROR")

    return result


def extract_ip_from_received(header_value: str) -> str:
    match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', str(header_value))
    if match:
        return match.group(1)
    match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', str(header_value))
    return match.group(1) if match else ""


def validate_received_chain(received_headers: list) -> Dict[str, Any]:
    chrono = list(reversed(received_headers))
    trusted_edge_found = False
    trusted_edge_ip = None
    anomalies = []

    for idx, hop in enumerate(chrono):
        ip_match = extract_ip_from_received(hop)
        if not ip_match:
            continue
        try:
            ip_obj = ipaddress.ip_address(ip_match)
        except ValueError:
            continue
        is_private = ip_obj.is_private or ip_obj.is_loopback
        if not is_private and not trusted_edge_found:
            trusted_edge_found = True
            trusted_edge_ip = ip_match
            continue
        if trusted_edge_found and is_private:
            anomalies.append({
                "hop_index": idx,
                "ip": ip_match,
                "reason": "PRIVATE_IP_AFTER_PUBLIC_EDGE",
                "severity": "HIGH",
                "risk_modifier": 20,
                "explanation": (
                    f"Hop {idx}: Private IP {ip_match} after trusted public edge "
                    f"{trusted_edge_ip}. Physically impossible in SMTP — header injection."
                ),
            })

    return {
        "trusted_edge_ip": trusted_edge_ip,
        "anomalies": anomalies,
        "risk_modifier": min(60, sum(a["risk_modifier"] for a in anomalies)),
    }


def detect_lookalike_with_valid_auth(from_domain: str, auth_results: Dict) -> Dict[str, Any]:
    anomalies = []
    domain_lower = (from_domain or "").lower()
    for brand, patterns in BRAND_LOOKALIKES.items():
        for pattern in patterns:
            if pattern in domain_lower:
                real_domains = [f"{brand}.com", f"{brand}.co.in", f"{brand}.gov.in"]
                if domain_lower not in real_domains:
                    anomalies.append({
                        "type": "LOOKALIKE_DOMAIN_WITH_VALID_AUTH",
                        "severity": "CRITICAL",
                        "domain": from_domain,
                        "impersonates": brand,
                        "auth_status": f"SPF={auth_results.get('spf')}, DKIM={auth_results.get('dkim')}, DMARC={auth_results.get('dmarc')}",
                        "explanation": (
                            f"'{from_domain}' impersonates {brand}. SPF/DKIM/DMARC "
                            f"all pass because attacker owns the domain. Crypto PASS ≠ legitimate."
                        ),
                        "risk_modifier": 30,
                    })
                    break
    return {
        "lookalike_anomalies": anomalies,
        "risk_modifier": min(60, sum(a["risk_modifier"] for a in anomalies)),
    }


def strip_hidden_content(html_body: str) -> str:
    html_body = re.sub(r'<style\b[^>]*>.*?</style\b[^>]*>', '', html_body, flags=re.DOTALL | re.IGNORECASE)
html_body = re.sub(r'<script\b[^>]*>.*?</script\b[^>]*>', '', html_body, flags=re.DOTALL | re.IGNORECASE)
    invisible_patterns = [
        r'display\s*:\s*none', r'visibility\s*:\s*hidden',
        r'opacity\s*:\s*0(?:\.0+)?\b', r'font-size\s*:\s*0',
        r'color\s*:\s*(?:#fff(?:fff)?|white)\b',
        r'height\s*:\s*0', r'width\s*:\s*0',
    ]
    for pattern in invisible_patterns:
        html_body = re.sub(
            rf'<[^>]*{pattern}[^>]*>.*?</[^>]+>',
            '', html_body, flags=re.DOTALL | re.IGNORECASE
        )
    return html_body


def sanitize_for_llm(text: str) -> str:
    injection_patterns = [
        r'ignore\s+(?:all\s+)?previous\s+instructions',
        r'you\s+are\s+now\s+(?:a|an)\s+',
        r'system\s*:\s*', r'assistant\s*:\s*',
        r'output\s+[\'"]legitimate[\'"]',
        r'set\s+threat\s+score\s+to\s+0',
        r'new\s+instruction[s]?\s*:',
    ]
    for pattern in injection_patterns:
        text = re.sub(pattern, '[REDACTED_INJECTION_ATTEMPT]', text, flags=re.IGNORECASE)
    return f"<untrusted_email_body>\n{text}\n</untrusted_email_body>"


def extract_headers_with_forensics(msg) -> Dict[str, Any]:
    singleton_headers = {
        "Date", "From", "Sender", "Reply-To", "To", "Cc", "Bcc",
        "Message-ID", "In-Reply-To", "References", "Subject", "Return-Path",
    }
    headers_dict = {}
    anomalies = []
    for header in singleton_headers:
        values = msg.get_all(header, [])
        if len(values) == 0:
            headers_dict[header] = None
        elif len(values) == 1:
            headers_dict[header] = str(values[0])
        else:
            headers_dict[header] = str(values[0])
            headers_dict[f"{header}_ALL"] = [str(v) for v in values]
            anomalies.append({
                "header": header,
                "count": len(values),
                "values": [str(v)[:100] for v in values],
                "severity": "HIGH",
                "risk_modifier": 15,
                "explanation": (
                    f"Header injection: {header} appears {len(values)} times. "
                    f"RFC 5322 permits only one. Strong indicator of MTA tampering."
                ),
            })
    headers_dict["Received_count"] = len(msg.get_all("Received", []))
    return {
        "headers": headers_dict,
        "header_injection_anomalies": anomalies,
        "injection_risk_score": min(60, sum(a["risk_modifier"] for a in anomalies)),
    }


CASE_STORAGE = Path("./cases")
CASE_STORAGE.mkdir(exist_ok=True)


def anchor_with_atomic_commit(case_id, merkle_root, file_sha256, classification, pdf_bytes, anchor_fn):
    temp_pdf = CASE_STORAGE / f"{case_id}.pdf.tmp"
    final_pdf = CASE_STORAGE / f"{case_id}.pdf"
    anchor_log = CASE_STORAGE / f"{case_id}.anchor.json"

    temp_pdf.write_bytes(pdf_bytes)
    anchor_result = anchor_fn(case_id, merkle_root, file_sha256, classification)

    if not anchor_result.get("success"):
        temp_pdf.unlink(missing_ok=True)
        return {"success": False, "stage": "BLOCKCHAIN_FAILED", "error": anchor_result.get("error")}

    anchor_log.write_text(json.dumps({
        "case_id": case_id,
        "tx_hash": anchor_result["tx_hash"],
        "merkle_root": merkle_root,
        "file_sha256": file_sha256,
    }, indent=2))

    try:
        temp_pdf.rename(final_pdf)
    except Exception as e:
        return {
            "success": False,
            "stage": "ORPHANED_HASH",
            "tx_hash": anchor_result["tx_hash"],
            "error": str(e),
        }

    return {"success": True, "pdf_path": str(final_pdf), "tx_hash": anchor_result["tx_hash"]}


def run_all_defenses(raw_bytes: bytes, msg, body_text: str, auth_results: Dict) -> Dict[str, Any]:
    total_risk = 0
    all_anomalies = []

    if len(raw_bytes) > MAX_UPLOAD_MB * 1024 * 1024:
        return {"blocked": True, "reason": "FILE_TOO_LARGE"}

    received = msg.get_all("Received", [])
    if received:
        chain = validate_received_chain(received)
        total_risk += chain["risk_modifier"]
        all_anomalies.extend(chain["anomalies"])

    from_header = str(msg.get("From", ""))
    from_domain = from_header.split("@")[-1].strip("> ") if "@" in from_header else ""
    lookalike = detect_lookalike_with_valid_auth(from_domain, auth_results)
    total_risk += lookalike["risk_modifier"]
    all_anomalies.extend(lookalike["lookalike_anomalies"])

    dup = extract_headers_with_forensics(msg)
    total_risk += dup["injection_risk_score"]
    all_anomalies.extend(dup["header_injection_anomalies"])

    return {
        "blocked": False,
        "total_security_risk": min(100, total_risk),
        "anomalies": all_anomalies,
        "headers": dup["headers"],
    }