"""
Tests for Body-Embedded Header Spoofing Detection (Issue #23).
Run: python tests/test_body_header_check.py
"""
import sys
from pathlib import Path
from email.message import EmailMessage

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.detection.body_header_check import (
    extract_embedded_headers,
    cross_verify_headers,
    detect_body_header_spoofing,
)


def _make_msg(headers: dict, body: str = "") -> EmailMessage:
    """Build an EmailMessage with headers and a plain-text body."""
    msg = EmailMessage()
    for k, v in headers.items():
        msg[k] = v
    msg.set_content(body)
    return msg


# ── Test 1: Clean email, no embedded headers ─────────────

def test_clean_email_no_embedded_headers():
    body = "Hello team,\n\nHere is the quarterly report.\n\nRegards,\nAlice"
    msg = _make_msg(
        {"From": "alice@company.com", "Subject": "Q3 report"},
        body=body,
    )
    result = detect_body_header_spoofing(msg)
    assert result["embedded_headers_found"] == 0, result
    assert result["mismatches"] == [], result
    assert result["total_risk_modifier"] == 0, result
    assert result["is_spoofed"] is False
    print("   [OK] Clean email → 0 embedded headers, 0 risk")


# ── Test 2: From mismatch between MIME and body ──────────

def test_from_mismatch_flagged_high():
    body = (
        "---------- Forwarded message ----------\n"
        "From: ceo@company.com\n"
        "Subject: Wire transfer approval\n"
        "\nPlease approve the pending wire.\n"
    )
    msg = _make_msg(
        {"From": "attacker@evil.ru", "Subject": "Fwd: Wire transfer"},
        body=body,
    )
    result = detect_body_header_spoofing(msg)
    assert result["embedded_headers_found"] >= 2, result
    from_mismatches = [m for m in result["mismatches"] if m["header"] == "From"]
    assert len(from_mismatches) == 1, result
    assert from_mismatches[0]["severity"] == "HIGH"
    assert from_mismatches[0]["risk_modifier"] == 20
    assert from_mismatches[0]["mime_value"] == "attacker@evil.ru"
    assert "ceo@company.com" in from_mismatches[0]["body_claim"]
    assert result["total_risk_modifier"] >= 20
    print(f"   [OK] From mismatch flagged: risk={result['total_risk_modifier']}")


# ── Test 3: Fabricated Received: chain in body ───────────

def test_received_chain_fabrication_flagged():
    body = (
        "Received: from trusted-bank.com (trusted-bank.com [10.0.0.1])\n"
        "Received: from mail.company.com (mail.company.com [10.0.0.2])\n"
        "Received: from gateway.partner.io (gateway.partner.io [10.0.0.3])\n"
        "Received: from smtp.legit.net (smtp.legit.net [10.0.0.4])\n"
        "Received: from relay.example.org (relay.example.org [10.0.0.5])\n"
        "Received: from mx6.finalhop.org (mx6.finalhop.org [10.0.0.6])\n"
        "\nOriginal message body follows.\n"
    )
    msg = _make_msg(
        {
            "From": "user@company.com",
            "Received": "from actual-mx.company.com (actual-mx.company.com [10.0.0.9])",
        },
        body=body,
    )
    result = detect_body_header_spoofing(msg)
    # Rule 5 (Received mismatch) and Rule 4 (>5 embedded lines) should both fire
    types = {m["header"] for m in result["mismatches"]}
    assert "Received" in types, f"Missing Received mismatch: {result}"
    assert "(structural)" in types, f"Missing structural flag: {result}"
    received_mismatch = next(
        m for m in result["mismatches"] if m["header"] == "Received"
    )
    assert received_mismatch["severity"] == "HIGH"
    assert result["total_risk_modifier"] >= 25
    print(f"   [OK] Fabricated Received chain flagged: risk={result['total_risk_modifier']}")


# ── Test 4: extract_embedded_headers unit test ───────────

def test_extract_embedded_headers_basic():
    body = "From: a@b.com\nReceived: x\nReceived: y\nNot a header line"
    result = extract_embedded_headers(body)
    assert result["from"] == ["a@b.com"]
    assert result["received"] == ["x", "y"]
    assert "not a header line" not in result
    print("   [OK] extract_embedded_headers parses correctly")


# ── Test 5: Risk modifier cap ────────────────────────────

def test_risk_modifier_cap():
    body = (
        "From: ceo@company.com\n"
        "Return-Path: <ceo@company.com>\n"
        "Reply-To: ceo@company.com\n"
        "Sender: ceo@company.com\n"
        "Subject: Different subject\n"
        "Date: Fri, 01 Jan 1999 00:00:00 +0000\n"
        "Received: from fake1.com\n"
        "Received: from fake2.com\n"
    )
    msg = _make_msg(
        {
            "From": "attacker@evil.ru",
            "Return-Path": "<bounce@evil.ru>",
            "Reply-To": "attacker@evil.ru",
            "Sender": "attacker@evil.ru",
            "Subject": "Real subject",
            "Date": "Sat, 02 Oct 2026 12:00:00 +0000",
        },
        body=body,
    )
    result = detect_body_header_spoofing(msg)
    assert result["total_risk_modifier"] <= 40, result
    print(f"   [OK] Risk cap enforced: {result['total_risk_modifier']} <= 40")


# ── Runner ────────────────────────────────────────────────

def main():
    print("\n[TEST] Body Header Spoofing Detection (Issue #23)\n")
    tests = [
        ("Clean email — no embedded headers", test_clean_email_no_embedded_headers),
        ("From mismatch flagged HIGH", test_from_mismatch_flagged_high),
        ("Fabricated Received: chain flagged", test_received_chain_fabrication_flagged),
        ("extract_embedded_headers basic parsing", test_extract_embedded_headers_basic),
        ("Risk modifier capped at 40", test_risk_modifier_cap),
    ]
    passed = failed = 0
    for name, fn in tests:
        print(f"[RUN ] {name}")
        try:
            fn()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {name}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERR ] {name}: {type(e).__name__}: {e}")
            failed += 1
    print(f"\n[SUMMARY] {passed} passed, {failed} failed\n")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
