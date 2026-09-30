"""
Tests for Thread Hijacking Detection (Issue #22).
Run: python tests/test_thread_hijack.py
"""
import sys
from pathlib import Path
from email.message import EmailMessage

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.detection.thread_hijack import detect_thread_hijacking


def _make_msg(**headers) -> EmailMessage:
    """Build an EmailMessage with the given headers."""
    msg = EmailMessage()
    for k, v in headers.items():
        msg[k.replace("_", "-")] = v
    return msg


# ── Test 1: Legitimate thread ─────────────────────────────

def test_legitimate_thread():
    """Normal reply within same domain - should NOT be flagged."""
    msg = _make_msg(
        From="Alice <alice@company.com>",
        To="Bob <bob@company.com>",
        Subject="Re: Project update",
        In_Reply_To="<msg1@company.com>",
        References="<msg0@company.com> <msg1@company.com>",
    )
    result = detect_thread_hijacking(msg)
    assert not result["is_hijacked"], f"Legit thread flagged: {result['anomalies']}"
    assert result["risk_modifier"] == 0
    print("   [OK] Legitimate thread not flagged")


# ── Test 2: Spoofed thread (foreign In-Reply-To domain) ────

def test_spoofed_thread():
    """In-Reply-To references legit domain but From is attacker - CRITICAL."""
    msg = _make_msg(
        From="Attacker <attacker@evil.ru>",
        To="Victim <victim@company.com>",
        Subject="Re: Wire transfer",
        In_Reply_To="<abc123@company.com>",
        References="<abc123@company.com>",
    )
    result = detect_thread_hijacking(msg)
    assert result["is_hijacked"], "Spoofed thread should be flagged"
    assert any(a["type"] == "DOMAIN_MISMATCH" for a in result["anomalies"])
    assert result["risk_modifier"] >= 25

    # Verify the CRITICAL severity
    critical = [a for a in result["anomalies"] if a["severity"] == "CRITICAL"]
    assert len(critical) == 1
    assert critical[0]["in_reply_to_domain"] == "company.com"
    assert critical[0]["from_domain"] == "evil.ru"
    print(f"   [OK] Spoofed thread flagged: risk={result['risk_modifier']}, types={[a['type'] for a in result['anomalies']]}")


# ── Test 3: Fabricated thread (too many references + wild domain jumps) ──

def test_fabricated_thread():
    """References chain has 12+ IDs jumping across multiple domains."""
    refs = " ".join(
        f"<msg{i}@{'company.com' if i % 2 == 0 else ('partner.io' if i % 3 == 0 else 'random.net')}>"
        for i in range(12)
    )
    msg = _make_msg(
        From="User <user@company.com>",
        To="Victim <victim@company.com>",
        Subject="Re: Re: Re: Invoice",
        In_Reply_To="<msg10@company.com>",
        References=refs,
    )
    result = detect_thread_hijacking(msg)
    assert result["is_hijacked"], "Fabricated thread should be flagged"
    types = [a["type"] for a in result["anomalies"]]
    assert "EXCESSIVE_REFERENCES" in types, f"Missing EXCESSIVE_REFERENCES: {types}"
    assert "FABRICATED_CHAIN" in types, f"Missing FABRICATED_CHAIN: {types}"
    assert result["risk_modifier"] >= 30
    print(f"   [OK] Fabricated thread flagged: risk={result['risk_modifier']}, types={types}")


# ── Test 4: Empty headers (no thread context) ─────────────

def test_no_thread_context():
    """Fresh email with no In-Reply-To / References - not hijacked."""
    msg = _make_msg(
        From="alice@company.com",
        Subject="Fresh email",
    )
    result = detect_thread_hijacking(msg)
    assert not result["is_hijacked"]
    assert result["risk_modifier"] == 0
    print("   [OK] Fresh email (no thread) not flagged")


# ── Test 5: Risk modifier cap at 40 ──────────────────────

def test_risk_modifier_cap():
    """Risk modifier should never exceed 40, even with multiple anomalies."""
    refs = " ".join(f"<msg{i}@{['a.com','b.com','c.com','d.com','e.com'][i%5]}>" for i in range(15))
    msg = _make_msg(
        From="user@attacker.ru",
        In_Reply_To="<abc@company.com>",
        References=refs,
    )
    result = detect_thread_hijacking(msg)
    assert result["risk_modifier"] <= 40, f"Risk {result['risk_modifier']} > 40"
    print(f"   [OK] Risk modifier capped: {result['risk_modifier']} <= 40")


# ── Test 6: Dict input compatibility ─────────────────────

def test_dict_input():
    """Should also accept dict-like header containers."""
    class DictMsg:
        def __init__(self, d): self._d = d
        def get(self, k, default=""): return self._d.get(k, default)

    msg = DictMsg({
        "From": "Attacker <attacker@evil.ru>",
        "In-Reply-To": "<abc123@company.com>",
        "References": "<abc123@company.com>",
    })
    result = detect_thread_hijacking(msg)
    assert result["is_hijacked"]
    print("   [OK] Dict input supported")


# ── Runner ────────────────────────────────────────────────

def main():
    print("\n[TEST] Thread Hijacking Detection (Issue #22)\n")

    tests = [
        ("Legitimate thread", test_legitimate_thread),
        ("Spoofed thread (foreign In-Reply-To)", test_spoofed_thread),
        ("Fabricated thread (too many refs + jumps)", test_fabricated_thread),
        ("Fresh email (no thread context)", test_no_thread_context),
        ("Risk modifier capped at 40", test_risk_modifier_cap),
        ("Dict input compatibility", test_dict_input),
    ]

    passed = 0
    failed = 0
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
