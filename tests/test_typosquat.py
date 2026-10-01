"""
Tests for the Typosquat & Homoglyph Detection Module.
Run: python tests/test_typosquat.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Ensure UTF-8 output on Windows (fixes Cyrillic homoglyph tests)
try:
    import sys as _sys
    _sys.stdout.reconfigure(encoding="utf-8")
    _sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

from backend.typosquat.detector import detect_domain, detect_domains


def test_typosquat_levenshtein():
    """paypa1.com vs paypal.com -> flag"""
    result = detect_domain("paypa1.com", check_rdap=False)
    assert result.is_suspicious, "paypa1.com should be flagged"
    assert result.total_score > 0
    print(f"   [OK] paypa1.com -> score {result.total_score}")


def test_homoglyph_cyrillic():
    """Cyrillic a + pple.com vs apple.com -> flag"""
    domain = "\u0430pple.com"  # U+0430 Cyrillic a
    result = detect_domain(domain, check_rdap=False)
    assert result.is_suspicious, f"{domain} should be flagged"
    assert any(s["type"] == "mixed_script" for s in result.signals), "Should detect mixed script"
    print(f"   [OK] {domain} -> score {result.total_score} (mixed script)")


def test_keyword_combo():
    """sbi-secure-login.com vs sbi.co.in -> flag"""
    result = detect_domain("sbi-secure-login.com", check_rdap=False)
    assert result.is_suspicious, "sbi-secure-login.com should be flagged"
    print(f"   [OK] sbi-secure-login.com -> score {result.total_score} signals={[s['type'] for s in result.signals]}")


def test_legitimate():
    """google.com -> low risk"""
    result = detect_domain("google.com", check_rdap=False)
    print(f"   [INFO] google.com -> score {result.total_score} signals={[s['type'] for s in result.signals]}")
    assert result.total_score < 30, "google.com should be low-risk"


def test_punycode():
    """xn--yutube-wqf.com -> flag"""
    result = detect_domain("xn--yutube-wqf.com", check_rdap=False)
    assert result.is_suspicious, "Punycode domain should be flagged"
    print(f"   [OK] xn--yutube-wqf.com -> score {result.total_score} (punycode)")


def test_hdfc_lookalike():
    """hdfcbank-kyc.com -> flag"""
    result = detect_domain("hdfcbank-kyc.com", check_rdap=False)
    assert result.is_suspicious, "hdfcbank-kyc.com should be flagged"
    print(f"   [OK] hdfcbank-kyc.com -> score {result.total_score} signals={[s['type'] for s in result.signals]}")


def test_subdomain_spoof():
    """sbi.attacker.com -> flag"""
    result = detect_domain("sbi.attacker.com", check_rdap=False)
    assert result.is_suspicious, "sbi.attacker.com should be flagged"
    print(f"   [OK] sbi.attacker.com -> score {result.total_score} signals={[s['type'] for s in result.signals]}")


def test_batch():
    """Batch accuracy check."""
    test_cases = [
        ("paypa1.com", True),
        ("\u0430pple.com", True),
        ("sbi-secure-login.com", True),
        ("google.com", False),
        ("hdfcbank-kyc.com", True),
        ("xn--yutube-wqf.com", True),
        ("icicibank.com", False),
        ("flipkart-offer.com", True),
        ("amazon.in", False),
        ("paytm-kyc-update.com", True),
    ]

    results = detect_domains([d for d, _ in test_cases], check_rdap=False)

    correct = 0
    for (domain, expected), result in zip(test_cases, results):
        predicted = result.is_suspicious
        match = predicted == expected
        correct += match
        status = "OK  " if match else "MISS"
        print(f"   [{status}] {domain:35s} expected={expected} got={predicted} score={result.total_score}")

    accuracy = correct / len(test_cases)
    print(f"\n   Accuracy: {correct}/{len(test_cases)} = {accuracy:.0%}")
    assert accuracy >= 0.90, f"Accuracy {accuracy:.0%} < 90%"


def main():
    print("\n[TEST] Typosquat & Homoglyph Detection Module\n")

    tests = [
        ("Levenshtein typosquat", test_typosquat_levenshtein),
        ("Cyrillic homoglyph", test_homoglyph_cyrillic),
        ("Keyword combosquatting", test_keyword_combo),
        ("Legitimate domain", test_legitimate),
        ("Punycode IDN", test_punycode),
        ("HDFC lookalike", test_hdfc_lookalike),
        ("Subdomain spoofing", test_subdomain_spoof),
        ("Batch accuracy", test_batch),
    ]

    passed = 0
    failed = 0
    for name, fn in tests:
        try:
            print(f"[RUN ] {name}")
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
