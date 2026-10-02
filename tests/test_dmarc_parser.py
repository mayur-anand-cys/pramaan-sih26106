"""
Tests for DMARC aggregate report parser (Issue #49).
Run: python tests/test_dmarc_parser.py
"""
import gzip
import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.intel.dmarc_parser import parse_dmarc_report, summarize_dmarc


# ── Fixture builders ────────────────────────────────────────

SAMPLE_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">
  <report_metadata>
    <org_name>Example Receiver</org_name>
    <email>dmarc@example.com</email>
    <report_id>abc-123</report_id>
    <date_range><begin>1700000000</begin><end>1700086400</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <p>reject</p>
  </policy_published>
  <record>
    <row>
      <source_ip>203.0.113.5</source_ip>
      <count>7</count>
      <policy_evaluated>
        <disposition>reject</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
      <envelope_from>bounce@example.com</envelope_from>
    </identifiers>
  </record>
  <record>
    <row>
      <source_ip>198.51.100.9</source_ip>
      <count>3</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
    </identifiers>
  </record>
  <record>
    <row>
      <source_ip>192.0.2.10</source_ip>
      <count>2</count>
      <policy_evaluated>
        <disposition>quarantine</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
    </identifiers>
  </record>
</feedback>
"""


def _zip_bytes(xml: bytes, name: str = "report.xml") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(name, xml)
    return buf.getvalue()


# ── Test 1: Parse from ZIP ──────────────────────────────────

def test_parse_from_zip():
    records = parse_dmarc_report(_zip_bytes(SAMPLE_XML))
    assert len(records) == 3, records
    assert records[0]["source_ip"] == "203.0.113.5"
    assert records[0]["count"] == 7
    assert records[0]["spf_result"] == "fail"
    assert records[0]["dkim_result"] == "fail"
    assert records[0]["both_fail"] is True
    assert records[0]["disposition"] == "reject"
    assert records[0]["header_from"] == "example.com"
    print("   [OK] Parsed 3 records from ZIP")


# ── Test 2: Parse raw XML (no ZIP) ─────────────────────────

def test_parse_raw_xml():
    records = parse_dmarc_report(SAMPLE_XML)
    assert len(records) == 3
    assert records[0]["both_fail"] is True
    print("   [OK] Parsed raw XML (no container)")


# ── Test 3: Parse gzipped XML ──────────────────────────────

def test_parse_gzipped_xml():
    gz = gzip.compress(SAMPLE_XML)
    records = parse_dmarc_report(gz)
    assert len(records) == 3
    print("   [OK] Parsed gzipped XML")


# ── Test 4: both_fail detection ────────────────────────────

def test_both_fail_detection():
    records = parse_dmarc_report(_zip_bytes(SAMPLE_XML))
    both_fail_ips = {r["source_ip"] for r in records if r["both_fail"]}
    assert both_fail_ips == {"203.0.113.5", "192.0.2.10"}, both_fail_ips
    # The pass record is not flagged
    assert not any(r["source_ip"] == "198.51.100.9" and r["both_fail"] for r in records)
    print(f"   [OK] both_fail set = {both_fail_ips}")


# ── Test 5: summarize_dmarc ────────────────────────────────

def test_summarize():
    records = parse_dmarc_report(_zip_bytes(SAMPLE_XML))
    summary = summarize_dmarc(records)
    assert summary["record_count"] == 3
    assert summary["total_messages"] == 12          # 7 + 3 + 2
    assert summary["both_fail_count"] == 2
    assert summary["both_fail_messages"] == 9       # 7 + 2
    assert summary["spf_fail_count"] == 2
    assert summary["dkim_fail_count"] == 2
    print(f"   [OK] Summary: {summary}")


# ── Test 6: Empty / garbage input ──────────────────────────

def test_empty_input():
    assert parse_dmarc_report(b"") == []
    assert parse_dmarc_report(None) == []           # type: ignore
    assert parse_dmarc_report(b"not xml at all") == []
    print("   [OK] Empty/garbage input returns []")


# ── Test 7: ZIP with multiple XML files ────────────────────

def test_zip_multiple_xml():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.xml", SAMPLE_XML)
        zf.writestr("b.xml", SAMPLE_XML)
    records = parse_dmarc_report(buf.getvalue())
    assert len(records) == 6, f"Expected 6 records, got {len(records)}"
    print("   [OK] ZIP with 2 XML files → 6 records")


# ── Runner ─────────────────────────────────────────────────

def main():
    print("\n[TEST] DMARC Parser (Issue #49)\n")
    tests = [
        ("Parse from ZIP", test_parse_from_zip),
        ("Parse raw XML", test_parse_raw_xml),
        ("Parse gzipped XML", test_parse_gzipped_xml),
        ("both_fail detection", test_both_fail_detection),
        ("summarize_dmarc", test_summarize),
        ("Empty / garbage input", test_empty_input),
        ("ZIP with multiple XML", test_zip_multiple_xml),
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
