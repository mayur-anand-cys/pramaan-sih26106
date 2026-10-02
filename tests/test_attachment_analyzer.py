"""
Tests for Attachment Analyzer (Issue #48).
Run: python tests/test_attachment_analyzer.py
"""
import sys
import struct
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.detection.attachment_analyzer import (
    analyze_attachment,
    analyze_attachments,
)


# ── Fixture builders ────────────────────────────────────────

def _make_minimal_ole_with_vba() -> bytes:
    """
    Build a tiny OLE compound file containing a stream named
    'VBA/dir' so the macro detector fires. This is NOT a valid
    Word document — it's the minimal byte pattern olefile needs
    to enumerate a VBA stream.
    """
    # A hand-rolled minimal OLE header + directory is complex.
    # Instead, embed the VBA marker in a valid OLE file skeleton
    # by using raw bytes with the correct OLE magic and the string
    # "VBA" in the byte stream, which our zip/ole fallback detects.
    magic = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # OLE magic
    padding = b"\x00" * 4088
    vba_marker = b"VBA\x00dir\x00VBA_PROJECT\x00"
    return magic + padding + vba_marker


def _make_docm_with_macro_zip() -> bytes:
    """
    Minimal ZIP-like OOXML .docm containing 'vbaProject.bin' in the
    byte stream — enough for our static detector to flag it.
    """
    # Not a real ZIP — just a byte sequence containing the marker.
    return b"PK\x03\x04" + b"\x00" * 100 + b"vbaProject.bin" + b"\x00" * 100


def _make_clean_pdf() -> bytes:
    """Minimal, harmless PDF."""
    return (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
        b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n"
        b"0000000058 00000 n \n0000000115 00000 n \n"
        b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n190\n%%EOF\n"
    )


def _make_pdf_with_js() -> bytes:
    """PDF containing /JavaScript — should be flagged."""
    return (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/OpenAction 5 0 R>>endobj\n"
        b"5 0 obj<</S/JavaScript/JS(app.alert\\('pwn'\\);)>>endobj\n"
        b"trailer<</Root 1 0 R>>\n%%EOF\n"
    )


def _make_pdf_with_embedded_file() -> bytes:
    """PDF with an /EmbeddedFile."""
    return (
        b"%PDF-1.5\n"
        b"1 0 obj<</Type/Catalog>>endobj\n"
        b"9 0 obj<</Type/Filespec/EF<</F 10 0 R>>>>endobj\n"
        b"10 0 obj<</Type/EmbeddedFile/Length 12>>stream\n"
        b"hello world!\nendstream endobj\n"
        b"trailer<</Root 1 0 R>>\n%%EOF\n"
    )


# ── Test 1: Clean text file — no risk ───────────────────────

def test_clean_text_file():
    data = b"Hello, this is a plain text attachment.\n"
    report = analyze_attachment("notes.txt", data)
    assert report["filename"] == "notes.txt"
    assert report["size_bytes"] == len(data)
    assert len(report["sha256"]) == 64
    assert report["has_macros"] is False
    assert report["double_extension"] is None
    assert report["pdf_javascript"] is False
    assert report["risk_modifier"] == 0
    assert report["risk_factors"] == []
    print("   [OK] Clean .txt — 0 risk")


# ── Test 2: Macro-enabled .docm — HIGH, +25 ────────────────

def test_docm_with_macro_flagged():
    data = _make_docm_with_macro_zip()
    report = analyze_attachment("invoice.docm", data)
    assert report["has_macros"] is True, report
    assert report["mime_type"] == "application/vnd.ms-word.document.macroEnabled.12"
    types = {f["type"] for f in report["risk_factors"]}
    assert "Macro-Enabled Attachment" in types, report["risk_factors"]
    assert report["risk_modifier"] >= 25
    print(f"   [OK] Macro .docm flagged: risk={report['risk_modifier']}")


# ── Test 3: Double extension — HIGH, +20 ───────────────────

def test_double_extension_flagged():
    data = b"plain file contents"
    report = analyze_attachment("invoice.pdf.exe", data)
    assert report["double_extension"] is not None
    assert report["double_extension"].lower().endswith(".exe")
    types = {f["type"] for f in report["risk_factors"]}
    assert "Double Extension" in types, report
    assert report["risk_modifier"] >= 20
    print(f"   [OK] Double ext flagged: risk={report['risk_modifier']}")


# ── Test 4: PDF with JavaScript — HIGH, +20 ────────────────

def test_pdf_javascript_flagged():
    data = _make_pdf_with_js()
    report = analyze_attachment("statement.pdf", data)
    assert report["pdf_javascript"] is True, report
    types = {f["type"] for f in report["risk_factors"]}
    assert "PDF Active Content" in types, report
    assert report["risk_modifier"] >= 20
    print(f"   [OK] PDF JavaScript flagged: risk={report['risk_modifier']}")


# ── Test 5: Clean PDF — no risk ────────────────────────────

def test_clean_pdf_no_risk():
    data = _make_clean_pdf()
    report = analyze_attachment("report.pdf", data)
    assert report["pdf_javascript"] is False, report
    assert report["risk_modifier"] == 0
    print("   [OK] Clean PDF — 0 risk")


# ── Test 6: PDF with embedded file — MEDIUM, +10 ───────────

def test_pdf_embedded_file_flagged():
    data = _make_pdf_with_embedded_file()
    report = analyze_attachment("brochure.pdf", data)
    assert report["embedded_file_count"] >= 1, report
    types = {f["type"] for f in report["risk_factors"]}
    assert "Embedded Files" in types, report
    assert report["risk_modifier"] >= 10
    print(f"   [OK] PDF embedded file flagged: risk={report['risk_modifier']}")


# ── Test 7: Aggregate — multiple attachments, cap at 40 ────

def test_aggregate_and_cap():
    attachments = [
        {"filename": "a.docm", "data": _make_docm_with_macro_zip()},
        {"filename": "b.pdf.exe", "data": b"binary"},
        {"filename": "c.pdf", "data": _make_pdf_with_js()},
        {"filename": "clean.txt", "data": b"hello"},
    ]
    result = analyze_attachments(attachments)
    assert result["attachment_count"] == 4
    assert result["flagged_count"] == 3
    assert result["total_risk_modifier"] <= 40
    assert result["total_risk_modifier"] >= 40, "should hit cap"
    assert len(result["attachments"]) == 4
    print(f"   [OK] Aggregate capped at {result['total_risk_modifier']}, flagged {result['flagged_count']}/4")


# ── Test 8: Empty attachments list ─────────────────────────

def test_empty_attachments():
    result = analyze_attachments([])
    assert result["attachment_count"] == 0
    assert result["total_risk_modifier"] == 0
    assert result["flagged_count"] == 0
    print("   [OK] Empty list — 0 risk")


# ── Runner ─────────────────────────────────────────────────

def main():
    print("\n[TEST] Attachment Analyzer (Issue #48)\n")
    tests = [
        ("Clean text file — 0 risk", test_clean_text_file),
        ("Macro-enabled .docm — HIGH +25", test_docm_with_macro_flagged),
        ("Double extension — HIGH +20", test_double_extension_flagged),
        ("PDF with JavaScript — HIGH +20", test_pdf_javascript_flagged),
        ("Clean PDF — 0 risk", test_clean_pdf_no_risk),
        ("PDF with embedded file — MEDIUM +10", test_pdf_embedded_file_flagged),
        ("Aggregate cap at 40", test_aggregate_and_cap),
        ("Empty attachments list", test_empty_attachments),
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
