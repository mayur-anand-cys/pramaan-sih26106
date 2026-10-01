"""Tests for font obfuscation detection (PR #64)."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.detection.font_forensics import (
    extract_embedded_fonts,
    analyze_font_obfuscation,
)


def test_empty_html_returns_empty():
    result = analyze_font_obfuscation("<html>Hello</html>", "Hello")
    assert result["has_obfuscation"] is False
    assert result["fonts_found"] == 0


def test_invalid_base64_ignored():
    html = 'data:font/ttf;base64,INVALIDSHORT'
    assert extract_embedded_fonts(html) == []


def test_no_font_still_returns_structure():
    result = analyze_font_obfuscation("", "")
    assert "has_obfuscation" in result
    assert "mismatches" in result


if __name__ == "__main__":
    test_empty_html_returns_empty();  print("[OK] test_empty_html_returns_empty")
    test_invalid_base64_ignored();    print("[OK] test_invalid_base64_ignored")
    test_no_font_still_returns_structure(); print("[OK] test_no_font_still_returns_structure")
    print("\n3 passed, 0 failed")
