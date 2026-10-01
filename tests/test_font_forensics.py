"""Tests for font obfuscation detection (PR #64)."""
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
