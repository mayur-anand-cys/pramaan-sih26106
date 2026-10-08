"""
Tests for backend/detection/display_name_obfuscation.py

Covers:
- Clean ASCII name → no findings
- Cyrillic homoglyph → detected
- Greek homoglyph → detected
- Zero-width space → detected
- Bidi override → detected
- Mixed scripts → flagged
- Empty string → safe defaults
- Real non-Latin name (Hindi) → no false positive
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.detection.display_name_obfuscation import (
    detect_homoglyphs,
    detect_invisible,
    detect_scripts,
    scan_display_name,
)


class TestCleanNames:
    def test_ascii_name_is_clean(self):
       r = scan_display_name("Rahul Verma")
       assert r["has_homoglyphs"] is False
       assert r["has_invisible"] is False
       assert r["has_mixed_scripts"] is False
       assert r["risk_level"] == "LOW"

    def test_hindi_name_is_clean(self):
       r = scan_display_name("राहुल वर्मा")
       assert r["has_homoglyphs"] is False
       assert r["has_mixed_scripts"] is False


class TestHomoglyphs:
    def test_cyrillic_a_detected(self):
       r = scan_display_name("R\u0430hul")
       assert r["has_homoglyphs"] is True
       assert r["risk_level"] in ("MEDIUM", "HIGH")
       assert any(h["looks_like"] == "a" for h in r["homoglyphs"])

    def test_greek_o_detected(self):
        # U+03BF Greek omicron replaces the 'o' in "Rohit"
        r = scan_display_name("Rohit".replace("o", "\u03bf", 1))
        assert r["has_homoglyphs"] is True

    def test_multiple_homoglyphs_stack(self):
       r = scan_display_name("Rаhul Vеrma")
       assert len(r["homoglyphs"]) == 2
       assert r["risk_modifier"] >= 20


class TestInvisible:
    def test_zero_width_space_detected(self):
       r = scan_display_name("Rahul\u200bVerma")
       assert r["has_invisible"] is True
       assert r["risk_level"] in ("MEDIUM", "HIGH")

    def test_bidi_override_detected(self):
       r = scan_display_name("Rahul\u202eVerma")
       assert r["has_invisible"] is True


class TestMixedScripts:
    def test_latin_cyrillic_mix_flagged(self):
       r = scan_display_name("Rаhul Verma")  # one Cyrillic + Latin
       assert r["has_mixed_scripts"] is True
       assert "LATIN" in r["scripts"]
       assert "CYRILLIC" in r["scripts"]


class TestEdgeCases:
    def test_empty_string(self):
       r = scan_display_name("")
       assert r["risk_level"] == "LOW"
       assert r["risk_modifier"] == 0

    def test_none_returns_safe(self):
       # Our guard uses `if not name` so None is handled
       r = scan_display_name(None)
       assert r["risk_level"] == "LOW"