# backend/detection/font_forensics.py
"""Detect glyph substitution attacks via embedded base64 web fonts.

Phishing kits embed a custom font with a manipulated CMAP table - the raw
HTML contains gibberish like "QbzbC" but the browser renders "PayPal" because
each codepoint maps to an attacker-controlled glyph. This bypasses regex/NLP.
"""

import base64
import re
from io import BytesIO

from fontTools.ttLib import TTFont


_FONT_DATA_URI_RE = re.compile(
    r"data:(?:font/(?:ttf|otf|woff2?|sfnt)|application/font-(?:woff2?|sfnt|ttf))"
    r";base64,([A-Za-z0-9+/=\s]{100,})",
    re.IGNORECASE,
)


def extract_embedded_fonts(html: str) -> list:
    """Return list of base64-decoded font byte blobs found in the HTML."""
    blobs = []
    for match in _FONT_DATA_URI_RE.finditer(html or ""):
        raw = match.group(1)
        raw = re.sub(r"\s+", "", raw)
        try:
            decoded = base64.b64decode(raw, validate=False)
            if decoded[:4] in (
                b"\x00\x01\x00\x00",
                b"OTTO",
                b"wOFF",
                b"wOF2",
                b"true",
                b"ttcf",
            ):
                blobs.append(decoded)
        except Exception:
            continue
    return blobs


def parse_font_cmap(font_bytes: bytes) -> dict:
    """Return {codepoint: glyph_name} for the best available cmap subtable."""
    try:
        font = TTFont(BytesIO(font_bytes), fontNumber=0, lazy=True)
    except Exception:
        return {}

    cmap = {}
    try:
        best = font.getBestCmap() or {}
        cmap = {int(cp): name for cp, name in best.items()}
    finally:
        font.close()
    return cmap


def detect_glyph_mismatch(font_bytes: bytes) -> dict:
    """Detect glyphs whose name doesn't match the codepoint they map to."""
    cmap = parse_font_cmap(font_bytes)
    if not cmap:
        return {"mismatches": [], "analyzable": False}

    mismatches = []
    for codepoint, glyph_name in cmap.items():
        if not (0x20 <= codepoint <= 0x7E):
            continue

        expected = chr(codepoint)
        expected_lower = expected.lower()
        glyph_clean = glyph_name.split(".")[0]

        # Only flag real glyph swaps: when the glyph name is a single letter
        # (like "B") that does NOT match the codepoint's expected letter (like "P").
        # Symbol glyphs like "exclam", "quotedbl", "uni0041", "cid123" are normal.

        is_single_letter_name = (
            len(glyph_clean) == 1 and glyph_clean.isalpha()
        )

        if is_single_letter_name and glyph_clean.lower() != expected_lower:
            mismatches.append({
                "codepoint": codepoint,
                "expected_char": expected,
                "glyph_name": glyph_name,
                "codepoint_hex": "U+%04X" % codepoint,
            })

    printable_count = len([c for c in cmap if 0x20 <= c <= 0x7E])
    # Guard against subsetting false positives: real attacks remap many glyphs
    if len(mismatches) < 3:
        mismatches = []
    return {
        "mismatches": mismatches,
        "analyzable": True,
        "total_glyphs_checked": printable_count,
    }


def reconstruct_visual_text(font_bytes: bytes, raw_text: str) -> str:
    """Approximate what the browser renders by mapping chars through the font."""
    cmap = parse_font_cmap(font_bytes)
    if not cmap:
        return raw_text

    out = []
    for ch in raw_text:
        cp = ord(ch)
        glyph_name = cmap.get(cp)
        if not glyph_name:
            out.append(ch)
            continue
        clean = glyph_name.split(".")[0]
        if len(clean) == 1 and clean.isalpha():
            out.append(clean)
        elif clean.startswith("uni") and len(clean) == 7:
            try:
                out.append(chr(int(clean[3:], 16)))
            except Exception:
                out.append(ch)
        else:
            out.append(ch)
    return "".join(out)


def analyze_font_obfuscation(html: str, raw_text: str = "") -> dict:
    """Top-level entry: analyze all embedded fonts in the HTML for glyph attacks."""
    fonts = extract_embedded_fonts(html)

    all_mismatches = []
    visually_intended = raw_text

    for idx, blob in enumerate(fonts):
        info = detect_glyph_mismatch(blob)
        if info.get("analyzable") and info.get("mismatches"):
            for m in info["mismatches"]:
                m["font_index"] = idx
            all_mismatches.extend(info["mismatches"])

        if raw_text:
            candidate = reconstruct_visual_text(blob, raw_text)
            if len(candidate) > 0 and candidate != raw_text:
                visually_intended = candidate

    risk_modifier = 0
    if all_mismatches:
        risk_modifier = min(40, len(all_mismatches) * 15)

    return {
        "has_obfuscation": len(all_mismatches) > 0,
        "fonts_found": len(fonts),
        "mismatch_count": len(all_mismatches),
        "mismatches": all_mismatches[:20],
        "visually_intended_text": visually_intended,
        "risk_modifier": risk_modifier,
    }