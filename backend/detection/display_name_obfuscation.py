"""
Detect Unicode homoglyphs and invisible characters in email display names.

Attackers use Cyrillic/Greek lookalikes in From: display names to fool the
human eye — 'Rаhul' with Cyrillic 'а' looks identical to 'Rahul' but is a
different string. They also use zero-width and bidi-control characters to
hide or reorder text.

Ref: Issue #140
"""

import unicodedata
from typing import Any, Dict, List


HOMOGLYPH_TO_LATIN: Dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "у": "y", "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "ɡ": "g",
    "α": "a", "ε": "e", "ο": "o", "ρ": "p", "ν": "v", "τ": "t",
    "υ": "u", "χ": "x", "ι": "i", "κ": "k",
}


INVISIBLE_CHARS = {
    "\u200b", "\u200c", "\u200d", "\u2060",
    "\u200e", "\u200f",
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\ufeff",
}


def detect_homoglyphs(text: str) -> List[Dict[str, Any]]:
    hits = []
    for i, ch in enumerate(text):
        if ch in HOMOGLYPH_TO_LATIN:
            hits.append({
                "position": i,
                "char": ch,
                "codepoint": "U+%04X" % ord(ch),
                "looks_like": HOMOGLYPH_TO_LATIN[ch],
            })
    return hits


def detect_invisible(text: str) -> List[Dict[str, Any]]:
    hits = []
    for i, ch in enumerate(text):
        if ch in INVISIBLE_CHARS or unicodedata.category(ch) == "Cf":
            hits.append({
                "position": i,
                "codepoint": "U+%04X" % ord(ch),
                "name": unicodedata.name(ch, "UNKNOWN"),
            })
    return hits


def detect_scripts(text: str) -> List[str]:
    scripts = set()
    for ch in text:
        if not ch.isalpha():
            continue
        try:
            script = unicodedata.name(ch).split()[0]
            scripts.add(script)
        except ValueError:
            continue
    return sorted(scripts)


def scan_display_name(name: str) -> Dict[str, Any]:
    if not name:
        return {
            "has_homoglyphs": False, "has_invisible": False,
            "has_mixed_scripts": False, "scripts": [],
            "homoglyphs": [], "invisible": [],
            "risk_level": "LOW", "risk_modifier": 0,
            "explanation": "",
        }

    homoglyphs = detect_homoglyphs(name)
    invisible = detect_invisible(name)
    scripts = detect_scripts(name)
    has_mixed = len(scripts) > 1

    risk_modifier = 0
    reasons = []
    if homoglyphs:
        risk_modifier += min(35, 15 + (len(homoglyphs) - 1) * 10)
        reasons.append(f"{len(homoglyphs)} homoglyph(s)")

    if invisible:
        risk_modifier += 20 + min(15, (len(invisible) - 1) * 8)
        reasons.append(f"{len(invisible)} invisible char(s)")

    if has_mixed:
        risk_modifier += 15
        reasons.append(f"mixed scripts ({', '.join(scripts)})")

    risk_modifier = min(40, risk_modifier)

    if risk_modifier >= 30:
        risk_level = "HIGH"
    elif risk_modifier >= 15:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "has_homoglyphs": bool(homoglyphs),
        "has_invisible": bool(invisible),
        "has_mixed_scripts": has_mixed,
        "scripts": scripts,
        "homoglyphs": homoglyphs,
        "invisible": invisible,
        "risk_level": risk_level,
        "risk_modifier": risk_modifier,
        "explanation": "Display name obfuscation: " + ", ".join(reasons) if reasons else "",
    }