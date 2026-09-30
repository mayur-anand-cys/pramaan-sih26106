"""
Unicode homoglyph, mixed-script, and Punycode detection for PRAMAAN.
"""
import unicodedata
from typing import Dict, Set

CONFUSABLES = {
    # Cyrillic -> Latin
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0445": "x", "\u0443": "y", "\u0456": "i",
    "\u0458": "j", "\u04bb": "h", "\u0501": "d", "\u051b": "q",
    "\u051d": "w", "\u0432": "b", "\u043d": "h", "\u043a": "k",
    "\u043c": "m", "\u0442": "t", "\u0437": "3", "\u0455": "s",
    "\u050d": "b",

    # Greek -> Latin
    "\u03b1": "a", "\u03b2": "b", "\u03b5": "e", "\u03b7": "n",
    "\u03b9": "i", "\u03ba": "k", "\u03bc": "u", "\u03bd": "v",
    "\u03bf": "o", "\u03c1": "p", "\u03c3": "o", "\u03c4": "t",
    "\u03c5": "u", "\u03c7": "x", "\u03c9": "w",

    # Fullwidth Latin
    "\uff41": "a", "\uff42": "b", "\uff43": "c", "\uff44": "d", "\uff45": "e",
    "\uff46": "f", "\uff47": "g", "\uff48": "h", "\uff49": "i", "\uff4a": "j",
    "\uff4b": "k", "\uff4c": "l", "\uff4d": "m", "\uff4e": "n", "\uff4f": "o",
    "\uff50": "p", "\uff51": "q", "\uff52": "r", "\uff53": "s", "\uff54": "t",
    "\uff55": "u", "\uff56": "v", "\uff57": "w", "\uff58": "x", "\uff59": "y",
    "\uff5a": "z",
}

SCRIPT_RANGES = {
    "latin": [(0x0041, 0x005A), (0x0061, 0x007A), (0x00C0, 0x024F), (0x1E00, 0x1EFF)],
    "cyrillic": [(0x0400, 0x04FF), (0x0500, 0x052F), (0x2DE0, 0x2DFF), (0xA640, 0xA69F)],
    "greek": [(0x0370, 0x03FF), (0x1F00, 0x1FFF)],
}


def normalize_nfkc(text: str) -> str:
    return unicodedata.normalize("NFKC", text)


def get_char_script(char: str) -> str:
    cp = ord(char)
    for script, ranges in SCRIPT_RANGES.items():
        for start, end in ranges:
            if start <= cp <= end:
                return script
    return "other"


def get_scripts_in_text(text: str) -> Set[str]:
    scripts = set()
    for char in text:
        if char.isalpha():
            scripts.add(get_char_script(char))
    scripts.discard("other")
    return scripts


def is_mixed_script(text: str) -> bool:
    scripts = get_scripts_in_text(text)
    dangerous_mixes = [
        {"latin", "cyrillic"},
        {"latin", "greek"},
        {"latin", "cyrillic", "greek"},
    ]
    return any(mix.issubset(scripts) for mix in dangerous_mixes)


def normalize_homoglyphs(text: str) -> str:
    text = normalize_nfkc(text)
    return "".join(CONFUSABLES.get(c.lower(), c) for c in text)


def is_punycode(domain: str) -> bool:
    return domain.lower().startswith("xn--") or ".xn--" in domain.lower()


def decode_punycode(domain: str) -> str:
    try:
        if domain.startswith("xn--"):
            return domain.encode("ascii").decode("idna")
        return domain.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return domain


def analyze_homoglyphs(domain: str) -> Dict:
    domain_lower = domain.lower()
    normalized = normalize_nfkc(domain_lower)
    homoglyph_normalized = normalize_homoglyphs(domain_lower)
    scripts = get_scripts_in_text(domain_lower)

    suspicious = []
    for char in domain_lower:
        if char in CONFUSABLES:
            suspicious.append((char, CONFUSABLES[char]))

    is_pc = is_punycode(domain)
    decoded = decode_punycode(domain) if is_pc else domain

    return {
        "original": domain,
        "normalized": normalized,
        "homoglyph_normalized": homoglyph_normalized,
        "scripts": list(scripts),
        "is_mixed_script": is_mixed_script(domain),
        "is_punycode": is_pc,
        "decoded": decoded,
        "has_confusables": len(suspicious) > 0,
        "suspicious_chars": suspicious,
        "script_count": len(scripts),
    }
