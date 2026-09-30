"""
Typosquat & Homoglyph Detection Module for PRAMAAN.
"""
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict

from rapidfuzz.distance import Levenshtein, JaroWinkler

from .brand_list import TOP_INDIAN_BRANDS
from .homoglyph import analyze_homoglyphs
from .rdap_lookup import lookup_domain_age


RISK_POINTS = {
    "homoglyph_confusable": 15,
    "mixed_script": 20,
    "punycode": 12,
    "levenshtein_close": 18,
    "jaro_high": 15,
    "keyword_combo": 10,
    "fresh_domain": 15,
    "subdomain_spoof": 12,
}

LEVENSHTEIN_THRESHOLD = 2
JARO_THRESHOLD = 0.90


@dataclass
class DetectionResult:
    domain: str
    is_suspicious: bool = False
    total_score: int = 0
    matched_brand: Optional[str] = None
    matched_brand_domain: Optional[str] = None
    signals: List[Dict] = field(default_factory=list)
    details: Dict = field(default_factory=dict)

    def add_signal(self, signal_type: str, description: str, points: int):
        self.signals.append({
            "type": signal_type,
            "description": description,
            "points": points,
        })
        self.total_score += points
        self.is_suspicious = self.total_score > 0

    def to_dict(self) -> Dict:
        return asdict(self)


def _levenshtein(a: str, b: str) -> int:
    return Levenshtein.distance(a, b)


def _jaro_winkler(a: str, b: str) -> float:
    return JaroWinkler.similarity(a, b)


def _extract_root_domain(domain: str) -> Tuple[str, str]:
    parts = domain.lower().strip().rstrip(".").split(".")
    if len(parts) <= 2:
        return "", domain.lower()
    return ".".join(parts[:-2]), ".".join(parts[-2:])


def _is_known_brand_domain(root: str, brands: List[Dict]) -> bool:
    """Return True if root exactly matches any brand's canonical domain."""
    for brand in brands:
        if root == brand["domain"]:
            return True
    return False


def _is_legitimate_brand_domain(root: str, brand: Dict) -> bool:
    """Return True if root is naturally related to the brand (same root label, subdomain, or alias)."""
    brand_domain = brand["domain"]
    if root == brand_domain:
        return True

    brand_root_label = brand_domain.split(".")[0]
    root_label = root.split(".")[0]

    # Same root label (google.com vs google.co.in)
    if root_label == brand_root_label:
        return True

    # Subdomain relationship (pay.google.com vs google.com)
    if brand_domain.endswith("." + root) or root.endswith("." + brand_domain):
        return True

    # Root label exactly equals an alias
    for alias in brand.get("aliases", []):
        if root_label == alias:
            return True

    return False


def detect_homoglyph_threat(domain: str) -> DetectionResult:
    result = DetectionResult(domain=domain)
    analysis = analyze_homoglyphs(domain)
    result.details["homoglyph"] = analysis

    if analysis["is_mixed_script"]:
        result.add_signal(
            "mixed_script",
            f"Mixed scripts detected: {', '.join(analysis['scripts'])}",
            RISK_POINTS["mixed_script"],
        )

    if analysis["has_confusables"]:
        sample = ", ".join(f"'{c}' -> '{r}'" for c, r in analysis["suspicious_chars"][:5])
        result.add_signal(
            "homoglyph_confusable",
            f"Confusable characters: {sample}",
            RISK_POINTS["homoglyph_confusable"],
        )

    if analysis["is_punycode"]:
        result.add_signal(
            "punycode",
            f"Punycode-encoded IDN: {domain} -> {analysis['decoded']}",
            RISK_POINTS["punycode"],
        )

    return result


def detect_typosquat_threat(domain: str, brands: Optional[List[Dict]] = None) -> DetectionResult:
    result = DetectionResult(domain=domain)
    brands = brands or TOP_INDIAN_BRANDS

    subdomain, root = _extract_root_domain(domain)

    # If the domain is exactly a known brand's canonical domain, it's legitimate.
    if _is_known_brand_domain(root, brands):
        return result

    root_label = root.split(".")[0] if root else ""

    best_match = None
    best_score = 0.0

    for brand in brands:
        # Skip legitimate brand relationships (same root label, subdomain, alias)
        if _is_legitimate_brand_domain(root, brand):
            continue

        brand_domain = brand["domain"]
        lev_dist = _levenshtein(root, brand_domain)
        jw_sim = _jaro_winkler(root, brand_domain)

        for alias in brand.get("aliases", []):
            if root_label == alias:
                continue
            alias_lev = _levenshtein(root_label, alias)
            if alias_lev < lev_dist:
                lev_dist = alias_lev
            alias_jw = _jaro_winkler(root_label, alias)
            if alias_jw > jw_sim:
                jw_sim = alias_jw

        if lev_dist <= LEVENSHTEIN_THRESHOLD and root != brand_domain:
            score = (LEVENSHTEIN_THRESHOLD - lev_dist + 1) * 5
            if score > best_score:
                best_score = score
                best_match = {
                    "brand": brand["name"],
                    "brand_domain": brand_domain,
                    "signal": "levenshtein_close",
                    "detail": f"Levenshtein distance {lev_dist} from {brand_domain}",
                }

        if jw_sim >= JARO_THRESHOLD and root != brand_domain:
            score = jw_sim * 15
            if score > best_score:
                best_score = score
                best_match = {
                    "brand": brand["name"],
                    "brand_domain": brand_domain,
                    "signal": "jaro_high",
                    "detail": f"Jaro-Winkler similarity {jw_sim:.2f} with {brand_domain}",
                }

    if best_match:
        result.matched_brand = best_match["brand"]
        result.matched_brand_domain = best_match["brand_domain"]
        result.add_signal(
            best_match["signal"],
            best_match["detail"],
            RISK_POINTS.get(best_match["signal"], 10),
        )

    # Keyword combosquatting
    suspicious_keywords = {"login", "secure", "verify", "update", "kyc", "netbanking", "account", "signin"}
    domain_parts = re.split(r"[-.]", root.lower())
    matched_kw = [kw for kw in domain_parts if kw in suspicious_keywords]

    brand_in_domain = None
    for brand in brands:
        if _is_legitimate_brand_domain(root, brand):
            continue
        for alias in brand.get("aliases", []):
            if alias in root.lower():
                brand_in_domain = brand
                break
        if brand_in_domain:
            break

    if brand_in_domain and matched_kw:
        result.matched_brand = result.matched_brand or brand_in_domain["name"]
        result.matched_brand_domain = result.matched_brand_domain or brand_in_domain["domain"]
        result.add_signal(
            "keyword_combo",
            f"Brand '{brand_in_domain['name']}' + suspicious keywords: {matched_kw}",
            RISK_POINTS["keyword_combo"],
        )

    # Subdomain spoofing
    if subdomain:
        for brand in brands:
            for alias in brand.get("aliases", []):
                if alias in subdomain.lower():
                    result.add_signal(
                        "subdomain_spoof",
                        f"Brand '{brand['name']}' appears in subdomain of '{root}'",
                        RISK_POINTS["subdomain_spoof"],
                    )
                    break
            else:
                continue
            break

    return result


def detect_domain(domain: str, check_rdap: bool = True) -> DetectionResult:
    domain = domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("://", 1)[1]
    domain = domain.split("/")[0]

    result = detect_homoglyph_threat(domain)

    typo_result = detect_typosquat_threat(domain)
    result.total_score += typo_result.total_score
    result.signals.extend(typo_result.signals)
    if not result.matched_brand:
        result.matched_brand = typo_result.matched_brand
        result.matched_brand_domain = typo_result.matched_brand_domain

    if check_rdap:
        rdap_info = lookup_domain_age(domain)
        result.details["rdap"] = rdap_info
        if rdap_info and rdap_info.get("is_fresh"):
            result.add_signal(
                "fresh_domain",
                f"Domain registered {rdap_info['age_days']} days ago (< 180)",
                RISK_POINTS["fresh_domain"],
            )

    result.is_suspicious = result.total_score > 0
    return result


def detect_domains(domains: List[str], check_rdap: bool = False) -> List[DetectionResult]:
    return [detect_domain(d, check_rdap=check_rdap) for d in domains]


def get_risk_score_contribution(result: DetectionResult) -> int:
    return min(result.total_score, 10)


__all__ = [
    "DetectionResult",
    "detect_domain",
    "detect_domains",
    "detect_homoglyph_threat",
    "detect_typosquat_threat",
    "get_risk_score_contribution",
    "TOP_INDIAN_BRANDS",
    "RISK_POINTS",
]
