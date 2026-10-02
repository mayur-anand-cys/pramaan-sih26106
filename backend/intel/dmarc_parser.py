"""
Parser for DMARC aggregate reports (RFC 7489 §7.2).

Accepts a raw XML document, a gzipped XML, or a ZIP containing one or
more XML reports. Extracts per-source-IP send records and flags those
where BOTH SPF and DKIM failed — a strong BEC / spoofing signal.

Stdlib only: zipfile, gzip, xml.etree.ElementTree.
"""
import gzip
import io
import zipfile
from typing import Dict, Any, List, Optional
from xml.etree import ElementTree as ET


# ── Constants ────────────────────────────────────────────────

ZIP_MAGIC = b"PK\x03\x04"
GZIP_MAGIC = b"\x1f\x8b"

# XML namespaces used by DMARC reports across schema versions
DMARC_NAMESPACES = [
    "urn:ietf:params:xml:ns:dmarc-2.0",
    "urn:ietf:params:xml:ns:dmarc-1.0",
]


# ── Helpers ──────────────────────────────────────────────────

def _strip_ns(tag: str) -> str:
    """Strip '{namespace}tag' to 'tag'."""
    return tag.rsplit("}", 1)[1] if "}" in tag else tag


def _findtext(node: ET.Element, path: str, default: str = "") -> str:
    """Find text along a path, ignoring namespaces. Returns '' if not found."""
    parts = path.split("/")
    current = node
    for part in parts:
        found = None
        for child in current:
            if _strip_ns(child.tag) == part:
                found = child
                break
        if found is None:
            return default
        current = found
    return (current.text or "").strip()


def _decompress(raw: bytes) -> List[bytes]:
    """Unwrap a ZIP or GZIP container and return a list of inner XML byte strings."""
    if not raw:
        return []

    # Case 1: ZIP — could contain multiple XML reports
    if raw[:4] == ZIP_MAGIC:
        out: List[bytes] = []
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            xml_names = [n for n in zf.namelist() if n.lower().endswith(".xml")]
            if not xml_names:
                # Some vendors put one unnamed file — take the first non-dir entry
                xml_names = [n for n in zf.namelist() if not n.endswith("/")][:1]
            for name in xml_names:
                out.append(zf.read(name))
        return out

    # Case 2: GZIP
    if raw[:2] == GZIP_MAGIC:
        try:
            return [gzip.decompress(raw)]
        except Exception:
            return []

    # Case 3: plain XML (or something else — let the XML parser decide)
    return [raw]


def _parse_single_xml(xml_bytes: bytes) -> List[Dict[str, Any]]:
    """Parse one DMARC XML document, return per-record dicts."""
    records: List[Dict[str, Any]] = []

    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return records

    # <feedback><record>... is standard; some reports use different roots
    for record in root.iter():
        if _strip_ns(record.tag) != "record":
            continue

        source_ip = _findtext(record, "row/source_ip")
        count_str = _findtext(record, "row/count", "0")
        try:
            count = int(count_str)
        except ValueError:
            count = 0

        spf_result = _findtext(record, "row/policy_evaluated/spf", "unknown").lower()
        dkim_result = _findtext(record, "row/policy_evaluated/dkim", "unknown").lower()
        disposition = _findtext(record, "row/policy_evaluated/disposition", "none").lower()
        header_from = _findtext(record, "identifiers/header_from", "")
        envelope_from = _findtext(record, "identifiers/envelope_from", "")

        both_fail = (spf_result == "fail" and dkim_result == "fail")

        records.append({
            "source_ip": source_ip,
            "count": count,
            "spf_result": spf_result,
            "dkim_result": dkim_result,
            "disposition": disposition,
            "header_from": header_from,
            "envelope_from": envelope_from,
            "both_fail": both_fail,
        })

    return records


# ── Public API ───────────────────────────────────────────────

def parse_dmarc_report(zip_bytes: bytes) -> List[Dict[str, Any]]:
    """
    Parse a DMARC aggregate report from a ZIP, GZIP, or raw XML byte string.

    Returns a list of records, one per <record> element:
        {
            "source_ip": "203.0.113.5",
            "count": 3,
            "spf_result": "fail",
            "dkim_result": "fail",
            "disposition": "reject",
            "header_from": "example.com",
            "envelope_from": "bounce.example.com",
            "both_fail": True,
        }
    """
    if not zip_bytes:
        return []

    xml_parts = _decompress(zip_bytes)
    if not xml_parts:
        return []

    out: List[Dict[str, Any]] = []
    for part in xml_parts:
        if part and part.strip():
            out.extend(_parse_single_xml(part))
    return out


def summarize_dmarc(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate stats for a DMARC report — useful for UI headers."""
    total_messages = sum(r.get("count", 0) for r in records)
    both_fail = [r for r in records if r.get("both_fail")]
    spf_fail = [r for r in records if r.get("spf_result") == "fail"]
    dkim_fail = [r for r in records if r.get("dkim_result") == "fail"]

    return {
        "record_count": len(records),
        "total_messages": total_messages,
        "both_fail_count": len(both_fail),
        "both_fail_messages": sum(r.get("count", 0) for r in both_fail),
        "spf_fail_count": len(spf_fail),
        "dkim_fail_count": len(dkim_fail),
    }


__all__ = ["parse_dmarc_report", "summarize_dmarc"]
