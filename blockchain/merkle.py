"""PRAMAAN Merkle Tree builder."""
import hashlib
from typing import Dict, List, Any


def sha256_hex(data: bytes) -> str:
    """Return 64-char hex SHA-256."""
    return hashlib.sha256(data).hexdigest()


def _hash_pair(left: str, right: str) -> str:
    """Hash two hex strings together."""
    combined = bytes.fromhex(left) + bytes.fromhex(right)
    return hashlib.sha256(combined).hexdigest()


def build_merkle_tree(leaves: List[str]) -> Dict[str, Any]:
    """Build a Merkle tree from a list of hex-encoded hashes."""
    if not leaves:
        return {
            "root": sha256_hex(b""),
            "leaves": [],
            "levels": [],
            "leaf_count": 0,
        }

    clean_leaves = [l.lower().strip() for l in leaves if l]
    if len(clean_leaves) == 1:
        return {
            "root": clean_leaves[0],
            "leaves": clean_leaves,
            "levels": [clean_leaves],
            "leaf_count": 1,
        }

    levels = [clean_leaves]
    current = clean_leaves

    while len(current) > 1:
        if len(current) % 2 == 1:
            current = current + [current[-1]]

        next_level = []
        for i in range(0, len(current), 2):
            next_level.append(_hash_pair(current[i], current[i + 1]))

        levels.append(next_level)
        current = next_level

    return {
        "root": current[0],
        "leaves": clean_leaves,
        "levels": levels,
        "leaf_count": len(clean_leaves),
    }


def build_evidence_merkle_root(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Build a Merkle tree from a PRAMAAN analysis dict."""
    leaves: List[str] = []

    if analysis.get("sha256"):
        leaves.append(analysis["sha256"])
    if analysis.get("headers_summary"):
        leaves.append(sha256_hex(analysis["headers_summary"].encode("utf-8")))
    if analysis.get("body_text"):
        leaves.append(sha256_hex(analysis["body_text"].encode("utf-8")))
    for url in analysis.get("urls", []):
        leaves.append(sha256_hex(str(url).encode("utf-8")))
    for ip in analysis.get("ips", []):
        ip_str = ip["ip"] if isinstance(ip, dict) else str(ip)
        leaves.append(sha256_hex(ip_str.encode("utf-8")))
    for h in analysis.get("attachment_hashes", []):
        leaves.append(h)

    tree = build_merkle_tree(leaves)
    return {
        "merkle_root": tree["root"],
        "leaf_count": tree["leaf_count"],
        "levels": len(tree["levels"]),
    }