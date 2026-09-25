import hashlib
import datetime
import email
from email import policy
import re
import sqlite3
import json
import os
from typing import Dict, List, Tuple, Any

DB_FILE = os.path.join(os.path.dirname(__file__), "zkfv_ledger.db")

def init_ledger_db(db_path: str = DB_FILE):
    """Initialize SQLite database table for ZKFV forensic evidence audit logging."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence_ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            eml_sha256 TEXT NOT NULL,
            merkle_root TEXT NOT NULL,
            leaf_count INTEGER NOT NULL,
            status TEXT NOT NULL,
            raw_proof_json TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def hash_string(text: str) -> str:
    """Compute SHA-256 hash of string."""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def hash_bytes(data: bytes) -> str:
    """Compute SHA-256 hash of bytes."""
    return hashlib.sha256(data).hexdigest()

def build_merkle_root(leaf_hashes: List[str]) -> str:
    """
    Build a Merkle tree from a list of leaf hash strings.
    Returns the Merkle root hash string.
    """
    if not leaf_hashes:
        return hash_string("EMPTY_TREE")
    
    current_level = list(leaf_hashes)

    while len(current_level) > 1:
        next_level = []
        if len(current_level) % 2 != 0:
            current_level.append(current_level[-1])
            
        for i in range(0, len(current_level), 2):
            combined = current_level[i] + current_level[i + 1]
            parent_hash = hash_string(combined)
            next_level.append(parent_hash)
            
        current_level = next_level

    return current_level[0]

def extract_artifacts_for_zkfv(msg: email.message.EmailMessage, eml_bytes: bytes) -> Dict[str, Any]:
    """Extract standard artifacts from email message for cryptographic hashing."""
    headers = [
        f"Subject:{msg.get('Subject', '')}",
        f"From:{msg.get('From', '')}",
        f"To:{msg.get('To', '')}",
        f"Date:{msg.get('Date', '')}",
        f"Return-Path:{msg.get('Return-Path', '')}",
        f"Reply-To:{msg.get('Reply-To', '')}"
    ]
    headers_str = "\n".join(headers)

    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_text += payload.decode('utf-8', errors='replace')
                except Exception:
                    pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                body_text = payload.decode('utf-8', errors='replace')
        except Exception:
            body_text = str(msg.get_payload() or "")

    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    found_urls = sorted(list(set(re.findall(url_pattern, body_text + " " + headers_str, re.IGNORECASE))))

    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    found_ips = sorted(list(set(re.findall(ip_pattern, body_text + " " + headers_str))))

    return {
        "headers_str": headers_str,
        "body_text": body_text,
        "urls": found_urls,
        "ips": found_ips
    }

def generate_evidence_proof(eml_bytes: bytes) -> Dict[str, Any]:
    """
    Generate Zero-Knowledge Forensic Verification (ZKFV) evidence proof dictionary.
    Includes artifact hashes, Merkle root calculation, and logs entry in SQLite ledger.
    """
    init_ledger_db()
    msg = email.message_from_bytes(eml_bytes, policy=policy.default)
    artifacts = extract_artifacts_for_zkfv(msg, eml_bytes)

    headers_hash = hash_string(artifacts["headers_str"])
    body_hash = hash_string(artifacts["body_text"])
    url_hashes = [hash_string(u) for u in artifacts["urls"]]
    ip_hashes = [hash_string(ip) for ip in artifacts["ips"]]
    eml_sha256 = hash_bytes(eml_bytes)

    leaves = [eml_sha256, headers_hash, body_hash] + url_hashes + ip_hashes
    merkle_root = build_merkle_root(leaves)

    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    proof = {
        "timestamp": timestamp,
        "eml_sha256": eml_sha256,
        "artifact_hashes": {
            "headers_hash": headers_hash,
            "body_hash": body_hash,
            "url_hashes": url_hashes,
            "ip_hashes": ip_hashes
        },
        "merkle_root": merkle_root,
        "leaf_count": len(leaves)
    }

    # Store in local SQLite audit log
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO evidence_ledger (timestamp, eml_sha256, merkle_root, leaf_count, status, raw_proof_json) VALUES (?, ?, ?, ?, ?, ?)",
            (timestamp, eml_sha256, merkle_root, len(leaves), "REGISTERED", json.dumps(proof))
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

    return proof

def verify_evidence_proof(eml_bytes: bytes, stored_proof: Dict[str, Any]) -> Tuple[bool, str, str]:
    """
    Recompute Merkle root from EML bytes and compare with stored proof.
    Returns (is_valid: bool, current_root: str, expected_root: str).
    """
    current_proof = generate_evidence_proof(eml_bytes)
    current_root = current_proof["merkle_root"]
    expected_root = stored_proof.get("merkle_root", "")
    
    is_valid = (current_root == expected_root) and (current_proof["eml_sha256"] == stored_proof.get("eml_sha256"))
    return is_valid, current_root, expected_root

def get_recent_audit_logs(limit: int = 10) -> List[Dict[str, Any]]:
    """Retrieve recent ZKFV evidence registration records from SQLite ledger."""
    init_ledger_db()
    logs = []
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT id, timestamp, eml_sha256, merkle_root, leaf_count, status FROM evidence_ledger ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        for r in rows:
            logs.append({
                "id": r[0],
                "timestamp": r[1],
                "eml_sha256": r[2],
                "merkle_root": r[3],
                "leaf_count": r[4],
                "status": r[5]
            })
        conn.close()
    except Exception:
        pass
    return logs
