"""End-to-end blockchain test for PRAMAAN."""
import os
from dotenv import load_dotenv

# Load .env file
load_dotenv()

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from blockchain.merkle import build_evidence_merkle_root
from blockchain.anchor import anchor_evidence, verify_evidence, blockchain_status

def main():
    print("\n" + "="*60)
    print("PRAMAAN Blockchain Anchor Test")
    print("="*60)

    # 1. Status
    status = blockchain_status()
    print(f"\n📡 Blockchain status:")
    for k, v in status.items():
        print(f"   {k}: {v}")

    # 2. Build Merkle tree
    sample_analysis = {
        "sha256": "a" * 64,
        "headers_summary": "From: attacker@evil.ru\nTo: victim@company.com",
        "body_text": "URGENT: Verify your account now",
        "urls": ["http://phish.example/login", "http://bit.ly/xyz"],
        "ips": [{"ip": "203.0.113.45"}, {"ip": "203.0.113.46"}],
        "attachment_hashes": ["b" * 64, "c" * 64],
    }

    merkle = build_evidence_merkle_root(sample_analysis)
    print(f"\n🌳 Merkle tree built:")
    print(f"   Root: {merkle['merkle_root']}")
    print(f"   Leaves: {merkle['leaf_count']}")
    print(f"   Depth: {merkle['levels']}")

    # 3. Anchor
    case_id = "PRAMAAN-TEST-001"
    print(f"\n⛓️  Anchoring case {case_id}...")
    anchor_result = anchor_evidence(
        case_id=case_id,
        merkle_root=merkle["merkle_root"],
        file_sha256=sample_analysis["sha256"],
        classification="PHISHING",
    )
    print(f"   Success: {anchor_result['success']}")
    print(f"   Storage: {anchor_result['storage']}")
    if anchor_result.get("tx_hash"):
        print(f"   TX Hash: {anchor_result['tx_hash']}")
    if anchor_result.get("explorer_url"):
        print(f"   Explorer: {anchor_result['explorer_url']}")

    # 4. Verify
    print(f"\n🔍 Verifying case {case_id}...")
    verify_result = verify_evidence(case_id, merkle["merkle_root"])
    print(f"   Verified: {verify_result.get('verified')}")
    print(f"   Storage: {verify_result['storage']}")

    print("\n" + "="*60)
    print("✅ Test complete")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()