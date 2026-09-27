"""End-to-end Neo4j test for PRAMAAN."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.graph.neo4j_client import init_schema, Neo4jClient
from backend.graph.ingest import ingest_email
from backend.graph.campaign import correlate_campaign
from backend.graph.queries import list_campaigns, get_campaign_graph


def main():
    print("\n[SETUP] Initializing Neo4j schema...")
    init_schema()

    if not Neo4jClient().verify_connection():
        print("[ERROR] Cannot connect to Neo4j. Run `docker-compose up neo4j -d` first.")
        return

    print("[OK] Neo4j connected\n")

    samples = [
        {
            "case_id": "PRAMAAN-001",
            "sha256": "a" * 64,
            "subject": "Urgent: Verify your PayPal account",
            "from_address": "security@paypa1-secure.com",
            "from_domain": "paypa1-secure.com",
            "reply_to": "verify@evil.ru",
            "origin_ip": "203.0.113.45",
            "origin_asn": 12345,
            "origin_asn_org": "BulletProof Hosting",
            "origin_country": "RU",
            "urls": [{"url": "http://paypa1-secure.com/login", "domain": "paypa1-secure.com"}],
            "attachment_hashes": [],
            "recipients": ["victim1@company.com"],
            "threat_score": 92,
            "classification": "PHISHING",
        },
        {
            "case_id": "PRAMAAN-002",
            "sha256": "b" * 64,
            "subject": "CEO wire transfer request",
            "from_address": "ceo@company-secure-pay.com",
            "from_domain": "company-secure-pay.com",
            "reply_to": "attacker@evil.ru",
            "origin_ip": "203.0.113.46",
            "origin_asn": 12345,
            "origin_asn_org": "BulletProof Hosting",
            "origin_country": "RU",
            "urls": [],
            "attachment_hashes": ["c" * 64],
            "recipients": ["victim2@company.com"],
            "threat_score": 89,
            "classification": "BEC",
        },
        {
            "case_id": "PRAMAAN-003",
            "sha256": "d" * 64,
            "subject": "Invoice #44521 attached",
            "from_address": "billing@malicious-url.io",
            "from_domain": "malicious-url.io",
            "reply_to": "reply@evil.ru",
            "origin_ip": "203.0.113.47",
            "origin_asn": 12345,
            "origin_asn_org": "BulletProof Hosting",
            "origin_country": "RU",
            "urls": [{"url": "http://malicious-url.io/invoice", "domain": "malicious-url.io"}],
            "attachment_hashes": ["e" * 64],
            "recipients": ["victim3@company.com"],
            "threat_score": 78,
            "classification": "PHISHING",
        },
    ]

    print("[INGEST] Ingesting 3 sample emails...")
    for s in samples:
        ingest_email(s)
        print(f"   [OK] {s['case_id']}")

    print("\n[CORRELATE] Running campaign correlation on PRAMAAN-001...")
    campaign = correlate_campaign("PRAMAAN-001")
    print(f"\n   Campaign ID: {campaign.get('campaign_id')}")
    print(f"   Confidence:  {campaign.get('confidence')}")
    print(f"   Signal types: {campaign.get('shared_signal_types')}")
    print(f"   Related emails: {len(campaign.get('related_emails', []))}")
    for r in campaign.get("related_emails", []):
        print(f"      -> {r['case_id']} (strength {r['strength']}) | {r['subject']}")

    print("\n[CAMPAIGNS] All campaigns:")
    for c in list_campaigns():
        print(f"   {c['campaign_id']} | {c['email_count']} emails | confidence {c['confidence']:.2f}")

    print("\n[GRAPH] Campaign graph (nodes + edges):")
    graph = get_campaign_graph(campaign.get("campaign_id"))
    print(f"   Nodes: {len(graph['nodes'])}")
    print(f"   Edges: {len(graph['edges'])}")

    print("\n[DONE] Test complete. Open http://localhost:7474 to see the graph.")


if __name__ == "__main__":
    main()
