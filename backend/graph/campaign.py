"""Campaign clustering algorithm for PRAMAAN."""
from datetime import datetime
from typing import Dict, Any
from .neo4j_client import Neo4jClient


def correlate_campaign(email_id: str, min_strength: int = 1) -> Dict[str, Any]:
    with Neo4jClient().session() as session:
        return session.execute_write(_correlate_tx, email_id, min_strength)


def _correlate_tx(tx, email_id: str, min_strength: int) -> Dict[str, Any]:
    query = """
    MATCH (target:Email {id: $email_id})
    OPTIONAL MATCH (target)-[:SENT_FROM_IP]->(:IPAddress)-[:BELONGS_TO]->(target_asn:ASN)
    OPTIONAL MATCH (target)-[:SENT_FROM_IP]->(target_ip:IPAddress)
    OPTIONAL MATCH (target)-[:SENT_FROM_DOMAIN]->(target_dom:Domain)
    OPTIONAL MATCH (target)-[:HAS_ATTACHMENT_HASH]->(target_hash:FileHash)
    OPTIONAL MATCH (target)-[:RECEIVED_BY]->(target_user:TargetedUser)

    WITH target,
         COLLECT(DISTINCT target_asn) AS asns,
         COLLECT(DISTINCT target_ip) AS ips,
         COLLECT(DISTINCT target_dom) AS domains,
         COLLECT(DISTINCT target_hash) AS hashes,
         COLLECT(DISTINCT target_user) AS users

    MATCH (other:Email)
    WHERE other.id <> target.id
      AND (
        EXISTS { MATCH (other)-[:SENT_FROM_IP]->(:IPAddress)-[:BELONGS_TO]->(a:ASN) WHERE a IN asns }
        OR EXISTS { MATCH (other)-[:SENT_FROM_IP]->(i:IPAddress) WHERE i IN ips }
        OR EXISTS { MATCH (other)-[:SENT_FROM_DOMAIN]->(d:Domain) WHERE d IN domains }
        OR EXISTS { MATCH (other)-[:HAS_ATTACHMENT_HASH]->(h:FileHash) WHERE h IN hashes }
        OR EXISTS { MATCH (other)-[:RECEIVED_BY]->(u:TargetedUser) WHERE u IN users }
      )

    WITH target, other,
         [a IN asns WHERE EXISTS { MATCH (other)-[:SENT_FROM_IP]->(:IPAddress)-[:BELONGS_TO]->(a) }] AS shared_asns,
         [i IN ips WHERE EXISTS { MATCH (other)-[:SENT_FROM_IP]->(i) }] AS shared_ips,
         [d IN domains WHERE EXISTS { MATCH (other)-[:SENT_FROM_DOMAIN]->(d) }] AS shared_domains,
         [h IN hashes WHERE EXISTS { MATCH (other)-[:HAS_ATTACHMENT_HASH]->(h) }] AS shared_hashes,
         [u IN users WHERE EXISTS { MATCH (other)-[:RECEIVED_BY]->(u) }] AS shared_users

    WITH target, other,
         shared_asns, shared_ips, shared_domains, shared_hashes, shared_users,
         (SIZE(shared_asns) * 3 + SIZE(shared_ips) * 4 +
          SIZE(shared_domains) * 2 + SIZE(shared_hashes) * 5 +
          SIZE(shared_users) * 1) AS strength

    WHERE strength >= $min_strength

    RETURN other.id AS related_email_id,
           other.subject AS related_subject,
           other.threat_score AS related_score,
           strength,
           [a IN shared_asns | a.number] AS shared_asns,
           [i IN shared_ips | i.address] AS shared_ips,
           [d IN shared_domains | d.name] AS shared_domains,
           [h IN shared_hashes | h.value] AS shared_hashes,
           [u IN shared_users | u.email] AS shared_users
    ORDER BY strength DESC
    LIMIT 50
    """

    records = list(tx.run(query, email_id=email_id, min_strength=min_strength))

    if not records:
        return {
            "campaign_id": None,
            "related_emails": [],
            "shared_signal_types": 0,
            "confidence": 0.0,
            "message": "No related emails found.",
        }

    existing = tx.run("""
        MATCH (e:Email {id: $email_id})-[:PART_OF_CAMPAIGN]->(c:Campaign)
        RETURN c.id AS campaign_id, c.confidence AS confidence
    """, email_id=email_id).single()

    if existing:
        campaign_id = existing["campaign_id"]
    else:
        campaign_id = _generate_campaign_id(tx)
        related_ids = [r["related_email_id"] for r in records]
        all_ids = related_ids + [email_id]

        tx.run("""
            MERGE (c:Campaign {id: $campaign_id})
            SET c.created_at = datetime(),
                c.email_count = $count
            WITH c
            UNWIND $email_ids AS eid
            MATCH (e:Email {id: eid})
            MERGE (e)-[:PART_OF_CAMPAIGN]->(c)
        """, campaign_id=campaign_id, count=len(all_ids), email_ids=all_ids)

    first = records[0]
    signal_types = sum([
        1 if first["shared_asns"] else 0,
        1 if first["shared_ips"] else 0,
        1 if first["shared_domains"] else 0,
        1 if first["shared_hashes"] else 0,
        1 if first["shared_users"] else 0,
    ])
    confidence = min(1.0, signal_types / 5.0)

    tx.run("""
        MATCH (c:Campaign {id: $campaign_id})
        SET c.confidence = $confidence,
            c.updated_at = datetime()
    """, campaign_id=campaign_id, confidence=confidence)

    return {
        "campaign_id": campaign_id,
        "related_emails": [
            {
                "case_id": r["related_email_id"],
                "subject": r["related_subject"],
                "threat_score": r["related_score"],
                "strength": r["strength"],
                "shared": {
                    "asns": r["shared_asns"],
                    "ips": r["shared_ips"],
                    "domains": r["shared_domains"],
                    "hashes": r["shared_hashes"],
                    "recipients": r["shared_users"],
                },
            } for r in records
        ],
        "shared_signal_types": signal_types,
        "confidence": confidence,
    }


def _generate_campaign_id(tx) -> str:
    result = tx.run("MATCH (c:Campaign) RETURN count(c) AS existing").single()
    seq = (result["existing"] or 0) + 1
    return f"CAMP-{seq:04d}"
