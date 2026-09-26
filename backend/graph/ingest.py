"""Ingest analyzed emails into the PRAMAAN Neo4j campaign graph."""
from datetime import datetime
from typing import Dict, Any, List
from .neo4j_client import Neo4jClient


def ingest_email(analysis: Dict[str, Any]) -> str:
    email_id = analysis["case_id"]
    with Neo4jClient().session() as session:
        session.execute_write(_ingest_tx, analysis)
    return email_id


def _ingest_tx(tx, a: Dict[str, Any]) -> None:
    tx.run("""
        MERGE (e:Email {id: $email_id})
        SET e.subject = $subject,
            e.sha256 = $sha256,
            e.from_address = $from_address,
            e.reply_to = $reply_to,
            e.threat_score = $threat_score,
            e.classification = $classification,
            e.received_at = datetime($received_at)
    """, email_id=a["case_id"],
         subject=a.get("subject", ""),
         sha256=a["sha256"],
         from_address=a.get("from_address", ""),
         reply_to=a.get("reply_to", ""),
         threat_score=int(a.get("threat_score", 0)),
         classification=a.get("classification", "unknown"),
         received_at=a.get("received_at", datetime.utcnow().isoformat()))

    if a.get("from_domain"):
        tx.run("""
            MATCH (e:Email {id: $email_id})
            MERGE (d:Domain {name: $domain})
            SET d.is_sender = true
            MERGE (e)-[:SENT_FROM_DOMAIN]->(d)
        """, email_id=a["case_id"], domain=a["from_domain"])

    if a.get("origin_ip"):
        tx.run("""
            MATCH (e:Email {id: $email_id})
            MERGE (ip:IPAddress {address: $ip})
            SET ip.country = $country
            MERGE (e)-[:SENT_FROM_IP]->(ip)
        """, email_id=a["case_id"], ip=a["origin_ip"],
             country=a.get("origin_country", ""))

        if a.get("origin_asn"):
            tx.run("""
                MATCH (ip:IPAddress {address: $ip})
                MERGE (asn:ASN {number: $asn})
                SET asn.org = $org, asn.country = $country
                MERGE (ip)-[:BELONGS_TO]->(asn)
            """, ip=a["origin_ip"],
                 asn=int(a["origin_asn"]),
                 org=a.get("origin_asn_org", ""),
                 country=a.get("origin_country", ""))

    for url_obj in a.get("urls", []):
        tx.run("""
            MATCH (e:Email {id: $email_id})
            MERGE (u:URL {value: $url})
            MERGE (e)-[:CONTAINS_URL]->(u)
            WITH u
            MERGE (d:Domain {name: $domain})
            MERGE (u)-[:RESOLVES_TO]->(d)
        """, email_id=a["case_id"],
             url=url_obj.get("url", ""),
             domain=url_obj.get("domain", "unknown.local"))

    for h in a.get("attachment_hashes", []):
        tx.run("""
            MATCH (e:Email {id: $email_id})
            MERGE (fh:FileHash {value: $hash})
            MERGE (e)-[:HAS_ATTACHMENT_HASH]->(fh)
        """, email_id=a["case_id"], hash=h)

    for recipient in a.get("recipients", []):
        tx.run("""
            MATCH (e:Email {id: $email_id})
            MERGE (u:TargetedUser {email: $recipient})
            MERGE (e)-[:RECEIVED_BY]->(u)
        """, email_id=a["case_id"], recipient=recipient)


def ingest_batch(analyses: List[Dict[str, Any]]) -> List[str]:
    return [ingest_email(a) for a in analyses]
