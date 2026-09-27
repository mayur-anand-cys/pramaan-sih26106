"""Reusable Cypher queries for the PRAMAAN dashboard."""
from .neo4j_client import Neo4jClient


def get_campaign_graph(campaign_id: str) -> dict:
    """Return the subgraph for Cytoscape/D3 visualization."""
    with Neo4jClient().session() as session:
        result = session.run("""
            MATCH (c:Campaign {id: $campaign_id})<-[:PART_OF_CAMPAIGN]-(e:Email)
            OPTIONAL MATCH (e)-[r:SENT_FROM_IP|SENT_FROM_DOMAIN|CONTAINS_URL|HAS_ATTACHMENT_HASH]->(n)
            RETURN c,
                   COLLECT(DISTINCT e) AS emails,
                   COLLECT(DISTINCT {from: e.id, rel: type(r), to: coalesce(n.address, n.name, n.value, n.id)}) AS edges
        """, campaign_id=campaign_id)

        records = list(result)
        if not records:
            return {"campaign_id": campaign_id, "nodes": [], "edges": []}

        rec = records[0]
        nodes = [{"id": rec["c"]["id"], "type": "Campaign", "label": rec["c"]["id"]}]

        for e in rec["emails"]:
            nodes.append({
                "id": e["id"],
                "type": "Email",
                "label": e.get("subject", "")[:40],
                "threat_score": e.get("threat_score", 0),
            })

        edges = []
        for edge in rec["edges"]:
            if edge.get("to"):
                edges.append({
                    "source": edge["from"],
                    "target": edge["to"],
                    "label": edge["rel"],
                })

        return {"campaign_id": campaign_id, "nodes": nodes, "edges": edges}


def list_campaigns(limit: int = 20) -> list:
    """List all campaigns ordered by confidence then size."""
    with Neo4jClient().session() as session:
        result = session.run("""
            MATCH (c:Campaign)
            OPTIONAL MATCH (c)<-[:PART_OF_CAMPAIGN]-(e:Email)
            WITH c,
                 count(e) AS email_count,
                 avg(e.threat_score) AS avg_score
            RETURN c.id AS campaign_id,
                   email_count AS email_count,
                   avg_score AS avg_score,
                   c.confidence AS confidence,
                   c.created_at AS created_at
            ORDER BY c.confidence DESC, email_count DESC
            LIMIT $limit
        """, limit=limit)
        return [dict(r) for r in result]


def get_campaign_by_id(campaign_id: str) -> dict:
    """Fetch campaign summary + all related emails."""
    with Neo4jClient().session() as session:
        result = session.run("""
            MATCH (c:Campaign {id: $campaign_id})<-[:PART_OF_CAMPAIGN]-(e:Email)
            RETURN c.id AS campaign_id,
                   c.confidence AS confidence,
                   c.created_at AS created_at,
                   collect({
                       id: e.id,
                       subject: e.subject,
                       score: e.threat_score,
                       classification: e.classification
                   }) AS emails
        """, campaign_id=campaign_id).single()
        return dict(result) if result else None
