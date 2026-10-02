import os
import logging
from typing import Dict, List, Any, Optional
import networkx as nx

logger = logging.getLogger("pramaan.neo4j")
logger.setLevel(logging.ERROR)  # silence expected offline warnings

# Neo4j Environment Configuration
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "pramaan123")

# Optional Neo4j Driver import
try:
    from neo4j import GraphDatabase, Driver
    HAS_NEO4J_DRIVER = True
except ImportError:
    HAS_NEO4J_DRIVER = False
    Driver = None

# In-memory Graph Store fallback when Neo4j is unreachable
_in_memory_graph = nx.MultiDiGraph()
_analyzed_emails: Dict[str, Dict[str, Any]] = {}

import time as _time

_last_connection_attempt: float = 0.0
_last_connection_ok: bool = False
_connection_backoff_seconds: float = 30.0


def get_neo4j_driver() -> Optional[Any]:
    """
    Establish or verify connection to Neo4j database using environment credentials.
    Returns Neo4j Driver object or None if unreachable / driver missing.

    Caches the failure state for 30s to avoid hammering the connection on
    every streamlit rerun or every graph query.
    """
    global _last_connection_attempt, _last_connection_ok

    if not HAS_NEO4J_DRIVER:
        logger.warning("neo4j library not available.")
        return None

    now = _time.time()

    # If we recently failed, skip retrying until backoff expires
    if not _last_connection_ok and (now - _last_connection_attempt) < _connection_backoff_seconds:
        return None

    _last_connection_attempt = now

    try:
        driver = GraphDatabase.driver(
            NEO4J_URI,
            auth=(NEO4J_USER, NEO4J_PASSWORD),
            connection_timeout=1.0
        )
        driver.verify_connectivity()
        if not _last_connection_ok:
            logger.info(f"Neo4j connection established ({NEO4J_URI})")
        _last_connection_ok = True
        return driver
    except Exception as e:
        if _last_connection_ok:
            logger.warning(f"Neo4j connection lost ({NEO4J_URI}): {e}")
        _last_connection_ok = False
        return None

def test_connection() -> Dict[str, Any]:
    """
    Check Neo4j connectivity and return connection status details.

    Returns:
        {
            "connected": bool,
            "mode": "neo4j" | "memory",
            "status": human-readable label with emoji,
            "status_color": "green" | "amber" | "red",
            "uri": NEO4J_URI,
            "user": NEO4J_USER,
            "message": guidance string,
            "driver_available": bool,
            "fallback_mode": "IN_MEMORY_GRAPH" (only when offline)
        }
    """
    driver = get_neo4j_driver()
    if driver is not None:
        try:
            driver.close()
            return {
                "connected": True,
                "mode": "neo4j",
                "status": "Live Neo4j",
                "status_color": "green",
                "uri": NEO4J_URI,
                "user": NEO4J_USER,
                "message": f"Connected to Neo4j at {NEO4J_URI}",
                "driver_available": True,
            }
        except Exception as e:
            logger.error(f"Error checking Neo4j connectivity: {e}")

    # Neo4j is offline  using NetworkX fallback (still functional, just not persistent)
    return {
        "connected": False,
        "mode": "memory",
        "status": "In-Memory Mode",
        "status_color": "amber",
        "uri": NEO4J_URI,
        "user": NEO4J_USER,
        "message": "Neo4j offline  using in-memory NetworkX fallback. Correlations work but are not persisted.",
        "how_to_enable": "Run: docker-compose up -d neo4j",
        "driver_available": HAS_NEO4J_DRIVER,
        "fallback_mode": "IN_MEMORY_GRAPH",
    }

def ingest_threat_data(
    sha256: str,
    sender: str,
    return_path: str,
    domains: List[str],
    ips: List[str],
    urls: List[str],
    risk_score: float
) -> Dict[str, Any]:
    """
    Ingest email threat indicators into Neo4j graph database.
    Falls back to internal in-memory NetworkX store if Neo4j is offline.
    """
    email_data = {
        "sha256": sha256,
        "sender": sender,
        "return_path": return_path,
        "domains": list(set(domains)),
        "ips": list(set(ips)),
        "urls": list(set(urls)),
        "risk_score": risk_score
    }
    _analyzed_emails[sha256] = email_data

    # Update in-memory fallback graph
    _in_memory_graph.add_node(sha256, type="EMAIL", sender=sender, risk_score=risk_score)
    for d in domains:
        if d:
            _in_memory_graph.add_node(d, type="DOMAIN")
            _in_memory_graph.add_edge(sha256, d, relation="HAS_DOMAIN")
    for ip in ips:
        if ip:
            _in_memory_graph.add_node(ip, type="IP")
            _in_memory_graph.add_edge(sha256, ip, relation="HAS_IP")
    for u in urls:
        if u:
            _in_memory_graph.add_node(u, type="URL")
            _in_memory_graph.add_edge(sha256, u, relation="CONTAINS_URL")

    driver = get_neo4j_driver()
    if driver is None:
        return {
            "success": True,
            "storage": "IN_MEMORY",
            "sha256": sha256,
            "status": "Stored in fallback in-memory graph repository"
        }

    try:
        query = """
        MERGE (e:Email {sha256: $sha256})
        SET e.sender = $sender, e.return_path = $return_path, e.risk_score = $risk_score, e.timestamp = datetime()
        
        WITH e
        UNWIND $domains AS d_name
        MERGE (d:Domain {name: d_name})
        MERGE (e)-[:HAS_DOMAIN]->(d)
        
        WITH e
        UNWIND $ips AS ip_addr
        MERGE (ip:IP {address: ip_addr})
        MERGE (e)-[:HAS_IP]->(ip)

        WITH e
        UNWIND $urls AS u_str
        MERGE (u:URL {url: u_str})
        MERGE (e)-[:CONTAINS_URL]->(u)
        """
        with driver.session() as session:
            session.run(
                query,
                sha256=sha256,
                sender=sender,
                return_path=return_path,
                domains=domains,
                ips=ips,
                urls=urls,
                risk_score=risk_score
            )
        driver.close()
        return {
            "success": True,
            "storage": "NEO4J",
            "sha256": sha256,
            "status": "Persisted to Neo4j graph database"
        }
    except Exception as e:
        logger.error(f"Neo4j ingestion query failed: {e}")
        return {
            "success": True,
            "storage": "IN_MEMORY_FALLBACK",
            "sha256": sha256,
            "error": str(e)
        }

def correlate_campaigns() -> List[Dict[str, Any]]:
    """
    Query cross-email correlations to detect shared infrastructure campaigns.
    Returns grouped campaign clusters based on shared IOCs (Domains, IPs, URLs).
    """
    driver = get_neo4j_driver()
    if driver is not None:
        try:
            query = """
            MATCH (e1:Email)-[r1]->(ioc)<-[r2]-(e2:Email)
            WHERE e1.sha256 < e2.sha256
            WITH ioc, labels(ioc)[0] AS ioc_type, collect(DISTINCT e1.sha256) + collect(DISTINCT e2.sha256) AS email_hashes
            RETURN ioc_type, 
                   CASE 
                     WHEN ioc_type = 'Domain' THEN ioc.name 
                     WHEN ioc_type = 'IP' THEN ioc.address 
                     WHEN ioc_type = 'URL' THEN ioc.url 
                     ELSE id(ioc) 
                   END AS shared_ioc,
                   email_hashes
            """
            with driver.session() as session:
                result = session.run(query)
                campaigns = []
                idx = 1
                for record in result:
                    email_hashes = list(set(record["email_hashes"]))
                    campaigns.append({
                        "campaign_id": f"CAMP-{idx:03d}",
                        "shared_ioc_type": record["ioc_type"],
                        "shared_ioc": record["shared_ioc"],
                        "correlated_emails_count": len(email_hashes),
                        "email_hashes": email_hashes
                    })
                    idx += 1
            driver.close()
            if campaigns:
                return campaigns
        except Exception as e:
            logger.error(f"Neo4j campaign correlation query failed: {e}")

    # Fallback in-memory correlation using NetworkX connected components on shared IOCs
    ioc_nodes = [n for n, d in _in_memory_graph.nodes(data=True) if d.get("type") in ["DOMAIN", "IP", "URL"]]
    campaigns = []
    c_idx = 1
    
    for ioc in ioc_nodes:
        # Get emails connected to this IOC
        neighbors = [n for n in _in_memory_graph.predecessors(ioc) if _in_memory_graph.nodes[n].get("type") == "EMAIL"]
        if len(neighbors) >= 2:
            campaigns.append({
                "campaign_id": f"CAMP-{c_idx:03d}",
                "shared_ioc_type": _in_memory_graph.nodes[ioc].get("type"),
                "shared_ioc": ioc,
                "correlated_emails_count": len(neighbors),
                "email_hashes": neighbors
            })
            c_idx += 1

    # Return only real campaigns (2+ emails sharing infrastructure).
    # No synthesized clusters — the UI will explain when there are none.
    return campaigns

def get_campaign_details(campaign_id: str) -> Dict[str, Any]:
    """
    Retrieve detail view for a specific campaign cluster.
    """
    all_campaigns = correlate_campaigns()
    target = next((c for c in all_campaigns if c["campaign_id"] == campaign_id), None)
    
    if not target:
        return {
            "campaign_id": campaign_id,
            "found": False,
            "message": "Campaign cluster not found"
        }

    emails_meta = []
    for sha in target.get("email_hashes", []):
        meta = _analyzed_emails.get(sha, {"sha256": sha, "sender": "Unknown", "risk_score": 0.0})
        emails_meta.append(meta)

    return {
        "campaign_id": campaign_id,
        "found": True,
        "shared_ioc_type": target.get("shared_ioc_type"),
        "shared_ioc": target.get("shared_ioc"),
        "correlated_emails_count": target.get("correlated_emails_count", 0),
        "emails": emails_meta
    }


def seed_demo_data() -> int:
    """
    Insert 3 synthetic demo emails sharing 'phish-server.com'.
    Idempotent — safe to call repeatedly.
    Returns count of emails ingested.
    """
    import hashlib

    demo_emails = [
        {
            "seed": "demo-001",
            "sender": "security@phish-server.com",
            "return_path": "bounce@phish-server.com",
            "domains": ["phish-server.com", "fake-bank-login.net"],
            "ips": ["203.0.113.10"],
            "urls": ["http://phish-server.com/login", "http://fake-bank-login.net/verify"],
            "risk_score": 85.0,
        },
        {
            "seed": "demo-002",
            "sender": "billing@phish-server.com",
            "return_path": "bounce@phish-server.com",
            "domains": ["phish-server.com", "fake-bank-login.net"],
            "ips": ["203.0.113.11"],
            "urls": ["http://phish-server.com/invoice"],
            "risk_score": 78.0,
        },
        {
            "seed": "demo-003",
            "sender": "hr@phish-server.com",
            "return_path": "bounce@phish-server.com",
            "domains": ["phish-server.com"],
            "ips": ["203.0.113.12"],
            "urls": ["http://phish-server.com/payroll"],
            "risk_score": 92.0,
        },
    ]

    count = 0
    for e in demo_emails:
        sha = hashlib.sha256(e["seed"].encode()).hexdigest()
        if sha in _analyzed_emails:
            continue
        ingest_threat_data(
            sha256=sha,
            sender=e["sender"],
            return_path=e["return_path"],
            domains=e["domains"],
            ips=e["ips"],
            urls=e["urls"],
            risk_score=e["risk_score"],
        )
        count += 1
    return count
