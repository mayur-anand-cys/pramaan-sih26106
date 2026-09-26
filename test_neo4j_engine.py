import pytest
from fastapi.testclient import TestClient
import neo4j_engine
from api import app

client = TestClient(app)

def test_neo4j_test_connection():
    status_info = neo4j_engine.test_connection()
    assert isinstance(status_info, dict)
    assert "status" in status_info
    assert "uri" in status_info
    assert "user" in status_info
    assert status_info["uri"] == "bolt://localhost:7687"
    assert status_info["user"] == "neo4j"

def test_neo4j_ingest_threat_data():
    res = neo4j_engine.ingest_threat_data(
        sha256="abc123hash",
        sender="attacker@phish.com",
        return_path="bounce@phish.com",
        domains=["phish.com"],
        ips=["1.2.3.4"],
        urls=["http://phish.com/login"],
        risk_score=85.0
    )
    assert res["success"] is True
    assert res["sha256"] == "abc123hash"

def test_neo4j_correlate_campaigns():
    # Ingest a second email with matching domain 'phish.com' to create correlation
    neo4j_engine.ingest_threat_data(
        sha256="def456hash",
        sender="victim@phish.com",
        return_path="bounce@phish.com",
        domains=["phish.com"],
        ips=["5.6.7.8"],
        urls=["http://phish.com/verify"],
        risk_score=90.0
    )
    campaigns = neo4j_engine.correlate_campaigns()
    assert isinstance(campaigns, list)
    assert len(campaigns) > 0
    first = campaigns[0]
    assert "campaign_id" in first
    assert "shared_ioc" in first

def test_neo4j_get_campaign_details():
    campaigns = neo4j_engine.correlate_campaigns()
    assert len(campaigns) > 0
    cid = campaigns[0]["campaign_id"]
    
    details = neo4j_engine.get_campaign_details(cid)
    assert details["found"] is True
    assert details["campaign_id"] == cid
    assert "emails" in details

def test_api_neo4j_status_endpoint():
    response = client.get("/api/v1/neo4j/status")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "uri" in data

def test_api_campaigns_endpoints():
    response = client.get("/api/v1/campaigns")
    assert response.status_code == 200
    data = response.json()
    assert "count" in data
    assert "campaigns" in data

    if data["count"] > 0:
        cid = data["campaigns"][0]["campaign_id"]
        detail_resp = client.get(f"/api/v1/campaigns/{cid}")
        assert detail_resp.status_code == 200
        detail_data = detail_resp.json()
        assert detail_data["campaign_id"] == cid
