import email
from email import policy
import hashlib
import json
import uvicorn
from fastapi import FastAPI, File, UploadFile, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List, Any, Optional

from model import predict_phishing_probability
import zkfv
import threat_intel
import graph_engine
import neo4j_engine

# Typosquat & Homoglyph detection (Issue #7)
from backend.typosquat.detector import detect_domain, get_risk_score_contribution

app = FastAPI(
    title="PRAMAAN Threat Intelligence & Digital Forensics API",
    description="High-Performance SOC Backend API for Phishing Analysis, Threat Graph Correlation, and ZKFV Evidence Proofs",
    version="2.4.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class EMLAnalyzeRequest(BaseModel):
    eml_text: str

class ProofVerifyRequest(BaseModel):
    eml_text: str
    stored_proof: Dict[str, Any]

@app.get("/")
def read_root():
    return {
        "service": "PRAMAAN Threat Intelligence & Digital Forensics API",
        "version": "2.4.0",
        "status": "ONLINE",
        "docs_url": "/docs"
    }

@app.get("/api/v1/health")
def health_check():
    return {"status": "HEALTHY", "engine": "PRAMAAN v2.4 Forensic Engine"}

@app.post("/api/v1/analyze")
async def analyze_eml_file(file: UploadFile = File(...)):
    """
    Upload an .eml file and perform full forensic threat analysis:
    - MIME header parsing & authentication checks (SPF/DKIM/DMARC)
    - ML phishing probability classification
    - Threat Intelligence & URL structural analysis
    - IP geolocation & ASN resolution
    - Dynamic Threat Infrastructure Graph construction
    - Zero-Knowledge Forensic Verification (ZKFV) Merkle proof generation
    """
    if not file.filename.endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are supported.")

    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    msg = email.message_from_bytes(raw_bytes, policy=policy.default)
    sha256_hash = hashlib.sha256(raw_bytes).hexdigest()

    subject_text = str(msg.get("Subject", ""))
    from_header = str(msg.get("From", ""))
    to_header = str(msg.get("To", ""))
    date_header = str(msg.get("Date", ""))
    reply_to = str(msg.get("Reply-To", ""))
    return_path = str(msg.get("Return-Path", ""))

    body_text = extract_body_from_msg(msg)
    full_text = f"{subject_text}\n{body_text}"

    # 1. Domain Alignment & Headers Analysis
    domain_alignment = threat_intel.analyze_domain_alignment(from_header, return_path, reply_to)

    # 1b. Typosquat & Homoglyph Detection (Issue #7)
    typosquat_result = None
    typosquat_bonus = 0
    _from_domain = domain_alignment.get("from_domain", "") if isinstance(domain_alignment, dict) else ""
    if _from_domain:
        try:
            typosquat_result = detect_domain(_from_domain, check_rdap=True)
            typosquat_bonus = get_risk_score_contribution(typosquat_result)
        except Exception as e:
            print(f"[WARN] Typosquat detection failed: {e}")

    # 2. Extract Artifacts
    urls = extract_urls(full_text)
    ips = extract_ips(full_text + " " + str(msg))

    # 3. URL Structural Analysis & Threat Intel
    analyzed_urls = threat_intel.analyze_url_structure(urls)

    # 4. Fast Parallel IP Geolocation
    ip_list = [item["ip"] for item in ips]
    geo_data = threat_intel.batch_geolocate_ips(ip_list)

    # 5. ML Model Prediction
    ml_prob = predict_phishing_probability(full_text)

    # 6. Auth Headers Check
    auth_info = analyze_auth_headers(msg)

    # 7. Risk Score & Factor Calculation
    risk_score, risk_factors = calculate_risk_score(
        msg, body_text, analyzed_urls, ips, auth_info, domain_alignment, ml_prob
    )

    # 7b. Add typosquat bonus to risk score
    if typosquat_bonus > 0 and typosquat_result is not None:
        risk_score = min(100, risk_score + typosquat_bonus)
        risk_factors.append({
            "factor": "typosquat_detection",
            "points": typosquat_bonus,
            "detail": f"Lookalike domain detected: {typosquat_result.matched_brand or 'unknown brand'}"
        })

    # 8. Infrastructure Graph Construction
    graph_data = graph_engine.build_threat_infrastructure_graph(from_header, return_path, urls, geo_data)

    # 9. Neo4j Campaign Graph Ingestion
    all_domains = [domain_alignment.get("from_domain"), domain_alignment.get("return_domain")]
    all_domains = [d for d in all_domains if d]
    neo4j_res = neo4j_engine.ingest_threat_data(
        sha256=sha256_hash,
        sender=from_header,
        return_path=return_path,
        domains=all_domains,
        ips=ip_list,
        urls=urls,
        risk_score=risk_score
    )

    # 10. ZKFV Evidence Proof Generation
    zkfv_proof = zkfv.generate_evidence_proof(raw_bytes)

    risk_level = "HIGH RISK" if risk_score >= 65 else ("MODERATE RISK" if risk_score >= 35 else "LOW RISK")

    return {
        "file_name": file.filename,
        "sha256": sha256_hash,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "ml_phishing_probability": ml_prob,
        "headers": {
            "subject": subject_text,
            "from": from_header,
            "to": to_header,
            "date": date_header,
            "reply_to": reply_to,
            "return_path": return_path
        },
        "authentication": auth_info,
        "domain_alignment": domain_alignment,
        "risk_factors": risk_factors,
        "extracted_urls": analyzed_urls,
        "extracted_ips": geo_data,
        "threat_graph": {
            "num_nodes": graph_data["num_nodes"],
            "num_edges": graph_data["num_edges"],
            "nodes": graph_data["nodes"],
            "edges": graph_data["edges"]
        },
        "neo4j_ingestion": neo4j_res,
        "zkfv_proof": zkfv_proof
    }

@app.post("/api/v1/verify-zkfv")
async def verify_zkfv_proof(file: UploadFile = File(...), proof_json: str = Query(...)):
    """Verify cryptographic evidence proof against uploaded EML bytes."""
    raw_bytes = await file.read()
    try:
        stored_proof = json.loads(proof_json)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid proof JSON string.")

    is_valid, current_root, expected_root = zkfv.verify_evidence_proof(raw_bytes, stored_proof)
    return {
        "is_valid": is_valid,
        "current_merkle_root": current_root,
        "expected_merkle_root": expected_root
    }

@app.get("/api/v1/audit-ledger")
def get_audit_ledger(limit: int = 20):
    """Retrieve evidence audit ledger entries from SQLite database."""
    return zkfv.get_recent_audit_logs(limit)

@app.get("/api/v1/neo4j/status")
def get_neo4j_status():
    """Return Neo4j connection status and configuration."""
    return neo4j_engine.test_connection()

@app.get("/api/v1/campaigns")
def get_campaign_correlations():
    """Retrieve cross-email correlated threat campaigns from Neo4j / graph store."""
    campaigns = neo4j_engine.correlate_campaigns()
    return {
        "count": len(campaigns),
        "campaigns": campaigns
    }

@app.get("/api/v1/campaigns/{campaign_id}")
def get_campaign_by_id(campaign_id: str):
    """Retrieve details and correlated email metadata for a specific campaign cluster."""
    details = neo4j_engine.get_campaign_details(campaign_id)
    if not details.get("found"):
        raise HTTPException(status_code=404, detail=f"Campaign '{campaign_id}' not found.")
    return details

def extract_body_from_msg(msg: email.message.EmailMessage) -> str:
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body += payload.decode('utf-8', errors='replace') + "\n"
                except Exception:
                    pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode('utf-8', errors='replace')
        except Exception:
            body = str(msg.get_payload() or "")
    return body

def extract_urls(text: str) -> List[str]:
    import re
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    matches = re.findall(url_pattern, text, re.IGNORECASE)
    cleaned = []
    for u in matches:
        c = re.sub(r'[.,;!)]+$', '', u)
        if c not in cleaned:
            cleaned.append(c)
    return cleaned

def extract_ips(text: str) -> List[Dict[str, Any]]:
    import re, ipaddress
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    candidates = re.findall(ip_pattern, text)
    valid_ips = []
    for candidate in candidates:
        try:
            ip_obj = ipaddress.ip_address(candidate)
            if not any(i["ip"] == candidate for i in valid_ips):
                valid_ips.append({"ip": candidate, "is_private": ip_obj.is_private})
        except ValueError:
            pass
    return valid_ips

def analyze_auth_headers(msg: email.message.EmailMessage) -> Dict[str, str]:
    auth_results = []
    for h_name, h_val in msg.items():
        if h_name.lower() in ["authentication-results", "received-spf", "x-authentication-results"]:
            auth_results.append(str(h_val).lower())
    full_str = " ".join(auth_results)

    spf = "PASS" if "spf=pass" in full_str else ("FAIL" if any(t in full_str for t in ["spf=fail", "spf=softfail"]) else "UNKNOWN")
    dkim = "PASS" if "dkim=pass" in full_str else ("FAIL" if "dkim=fail" in full_str else "UNKNOWN")
    dmarc = "PASS" if "dmarc=pass" in full_str else ("FAIL" if "dmarc=fail" in full_str else "UNKNOWN")

    return {"spf": spf, "dkim": dkim, "dmarc": dmarc}

def calculate_risk_score(msg, body, urls, ips, auth_info, domain_alignment, ml_prob) -> tuple:
    score = 0
    factors = []

    subject = str(msg.get("Subject", "")).lower()
    for kw in threat_intel.SUSPICIOUS_KEYWORDS:
        if kw in subject:
            score += 15
            factors.append({"category": "Suspicious Subject", "points": 15, "description": f"Urgent keyword in subject: '{kw}'"})
            break

    if urls:
        score += 5
        factors.append({"category": "Extracted URLs", "points": 5, "description": f"Email contains {len(urls)} link(s)"})
        for u in urls:
            if u.get("is_ip"):
                score += 20
                factors.append({"category": "URL IP Address", "points": 20, "description": f"URL uses raw IP: {u['url']}"})
                break
            if u.get("tld"):
                score += 15
                factors.append({"category": "Suspicious TLD", "points": 15, "description": f"URL uses high-risk TLD: {u['tld']}"})
                break

    if domain_alignment["is_spoofed"]:
        score += 20
        factors.append({"category": "Domain Mismatch", "points": 20, "description": "From domain does not match Return-Path domain"})

    if auth_info["spf"] == "FAIL":
        score += 15
        factors.append({"category": "Auth Failure", "points": 15, "description": "SPF authentication failed"})

    if ml_prob > 0.3:
        ml_pts = int(round(ml_prob * 25))
        score += ml_pts
        factors.append({"category": "ML Classifier", "points": ml_pts, "description": f"ML model estimated {ml_prob*100:.1f}% phishing likelihood"})

    final_score = min(100, max(0, score))
    return final_score, factors

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
