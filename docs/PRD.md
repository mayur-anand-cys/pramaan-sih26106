📘 PRAMAAN — Product Requirements Document (PRD)
Version: 2.0
Product: PRAMAAN (internally also called TRACE-X)
Problem Statement: SIH26106 — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform
Organization: AICTE Cyber Security Cell
Theme: Blockchain & Cybersecurity
Team: Team Apex (6 members)
Repo Owner: mayur-anand-cys
Date: September 2026

1. Executive Summary
PRAMAAN is an explainable, forensic-grade email threat investigation platform for SOC analysts, CERT-In responders, and law enforcement. It ingests a suspicious .eml file, runs a deterministic 14-stage pipeline, and outputs a threat score, geolocation map, Neo4j campaign correlation, blockchain-anchored evidence, and a court-ready PDF report.

Core differentiator: Real on-chain evidence anchoring (Sepolia + Solidity) — a capability no public competitor demonstrates.

2. Problem Statement
Traditional email security blocks threats but leaves analysts with no infrastructure visibility, no campaign awareness, no tamper-evident evidence, and no court-admissible documentation. TRINETRA and 30+ other competitors we analyzed focus on detection, not investigation.

The gap: Detection ≠ Investigation.

3. Goals and Objectives
Primary
Detect phishing, BEC, spoofing, and impersonation with explainable scores.

Reconstruct email relay paths using Trusted MTA Boundary logic.

Correlate emails into campaigns via Neo4j.

Preserve evidence via SHA-256 + Merkle root + blockchain anchor.

Generate court-ready PDF reports with chain-of-custody.

Secondary
Live DNS SPF/DKIM/DMARC/ARC verification

9-engine threat intel enrichment

XAI contradiction detection

STIX 2.1 export

Non-Goals
Not a replacement for enterprise email gateways

Does not identify the physical attacker

Does not claim blockchain = legal admissibility

4. The 5 Killer Features
#	Feature	Status
1	Neo4j persistent campaign graph	✅ Merged
2	Real Merkle + Solidity anchor on Sepolia	✅ Live
3	OAuth 2.0 live inbox firewall	⏳ Roadmap (Grand Finale)
4	Full chain-of-custody PDF with blockchain TX	✅ Partial
5	XAI contradiction detection	✅ Merged
5. Users
User	Need
SOC Analyst	Fast explainable verdicts with infrastructure intel
CERT-In Responder	Cross-org campaign correlation + court evidence
Law Enforcement	Court-ready PDF with blockchain proof
Enterprise Security	OAuth live inbox + multi-tenant
Government/Education	Institutional email security
6. Functional Requirements (High-Level)
Phase	Requirement
Parsing	MIME + RFC 5322/5321, SHA-256, header extraction
Auth	Live DNS SPF/DKIM/DMARC/ARC + Header Trust Score
Infrastructure	Trusted MTA Boundary, GeoIP, ASN, VPN/Tor
Analysis	DistilBERT/TF-IDF, PCI, XAI, risk scoring
Evidence	Merkle tree, Solidity anchor, PDF CoC
Correlation	Neo4j campaign clustering
Reporting	PDF + HTML + Markdown + STIX 2.1
Live Inbox	OAuth 2.0 for M365/Gmail (roadmap)
7. Non-Functional Requirements
Analysis ≤ 8 seconds per email

Neo4j correlation ≤ 500 ms

Blockchain anchor ≤ 15 seconds

99.9% uptime (production target)

GDPR Article 5 + DPDP Act 2023 compliant

BSA 2023 Section 63(4) aligned

Defense against MIME bombs, zip bombs, prompt injection, CSS evasion

8. Success Metrics
Precision/Recall ≥ 95% on phishing corpus

5× analyst productivity

90%+ campaign detection rate

Zero competitor with all 5 killer features (confirmed across 30+ repos analyzed)

9. Risks
Risk	Mitigation
Testnet deprecation	Dual-anchor: Sepolia + Hyperledger Fabric
API rate limits	30-day LRU cache + graceful degradation
Legal admissibility	Section 63(4) metadata only, not guarantee
Team fatigue	Clear ownership + phased sprints
10. Roadmap
Phase	Target	Deliverable
Phase 1	Sept 2026	Idea submission ✅
Phase 2	Oct 2026	Grand Finale demo
Phase 3	Nov 2026	Pilot with CERT-In/state cell
Phase 4	Q1 2027	Enterprise SaaS launch
Phase 5	2027–28	National infrastructure integration
🏗️ Architecture & Tech Stack Plan
System Architecture (14-Stage Pipeline)
text
INPUT: .eml OR OAuth live inbox
  │
  ├─ Stage 1:  Ingestion (byte preservation)
  ├─ Stage 2:  MIME + RFC 5322 parser
  ├─ Stage 3:  SHA-256 hashing
  ├─ Stage 4:  Live DNS SPF/DKIM/DMARC/ARC
  ├─ Stage 5:  Trusted MTA Boundary reconstruction
  ├─ Stage 6:  IOC extraction
  ├─ Stage 7:  9-engine threat intel (async)
  ├─ Stage 8:  GeoIP enrichment
  ├─ Stage 9:  ML classifier (TF-IDF)
  ├─ Stage 10: NLP/BEC + PCI
  ├─ Stage 11: Risk scoring (reason codes)
  ├─ Stage 12: XAI contradiction detection
  ├─ Stage 13: Merkle tree + LLM review
  ├─ Stage 14: Neo4j campaign correlation
  │
  ├─ Evidence: Blockchain anchor (Sepolia / Hyperledger)
  ├─ Storage:  PostgreSQL + Neo4j + S3
  └─ Output:   Dashboard + PDF + STIX
Tech Stack
Layer	Technology
Frontend	Streamlit + Cytoscape + Leaflet + Altair + Plotly
Backend	FastAPI + Uvicorn + Pydantic v2
ML	TF-IDF + Logistic Regression (scikit-learn)
NLP	Groq LLaMA 3.3 (tier-2)
DNS	dnspython + pyspf + dkimpy
Threat Intel	VirusTotal, AbuseIPDB, IPinfo, URLScan, Safe Browsing, RDAP, Shodan, Censys
Graph DB	Neo4j 5.x
Relational	PostgreSQL 16 (planned) / SQLite (demo)
Blockchain	Solidity PramaanEvidence.sol on Sepolia + Hyperledger (roadmap)
Reports	ReportLab + WeasyPrint + STIX 2.1
Geo	ip-api.com + MaxMind GeoLite2 (offline fallback)
Deployment	Streamlit Cloud / Docker / Vercel
Testing	pytest + pytest-asyncio
Repo Structure (Current)
text
pramaan-sih26106/
├── app.py                    Streamlit dashboard
├── api.py                    FastAPI REST endpoints
├── model.py                  TF-IDF phishing classifier
├── zkfv.py                   Merkle evidence proof
├── graph_engine.py           NetworkX infrastructure graph
├── neo4j_engine.py           Neo4j campaign correlation
├── threat_intel.py           IOC analysis
├── report_gen.py             ReportLab PDF
├── security_hardening.py     Defense module (pending commit)
├── blockchain/
│   ├── anchor.py             Web3.py + Sepolia
│   ├── merkle.py             Merkle tree builder
│   └── contracts/
│       └── PramaanEvidence.sol
├── backend/
│   ├── detection/
│   │   ├── auth_check.py     Live DNS SPF/DKIM/DMARC/ARC
│   │   └── xai.py            XAI contradiction engine
│   ├── intel/                (pending PR #36)
│   └── graph/                (pending PR #20)
├── pramaan/
│   └── report.py             CLI report generator
├── report_canvas.py          PDF canvas
├── report_html.py            HTML export
├── report_markdown.py        Markdown export
├── report_stix.py            STIX 2.1 export
├── tests/
├── requirements.txt
└── docker-compose.yml        Neo4j service
External Services
9 threat intel APIs (parallel async, 4s timeout, 30-day cache)

1 GeoIP API (ip-api.com, cached, private IP skipped)

1 LLM (Groq LLaMA 3.3, tier-2 review)

1 Blockchain RPC (Sepolia public endpoint)

📅 Agile Implementation Roadmap
Sprint Structure
2-week sprints. Daily 15-min standups. Weekly demos.

Sprint 0 — Submitted ✅ (Sept 20–30)
✅ Working Streamlit dashboard

✅ TF-IDF model

✅ ZKFV Merkle proof

✅ Neo4j campaign module

✅ Live Sepolia anchor

✅ Idea deck submitted

Sprint 1 — Clean Up (Oct 1–14) — Current
#	Task	Owner	Output
1	Commit security_hardening.py	Mayur	PR merged
2	Merge or close PRs #33, #35, #36, #37	Mayur	Clean tree
3	Install Docker Desktop	Mayur	Neo4j running live
4	Cherry-pick Charitha's UI	Mayur	New landing page
5	Fix SHAP waterfall display	Sudarshan	XAI visible
6	Add live DNS badges to Tab 2	Sudarshan	Killer feature visible
7	Fix use_container_width deprecation	Charitha	Clean logs
8	Add 5 real .eml fixtures	Shreya	Test data ready
9	Write 30+ pytest tests	Sudarshan	Green CI
10	Rewrite README with live URLs	Shreya	First impression
Sprint 2 — Grand Finale Prep (Oct 15–28)
#	Task	Owner	Output
1	Deploy to live URL (Vercel + Railway)	Sudarshan	Public demo
2	OAuth 2.0 firewall (M365 + Gmail)	Mayur	Killer feature #3
3	Thread hijacking detection	Keerthana	Forensics depth
4	MTA Boundary Honeypot	Sudarshan	Anti-evasion
5	PII masking in PDF	Sneha	DPDP compliance
6	Rehearse 4-min demo x3	All	Muscle memory
7	Backup demo video	Sudarshan	Safety net
8	Prepare 20 Q&A answers	All	Pitch readiness
Sprint 3 — Grand Finale Demo (Oct 25–31)
Live pitch

Handle judge questions

Backup video if needed

Sprint 4+ — Post-SIH Commercialization (Nov 2026+)
Phase	Focus
Nov 2026	Pilot with CERT-In / state cyber cell
Dec 2026	Hyperledger Fabric permissioned chain
Q1 2027	Multi-tenant SaaS, RBAC, HSM, FedRAMP prep
Q2 2027	Enterprise rollout, MSSP white-label
2028	National infrastructure integration
Milestones (GitHub)
SIH Idea Submission — due Sept 30, 2026 (✅ submitted)

Grand Finale Prep — due Oct 15, 2026

Grand Finale Demo — due Oct 25, 2026

Delivery Cadence Rules
One feature = one PR. No direct pushes to main.

Every PR must have: description, screenshot, tests, reviewer approval.

Commit format: feat(issue-N): description, fix(issue-N): description, docs: ...

Branch format: feature/issue-N-short-name, fix/issue-N-short-name, ui/short-name

Definition of Done: works locally, tested on sample.eml, screenshot attached, PR reviewed.

Known Weaknesses (Honest)
Weakness	Priority
No OAuth live inbox (roadmap)	High for Grand Finale
No Hyperledger Fabric deployment	Medium
Charitha's UI improvements not merged	High (visual polish)
security_hardening.py uncommitted	High (blocks security claim)
Only 4/6 killer features fully in main	Medium
No PII masking in PDF yet	Medium (DPDP)
TRINETRA has stronger Indic NLP	Acknowledged, not blocking
What Makes PRAMAAN Unique
vs. Competitor	PRAMAAN Edge
TRINETRA	Live Sepolia blockchain anchor (they have none)
TraceMail AI	Honest dynamic geolocation (no hardcoded maps)
Dino Coders	Neo4j persistent graph (they use NetworkX)
Sentinel Mail	Real blockchain + OAuth roadmap
All 30+ repos	Real Merkle tree + on-chain TX + dual-anchor roadmap
End of Document