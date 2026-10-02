# PRAMAAN — Post-SIH Deployment Plan

**Problem Statement:** SIH26106 — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform
**Sponsoring Ministry:** AICTE Cyber Security Cell
**Team:** Team Apex (6 members)
**Institution:** Vemana Institute of Technology, Bengaluru
**Document version:** 1.0 — October 2026

---

## 1. Purpose

This document responds to Guideline 4 of the SIH deployment framework: a detailed project plan covering implementation, tools, expert support, and timelines for the 6-month development phase of PRAMAAN after the Grand Finale.

It is written for ministry reviewers and mentors.

---

## 2. Current State (as of October 2026)

PRAMAAN is a working forensic-grade email investigation platform. The following components are functional on `main`:

| Capability | Module | Status |
|---|---|---|
| MIME parsing + RFC 5322 compliance | `api.py` | Shipped |
| SPF / DKIM / DMARC / ARC header parsing | `api.py` | Shipped |
| Live DNS authentication verification | `backend/detection/auth_check.py` | Shipped |
| ML phishing classifier (TF-IDF + LogReg) | `model.py` | Shipped |
| XAI contradiction detection engine | `xai_engine.py` | Shipped |
| Typosquat and homoglyph detection (114 Indian brands) | `backend/typosquat/` | Shipped |
| QR code / quishing detection | `backend/detection/media_parser.py` | In progress |
| Font obfuscation detection (glyph substitution) | `backend/detection/font_forensics.py` | Shipped |
| Thread hijacking detection | `backend/detection/thread_hijack.py` | Shipped |
| URL redirect chain tracing | `threat_intel.py` | Shipped |
| Parallel GeoIP + ASN enrichment | `threat_intel.py` | Shipped |
| Multi-hop relay path visualisation | `app.py`, `graph_engine.py` | Shipped |
| 9-engine threat intel aggregator | `backend/intel/` | Shipped |
| Neo4j campaign correlation | `neo4j_engine.py` | Shipped |
| SHA-256 + Merkle evidence proof | `zkfv.py` | Shipped |
| Solidity anchor on Ethereum Sepolia | `blockchain/` | Shipped |
| Multi-format reports (PDF, HTML, MD, STIX 2.1) | `report_*.py` | Shipped |
| PII masking for DPDP Act 2023 | `backend/reporting/pii_mask.py` | Shipped |
| Authentication + analyst/citizen roles | `backend/auth/` | Shipped |
| Security hardening (zip bombs, MIME recursion, prompt injection) | `security_hardening.py` | Shipped |

**Known limitations** (documented in README):

- No OAuth 2.0 live inbox integration
- No Hyperledger Fabric production chain
- SQLite used in demo; PostgreSQL not yet migrated
- ML classifier trained on ~50 samples; needs larger corpus
- No multi-tenant support

---

## 3. Gap Analysis — What Is Missing for Production

To move PRAMAAN from hackathon prototype to deployable tool for CERT-In and state cyber cells, the following work is required:

### 3.1 Data Layer
- Migrate SQLite → PostgreSQL 16 with row-level security
- Add Redis for session/cache layer
- Set up S3-compatible blob storage for raw `.eml` evidence retention
- Implement retention policy (configurable per DPDP Act 2023)

### 3.2 Authentication & Multi-Tenancy
- OAuth 2.0 integration for Microsoft 365 and Gmail
- Multi-tenant isolation (per-agency data separation)
- Role-based access control (analyst, senior analyst, admin, citizen)
- Hardware-backed key storage for blockchain signer keys

### 3.3 Detection Quality
- Retrain ML classifier on 10,000+ labelled samples (CERT-In advisories + public corpora)
- Add Hindi, Kannada, Tamil, Telugu phishing corpora
- Expand typosquat brand list beyond 114 to 500+
- Add attachment forensics (VBA macro, embedded JS in PDF)

### 3.4 Blockchain & Legal
- Deploy on Hyperledger Fabric permissioned chain for enterprise use
- Maintain Sepolia anchor as public verifiability layer
- Work with legal counsel on BSA 2023 Section 63(4) certification workflow
- Obtain digital signature from forensic examiner per report

### 3.5 Operations
- Docker Compose → Kubernetes Helm chart
- Prometheus + Grafana monitoring
- Structured logging with OpenTelemetry
- Backup/disaster recovery runbook
- SLI/SLO definitions

---

## 4. Six-Month Roadmap

### Month 1 — Foundation (Nov 2026)
| Week | Deliverable |
|------|-------------|
| 1 | Onboard ministry mentor; scope alignment; sign institution consent letter |
| 2 | PostgreSQL migration complete; CI extended to run against Postgres |
| 3 | Redis cache layer added; latency benchmarked at ≤ 8 s per email |
| 4 | OAuth 2.0 prototype for M365 (read-only mailbox); security review |

### Month 2 — Detection Depth (Dec 2026)
| Week | Deliverable |
|------|-------------|
| 5 | Attachment forensics module (VBA, PDF JS, double extensions) |
| 6 | Multi-language corpus assembled; retraining begins |
| 7 | Threat intel aggregator integrated with all 9 feeds (currently mocked) |
| 8 | Detection accuracy audit; false positive rate measured |

### Month 3 — Scale (Jan 2027)
| Week | Deliverable |
|------|-------------|
| 9 | Multi-tenant data isolation in PostgreSQL with row-level security |
| 10 | RBAC roles implemented; audit log per action |
| 11 | Kubernetes Helm chart; staging deployment on ministry cloud |
| 12 | Load test: 1,000 emails/hour sustained |

### Month 4 — Blockchain Production (Feb 2027)
| Week | Deliverable |
|------|-------------|
| 13 | Hyperledger Fabric network deployed (2 orgs, 4 peers) |
| 14 | Dual-anchor flow: Sepolia (public) + Fabric (permissioned) |
| 15 | HSM integration for signer key custody |
| 16 | Evidence integrity audit by external cybersecurity expert |

### Month 5 — Pilot (Mar 2027)
| Week | Deliverable |
|------|-------------|
| 17 | Pilot onboarding with 1 state cyber cell (target: Karnataka or Telangana) |
| 18 | User training sessions; SOP documentation |
| 19 | First 100 real investigations logged |
| 20 | Feedback-driven iteration; incident log review |

### Month 6 — Handover & Publication (Apr 2027)
| Week | Deliverable |
|------|-------------|
| 21 | CERT-In integration documentation |
| 22 | BSA 2023 Section 63(4) compliance review with legal counsel |
| 23 | Academic paper submission (IEEE or Springer security venue) |
| 24 | Final deployment report to MIC/AICTE |

---

## 5. Resource Requirements

### 5.1 Software Licences
| Item | Purpose | Est. cost |
|------|---------|-----------|
| MaxMind GeoLite2 Commercial | Accurate GeoIP at scale | $400/year |
| VirusTotal Enterprise (optional) | Higher API quota | Quote-based |
| AbuseIPDB Premium | Higher API quota | $100/month |
| Let's Encrypt / ACM | TLS certificates | Free |
| PostgreSQL + Redis + Neo4j | Self-hosted on ministry cloud | Free (OSS) |

### 5.2 Hardware
| Item | Purpose | Est. cost |
|------|---------|-----------|
| Cloud VM (16 vCPU, 64 GB RAM, 500 GB SSD) | App + DB hosting | ₹15,000/month |
| YubiHSM 2 (×2) | Blockchain signer key custody | ₹45,000 each |
| Backup storage (S3-compatible) | Evidence retention | ₹3,000/month |

### 5.3 Expert Support
| Role | Purpose | Commitment |
|------|---------|------------|
| Cybersecurity mentor (ministry-assigned) | Weekly review, threat landscape guidance | 4 hrs/week |
| Faculty co-mentor (Vemana) | Coordination, project continuity | 2 hrs/week |
| Legal counsel (BSA 2023) | Section 63(4) compliance workflow | 20 hrs total |
| DNS/email security expert | SPF/DKIM/DMARC at scale guidance | 10 hrs total |

---

## 6. Success Metrics

| Metric | Baseline (Oct 2026) | Target (Apr 2027) |
|--------|---------------------|-------------------|
| Detection precision (phishing corpus) | ~85% | ≥ 95% |
| False positive rate | ~10% | ≤ 3% |
| End-to-end analysis latency | ~6 s | ≤ 3 s |
| Email throughput | ~100/hour | 1,000/hour |
| Campaign correlation latency (Neo4j) | ~500 ms | ≤ 200 ms |
| Blockchain anchor latency | 10–15 s (Sepolia) | ≤ 5 s (Fabric) |
| Languages supported | English | English + 4 Indian |
| Automated tests passing | 57 | 150+ |

---

## 7. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Team members graduate / get jobs | High | High | Documented handover; 2 replacement slots pre-approved per SIH guideline |
| Ministry mentor unavailable | Medium | Medium | Faculty co-mentor as backup |
| API rate limits on threat intel | Medium | Low | 30-day LRU cache; local MaxMind fallback |
| Sepolia testnet deprecation | Low | Medium | Dual-anchor to Hyperledger Fabric already planned |
| Legal admissibility challenge | Medium | High | Engage BSA 2023 counsel early; produce metadata-only evidence |
| Cloud hosting budget overrun | Medium | Medium | Start with 1 VM; scale horizontally only on demand |

---

## 8. Team Commitment

All six members of Team Apex commit to:

- Minimum 15 hours/week each during the 6-month deployment
- Weekly progress report to assigned mentor
- In-person visits to ministry site as required
- Quarterly written status report to MIC/AICTE (per Guideline 15)

**Replacement policy:** Per SIH guidelines, if a member graduates or leaves, Team Apex will nominate a replacement from Vemana Institute of Technology within 15 days. The replacement will be onboarded with a 1-week shadow period.

---

## 9. Compliance

- **DPDP Act 2023:** PII masking in all exported reports; configurable retention
- **BSA 2023 Section 63(4):** Cryptographic chain of custody (SHA-256 + Merkle root + on-chain anchor)
- **IT Act 2000:** All evidence handling follows CERT-In empanelment guidelines
- **Open Source:** All dependencies MIT/BSD/Apache licensed; declared in [IP_NOTICE.md](../IP_NOTICE.md)

---

## 10. Contact

**Team Lead:** Mayur Anand — mayuranand.cys2025@vemanait.edu.in
**Institution:** Vemana Institute of Technology, Bengaluru
**Repository:** https://github.com/mayur-anand-cys/pramaan-sih26106

---

*This document is a living plan and will be revised monthly with the assigned ministry mentor.*
