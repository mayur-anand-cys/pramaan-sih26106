# PRAMAAN — 4-Minute Grand Finale Demo Script

**Issue:** #14
**Target runtime:** 4:00 (hard cap)
**Speakers:** Speaker 1 (Lead, narrator) · Speaker 2 (Operator, clicks through UI)

---

## Pre-demo checklist

Run this 5 minutes before going on stage.

- [ ] **Terminal 1** — API server: `uvicorn api:app --reload --port 8000`
- [ ] **Terminal 2** — Streamlit app: `streamlit run app.py`
- [ ] **Browser** — open `http://localhost:8501` (full screen, hidden tabs)
- [ ] **Terminal 3** — `TEST_FILE=demo_emails/demo_phish.eml` *(placeholder — see Open Questions)*
- [ ] **DEMO_MODE** env var is set to `true` (offline fallback ready)
- [ ] **Backup video** loaded on a separate device (offline)
- [ ] **Slides** (if any) queued behind the browser
- [ ] **Wi-Fi** tested once — if unstable, run demo with demo-mode on
- [ ] **Phone** muted, notifications off
- [ ] **Both speakers** know their cues

---

## Cast and cues

| Cue | Speaker | Action |
|---|---|---|
| **S1** | Lead | Speaks. Controls the narrative. Never touches the keyboard. |
| **S2** | Operator | Clicks. Types. Uploads. Follows S1's lead. |

**Rule:** S1 and S2 never talk at the same time. S1 finishes a sentence → S2 clicks → S1 continues.

---

## Script (240 seconds total)

### [0:00–0:15] Hook — S1

> **S1:** "24 teams entered this competition. Every one of them built a phishing
> detector. Not one of them can tell you *who* an attacker is, *which* campaign
> they belong to, or *how* to prove it in court."
>
> "We can. This is PRAMAAN."

**On screen:** Landing page. Nothing clicked yet.  
**Tone:** Calm, confident. Not rushed.

---

### [0:15–0:35] Upload a phishing email — S1 + S2

> **S1:** "This is a real phishing email. Paypal impersonation. Watch what
> happens in the first second."

**S2:** Upload `demo_emails/demo_phish.eml`.  
**On screen:** SHA-256 fingerprint + Merkle root appear in the header.

> **S1:** "SHA-256 fingerprint. Merkle root. This email is now immutable —
> anchored on chain in 30 seconds."

*[Placeholder — if Mayur confirms a CEO fraud file, this becomes "CEO impersonation. Our CEO." ]*

---

### [0:35–1:00] Live DNS SPF/DKIM/DMARC — S2

> **S1:** "While you watched, PRAMAAN called DNS. Live."

**S2:** Click **Tab 1 → Email Authentication** section.

> **S1:** "SPF: FAIL. DKIM: FAIL. DMARC: FAIL. The email claims to be from
> PayPal. The DNS says it isn't. That contradiction is the entire point."

**On screen:** Three red FAIL badges, plus the auth check results.

---

### [1:00–1:25] Neo4j campaign graph — S2

> **S1:** "Is this email alone? Or is it part of something bigger?"

**S2:** Click **Tab 4 → Campaign Graph**.

> **S1:** "Neo4j — a persistent graph database. 24 other emails share this
> infrastructure. They share the same domain. The same IP. The same
> sending pattern. This isn't a phishing email. It's campaign CAMP-0001."

**On screen:** Graph with central node highlighted, linked nodes fanning out.

---

### [1:25–1:55] 9-engine threat intel — S2

> **S1:** "What do the threat intel engines know about this domain?"

**S2:** Click **Tab 3 → Threat Intelligence**.

> **S1:** "Nine engines. RDAP, WHOIS, VirusTotal, URLScan, DNS resolver, reverse
> IP, SSL cert, subdomain scan, and our own typosquat detector. All queried in
> parallel. All back in under two seconds."

**On screen:** Grid of 9 results, mostly red.

---

### [1:55–2:20] XAI contradiction alert — S2

> **S1:** "The ML model says 92% phishing. The authentication says the domain
> is legitimate. Those disagree. So PRAMAAN flags it — for a human."

**S2:** Click **Tab 1 → Contradiction Alert**.

> **S1:** "Traditional phishing detectors average the signals. PRAMAAN refuses
> to. When two engines disagree, we surface the conflict to an analyst instead
> of hiding it."

**On screen:** Yellow alert box: *"Contradiction detected: ML classifies as phishing, authentication passes."*

---

### [2:20–2:45] Blockchain anchor — S2

> **S1:** "The evidence is now anchored on chain."

**S2:** Click **Tab 2 → Verify Cryptographic Proof**. Show Sepolia TX hash.

> **S1:** "Sepolia testnet. Here's the transaction. Here's the block. Here's
> the timestamp. If anyone edits this evidence — even one byte — the Merkle
> root changes. Detection becomes trivial."

**On screen:** Sepolia Etherscan link, TX hash visible.

---

### [2:45–3:10] PDF forensic report — S2

> **S1:** "For a court case, you need more than a hash. You need chain of
> custody, standard compliance, and a report a non-technical judge can read."

**S2:** Click **Download PDF Report**.

> **S1:** "One click. Court-ready under BSA 2023 and IT Act Section 65B.
> Contains the evidence hash, the chain of custody, the analyst's findings,
> and every external reference we cited."

**On screen:** PDF opens showing the report structure.

---

### [3:10–3:35] Test Console — S2

> **S1:** "For our judges who want to try it themselves — one more thing."

**S2:** *[Placeholder — Test Console demo. Exact UI TBD per Mayur's answer.]*

> **S1:** "Every CEO fraud variant you can throw at it gets classified,
> attributed, and anchored the same way."

*[Placeholder — replace once Mayur confirms what "Test Console" refers to.]*

---

### [3:35–4:00] Close — S1

> **S1:** "Other teams built detectors. We built a forensic platform.
> Attribution. Evidence. Prosecution."
>
> "PRAMAAN. Thank you."

**On screen:** Landing page with team names visible.  
**Tone:** Slow down. Land every word. **Do not rush the close.**

---

## Backup plan — if Wi-Fi dies

1. **DEMO_MODE is on.** The app falls back to seed data automatically.
2. **Narrate over it:** *"Wi-Fi just died — that's fine, we're in demo mode."*
   Keep moving. The judge cares about the story, not the network.
3. **If the app itself crashes:** switch to the **backup video**. Play it.
   Narrate over it live. Do not apologise.

---

## Rehearsal notes

- **Rehearse 3 times minimum.** Time each run.
- **Cut any sentence over 12 words.** Long sentences eat time.
- **Practise the transitions.** The script has 8 "S1 → S2 → S1" swaps.
  Each swap costs ~1 second. Nail them.
- **Do NOT read the screen.** Point at it. The script is what you say, not what's on screen.
- **Practise the close separately.** It's the line judges remember.

---

## Open questions (to resolve with Mayur)

1. **Step 2 file:** Demo emails folder contains `demo_clean.eml`, `demo_phish.eml`,
   `demo_phish_2.eml`, `demo_spoofed_ip.eml` — no CEO fraud file. Do we
   (a) create `demo_ceo_fraud.eml`, (b) reuse `demo_phish.eml`, or
   (c) point at a different file?
2. **Step 9 Test Console:** Not found in `app.py`. Is it called something else,
   in a different file, or not yet built?

---

*Drafted for issue #14. Update once Mayur confirms the two open questions.*