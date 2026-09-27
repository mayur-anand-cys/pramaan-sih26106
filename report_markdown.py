# report_markdown.py
"""Markdown export for forensic reports."""

import datetime


def _defang(value):
    if not value:
        return value
    v = str(value)
    v = v.replace("https://", "hxxps://").replace("http://", "hxxp://")
    v = v.replace(".", "[.]")
    return v


def generate_markdown_report(
    sha256_hash,
    risk_score,
    risk_level,
    headers_dict,
    urls,
    ips,
    geo_data,
    risk_factors,
    ml_prob,
    merkle_root,
    filename="forensic_report.md",
    case_metadata=None,
    auth_results=None,
    relay_hops=None,
    xai_weights=None,
    contradictions=None,
    blockchain_tx="",
    etherscan_url="",
    custody_timeline=None,
    classification="",
):
    case_metadata = case_metadata or {}
    auth_results = auth_results or {}
    relay_hops = relay_hops or []
    xai_weights = xai_weights or []
    contradictions = contradictions or []
    custody_timeline = custody_timeline or []

    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    dash = "-"

    lines = []
    lines.append("# EML Forensics & Threat Analysis Report")
    lines.append("")
    lines.append("**Generated:** " + now_str)
    lines.append("")
    lines.append("**Target SHA-256:** `" + sha256_hash + "`")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append("| Overall Threat Score | **" + str(risk_score) + "/100 (" + str(risk_level) + ")** |")
    lines.append("| Classification | " + (classification or dash) + " |")
    lines.append("| ML Phishing Probability | " + "{:.1f}%".format(ml_prob * 100) + " |")
    lines.append("| File SHA-256 | `" + sha256_hash + "` |")
    lines.append("| Merkle Root | `" + merkle_root + "` |")
    if blockchain_tx:
        lines.append("| Blockchain TX | `" + blockchain_tx + "` |")
    if etherscan_url:
        lines.append("| Etherscan | " + etherscan_url + " |")
    lines.append("")

    if case_metadata:
        lines.append("## Case Metadata")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|---|---|")
        for k, v in case_metadata.items():
            lines.append("| " + str(k) + " | " + str(v) + " |")
        lines.append("")

    lines.append("## 1. Threat Factor Breakdown")
    lines.append("")
    if risk_factors:
        lines.append("| Category | Points | Description |")
        lines.append("|---|---|---|")
        for f in risk_factors:
            lines.append(
                "| " + str(f.get("category", ""))
                + " | +" + str(f.get("points", 0))
                + " | " + str(f.get("description", "")) + " |"
            )
    else:
        lines.append("_No major threat factors detected._")
    lines.append("")

    lines.append("## 2. Key Email Headers")
    lines.append("")
    lines.append("| Header Field | Value |")
    lines.append("|---|---|")
    for k, v in headers_dict.items():
        lines.append("| **" + str(k) + "** | " + str(v) + " |")
    lines.append("")

    if auth_results:
        lines.append("## 3. Authentication Results")
        lines.append("")
        lines.append("| Mechanism | Result |")
        lines.append("|---|---|")
        for k, v in auth_results.items():
            lines.append("| " + str(k) + " | " + str(v) + " |")
        lines.append("")

    if relay_hops:
        lines.append("## 4. Relay Hop Timeline")
        lines.append("")
        lines.append("| # | From Host | IP | Timestamp | Trust |")
        lines.append("|---|---|---|---|---|")
        for i, h in enumerate(relay_hops, 1):
            lines.append(
                "| " + str(i)
                + " | " + str(h.get("host", dash))
                + " | " + str(h.get("ip", dash))
                + " | " + str(h.get("ts", dash))
                + " | " + str(h.get("trust", dash)) + " |"
            )
        lines.append("")

    lines.append("## 5. Extracted IP Addresses & Geolocation")
    lines.append("")
    if geo_data:
        lines.append("| IP Address | Status | Country | City | ISP / ASN |")
        lines.append("|---|---|---|---|---|")
        for g in geo_data:
            if g.get("status") == "success":
                isp_asn = str(g.get("isp", "N/A")) + " (" + str(g.get("asn", "N/A")) + ")"
                lines.append(
                    "| " + str(g.get("ip", ""))
                    + " | PUBLIC | " + str(g.get("country", "N/A"))
                    + " | " + str(g.get("city", "N/A"))
                    + " | " + isp_asn + " |"
                )
            else:
                lines.append(
                    "| " + str(g.get("ip", ""))
                    + " | " + str(g.get("reason", "SKIPPED"))
                    + " | " + dash + " | " + dash + " | " + dash + " |"
                )
    else:
        lines.append("_No IP addresses extracted._")
    lines.append("")

    lines.append("## 6. Extracted URLs (defanged)")
    lines.append("")
    if urls:
        for idx, u in enumerate(urls, 1):
            lines.append(str(idx) + ". `" + _defang(u) + "`")
    else:
        lines.append("_No URLs extracted._")
    lines.append("")

    if xai_weights:
        lines.append("## 7. XAI Weighted Breakdown")
        lines.append("")
        lines.append("| Feature | Weight | Direction |")
        lines.append("|---|---|---|")
        for w in xai_weights:
            lines.append(
                "| " + str(w.get("feature", ""))
                + " | " + "{:.3f}".format(w.get("weight", 0))
                + " | " + str(w.get("direction", "")) + " |"
            )
        lines.append("")

    if contradictions:
        lines.append("## 8. Contradiction Alerts")
        lines.append("")
        for c in contradictions:
            lines.append("- " + str(c))
        lines.append("")

    if custody_timeline:
        lines.append("## 9. Chain of Custody Timeline")
        lines.append("")
        lines.append("| Event | Actor | Timestamp | Hash / Note |")
        lines.append("|---|---|---|---|")
        for ev in custody_timeline:
            hash_or_note = ev.get("hash", ev.get("note", ""))
            lines.append(
                "| " + str(ev.get("event", ""))
                + " | " + str(ev.get("actor", ""))
                + " | " + str(ev.get("ts", ""))
                + " | " + str(hash_or_note) + " |"
            )
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "**LEGAL & FORENSIC DISCLAIMER:** This report is generated automatically "
        "based on static heuristics, regex analysis, and machine learning models. "
        "It is intended for educational, technical investigation, and security "
        "triage purposes. Verify all findings independently."
    )
    lines.append("")

    return "\n".join(lines)


def write_markdown_report(path, **kwargs):
    md = generate_markdown_report(**kwargs)
    with open(path, "w", encoding="utf-8") as f:
        f.write(md)
