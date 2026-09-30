# report_html.py
"""HTML export for forensic reports."""

import datetime
import html


def _defang(value):
    if not value:
        return value
    v = str(value)
    v = v.replace("https://", "hxxps://").replace("http://", "hxxp://")
    v = v.replace(".", "[.]")
    return v


def _esc(value):
    return html.escape(str(value))


def _table(headers, rows):
    out = ["<table>", "<thead><tr>"]
    for h in headers:
        out.append("<th>" + _esc(h) + "</th>")
    out.append("</tr></thead><tbody>")
    for row in rows:
        out.append("<tr>")
        for cell in row:
            out.append("<td>" + cell + "</td>")
        out.append("</tr>")
    out.append("</tbody></table>")
    return "".join(out)


def generate_html_report(
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
    filename="forensic_report.html",
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

    if risk_score >= 65:
        score_class = "score-high"
    elif risk_score >= 35:
        score_class = "score-med"
    else:
        score_class = "score-low"

    css = """
    body { font-family: -apple-system, Segoe UI, Roboto, sans-serif;
           background: #f8fafc; color: #1e293b; margin: 0; padding: 24px; }
    .card { background: white; border: 1px solid #cbd5e1; border-radius: 8px;
            padding: 24px; max-width: 900px; margin: 0 auto; }
    h1 { font-size: 22px; color: #0f172a; margin: 0 0 4px 0; }
    h2 { font-size: 15px; color: #0f172a; border-bottom: 1px solid #e2e8f0;
         padding-bottom: 6px; margin-top: 24px; }
    .sub { color: #64748b; font-size: 12px; margin-bottom: 16px; }
    table { border-collapse: collapse; width: 100%; margin: 8px 0; font-size: 13px; }
    th { background: #e2e8f0; text-align: left; padding: 6px 8px;
         border: 1px solid #cbd5e1; }
    td { padding: 6px 8px; border: 1px solid #cbd5e1; vertical-align: top; }
    code { background: #f1f5f9; padding: 1px 4px; border-radius: 3px;
           font-family: Consolas, monospace; font-size: 12px; }
    .score-high { color: #ef4444; font-weight: bold; }
    .score-med  { color: #f59e0b; font-weight: bold; }
    .score-low  { color: #10b981; font-weight: bold; }
    .disclaimer { background: #fef2f2; border: 1px solid #ef4444;
                  border-radius: 6px; padding: 12px; color: #991b1b;
                  font-size: 12px; margin-top: 24px; }
    .footer { color: #94a3b8; font-size: 11px; margin-top: 16px;
              border-top: 1px solid #cbd5e1; padding-top: 8px; }
    """

    parts = []
    parts.append("<!DOCTYPE html>")
    parts.append("<html lang='en'><head><meta charset='utf-8'>")
    parts.append("<title>Forensic Report " + _esc(sha256_hash[:16]) + "</title>")
    parts.append("<style>" + css + "</style></head><body>")
    parts.append("<div class='card'>")

    parts.append("<h1>EML Forensics &amp; Threat Analysis Report</h1>")
    parts.append("<div class='sub'>Generated: " + _esc(now_str) + "</div>")

    parts.append("<h2>Executive Summary</h2>")
    summary_rows = [
        ["Overall Threat Score",
         "<span class='" + score_class + "'>" + str(risk_score) + "/100 ("
         + _esc(risk_level) + ")</span>"],
        ["Classification", _esc(classification or "-")],
        ["ML Phishing Probability", "{:.1f}%".format(ml_prob * 100)],
        ["File SHA-256", "<code>" + _esc(sha256_hash) + "</code>"],
        ["Merkle Root", "<code>" + _esc(merkle_root) + "</code>"],
    ]
    if blockchain_tx:
        summary_rows.append(["Blockchain TX", "<code>" + _esc(blockchain_tx) + "</code>"])
    if etherscan_url:
        summary_rows.append(
            ["Etherscan",
             "<a href='" + _esc(etherscan_url) + "'>" + _esc(etherscan_url) + "</a>"]
        )
    parts.append(_table(["Field", "Value"], summary_rows))

    if case_metadata:
        parts.append("<h2>Case Metadata</h2>")
        rows = [[_esc(k), _esc(v)] for k, v in case_metadata.items()]
        parts.append(_table(["Field", "Value"], rows))

    parts.append("<h2>1. Threat Factor Breakdown</h2>")
    if risk_factors:
        rows = []
        for f in risk_factors:
            rows.append([
                _esc(f.get("category", "")),
                "+" + str(f.get("points", 0)),
                _esc(f.get("description", "")),
            ])
        parts.append(_table(["Category", "Points", "Description"], rows))
    else:
        parts.append("<p>No major threat factors detected.</p>")

    parts.append("<h2>2. Key Email Headers</h2>")
    rows = [[_esc(k), _esc(v)] for k, v in headers_dict.items()]
    parts.append(_table(["Header Field", "Value"], rows))

    if auth_results:
        parts.append("<h2>3. Authentication Results</h2>")
        rows = [[_esc(k), _esc(v)] for k, v in auth_results.items()]
        parts.append(_table(["Mechanism", "Result"], rows))

    if relay_hops:
        parts.append("<h2>4. Relay Hop Timeline</h2>")
        rows = []
        for i, h in enumerate(relay_hops, 1):
            rows.append([
                str(i),
                _esc(h.get("host", "-")),
                _esc(h.get("ip", "-")),
                _esc(h.get("ts", "-")),
                _esc(h.get("trust", "-")),
            ])
        parts.append(_table(["#", "From Host", "IP", "Timestamp", "Trust"], rows))

    parts.append("<h2>5. Extracted IP Addresses &amp; Geolocation</h2>")
    if geo_data:
        rows = []
        for g in geo_data:
            if g.get("status") == "success":
                isp_asn = _esc(g.get("isp", "N/A")) + " (" + _esc(g.get("asn", "N/A")) + ")"
                rows.append([
                    _esc(g.get("ip", "")), "PUBLIC",
                    _esc(g.get("country", "N/A")),
                    _esc(g.get("city", "N/A")), isp_asn,
                ])
            else:
                rows.append([
                    _esc(g.get("ip", "")),
                    _esc(g.get("reason", "SKIPPED")),
                    "-", "-", "-",
                ])
        parts.append(_table(["IP Address", "Status", "Country", "City", "ISP / ASN"], rows))
    else:
        parts.append("<p>No IP addresses extracted.</p>")

    parts.append("<h2>6. Extracted URLs (defanged)</h2>")
    if urls:
        parts.append("<ol>")
        for u in urls:
            parts.append("<li><code>" + _esc(_defang(u)) + "</code></li>")
        parts.append("</ol>")
    else:
        parts.append("<p>No URLs extracted.</p>")

    if xai_weights:
        parts.append("<h2>7. XAI Weighted Breakdown</h2>")
        rows = []
        for w in xai_weights:
            rows.append([
                _esc(w.get("feature", "")),
                "{:.3f}".format(w.get("weight", 0)),
                _esc(w.get("direction", "")),
            ])
        parts.append(_table(["Feature", "Weight", "Direction"], rows))

    if contradictions:
        parts.append("<h2>8. Contradiction Alerts</h2><ul>")
        for c in contradictions:
            parts.append("<li>" + _esc(c) + "</li>")
        parts.append("</ul>")

    if custody_timeline:
        parts.append("<h2>9. Chain of Custody Timeline</h2>")
        rows = []
        for ev in custody_timeline:
            hash_or_note = ev.get("hash", ev.get("note", ""))
            rows.append([
                _esc(ev.get("event", "")),
                _esc(ev.get("actor", "")),
                _esc(ev.get("ts", "")),
                _esc(hash_or_note),
            ])
        parts.append(_table(["Event", "Actor", "Timestamp", "Hash / Note"], rows))

    parts.append(
        "<div class='disclaimer'><strong>LEGAL &amp; FORENSIC DISCLAIMER:</strong> "
        "This report is generated automatically based on static heuristics, regex "
        "analysis, and machine learning models. It is intended for educational, "
        "technical investigation, and security triage purposes. Verify all findings "
        "independently.</div>"
    )
    parts.append("<div class='footer'>CONFIDENTIAL - SOC / LEGAL HOLD</div>")

    parts.append("</div></body></html>")
    return "\n".join(parts)


def write_html_report(path, **kwargs):
    doc = generate_html_report(**kwargs)
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)