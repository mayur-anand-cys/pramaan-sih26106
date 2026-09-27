# report_gen.py
import io
import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from report_canvas import NumberedCanvas


def _defang(value: str) -> str:
    """Defang URLs / IPs for safe reporting."""
    if not value:
        return value
    v = str(value)
    v = v.replace("https://", "hxxps://").replace("http://", "hxxp://")
    v = v.replace(".", "[.]")
    return v


def generate_pdf_report(
    sha256_hash: str,
    risk_score: int,
    risk_level: str,
    headers_dict: dict,
    urls: list,
    ips: list,
    geo_data: list,
    risk_factors: list,
    ml_prob: float,
    merkle_root: str,
    filename: str = "forensic_report.pdf",
    # ---- new optional fields (safe defaults; existing callers unaffected) ----
    case_metadata: dict = None,
    auth_results: dict = None,
    relay_hops: list = None,
    xai_weights: list = None,
    contradictions: list = None,
    blockchain_tx: str = "",
    etherscan_url: str = "",
    custody_timeline: list = None,
    classification: str = "",
) -> bytes:
    """Generate a comprehensive forensic PDF report using reportlab."""

    case_metadata = case_metadata or {}
    auth_results = auth_results or {}
    relay_hops = relay_hops or []
    xai_weights = xai_weights or []
    contradictions = contradictions or []
    custody_timeline = custody_timeline or []

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=52,  # leave room for footer
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle', parent=styles['Heading1'], fontSize=20, leading=24,
        textColor=colors.HexColor('#1E293B'), spaceAfter=6
    )
    sub_title_style = ParagraphStyle(
        'DocSubTitle', parent=styles['Normal'], fontSize=10,
        textColor=colors.HexColor('#64748B'), spaceAfter=15
    )
    h2_style = ParagraphStyle(
        'SectionH2', parent=styles['Heading2'], fontSize=13, leading=16,
        textColor=colors.HexColor('#0F172A'), spaceBefore=12, spaceAfter=6
    )
    body_style = ParagraphStyle(
        'BodyTextCustom', parent=styles['Normal'], fontSize=9, leading=12,
        textColor=colors.HexColor('#334155')
    )
    disclaimer_style = ParagraphStyle(
        'DisclaimerText', parent=styles['Normal'], fontSize=8, leading=11,
        textColor=colors.HexColor('#991B1B')
    )

    elements = []

    # ---------- Title ----------
    elements.append(Paragraph("<b>EML Forensics & Threat Analysis Report</b>", title_style))
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    elements.append(Paragraph(
        f"Generated: {now_str} | Target File SHA-256: <code>{sha256_hash[:16]}...</code>",
        sub_title_style
    ))

    # ---------- Executive Summary card ----------
    if risk_score >= 65:
        score_color = colors.HexColor('#EF4444')
    elif risk_score >= 35:
        score_color = colors.HexColor('#F59E0B')
    else:
        score_color = colors.HexColor('#10B981')

    summary_rows = [
        [Paragraph("<b>Overall Threat Score:</b>", body_style),
         Paragraph(f"<font color='{score_color.hexval()}'><b>{risk_score}/100 ({risk_level})</b></font>", body_style)],
        [Paragraph("<b>Classification:</b>", body_style),
         Paragraph(classification or "—", body_style)],
        [Paragraph("<b>ML Phishing Probability:</b>", body_style),
         Paragraph(f"<b>{ml_prob * 100:.1f}%</b>", body_style)],
        [Paragraph("<b>File SHA-256 Hash:</b>", body_style),
         Paragraph(f"<code>{sha256_hash}</code>", body_style)],
        [Paragraph("<b>Merkle Root Hash:</b>", body_style),
         Paragraph(f"<code>{merkle_root}</code>", body_style)],
    ]
    if blockchain_tx:
        summary_rows.append([Paragraph("<b>Blockchain TX:</b>", body_style),
                             Paragraph(f"<code>{blockchain_tx}</code>", body_style)])
    if etherscan_url:
        summary_rows.append([Paragraph("<b>Etherscan:</b>", body_style),
                             Paragraph(f'<link href="{etherscan_url}">{etherscan_url}</link>', body_style)])

    summary_table = Table(summary_rows, colWidths=[150, 390])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 10))

    # ---------- Case Metadata ----------
    if case_metadata:
        elements.append(Paragraph("<b>Case Metadata</b>", h2_style))
        meta_rows = [["Field", "Value"]]
        for k, v in case_metadata.items():
            meta_rows.append([Paragraph(f"<b>{k}</b>", body_style),
                              Paragraph(str(v), body_style)])
        meta_table = Table(meta_rows, colWidths=[140, 400])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E2E8F0')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('PADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 10))

    # ---------- 1. Threat Factors ----------
    elements.append(Paragraph("<b>1. Threat Factor Breakdown</b>", h2_style))
    if risk_factors:
        factors_data = [["Category", "Points", "Description"]]
        for f in risk_factors:
            factors_data.append([
                Paragraph(f.get("category", ""), body_style),
                Paragraph(f"+{f.get('points', 0)}", body_style),
                Paragraph(f.get("description", ""), body_style),
            ])
        factors_table = Table(factors_data, colWidths=[130, 50, 360])
        factors_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E2E8F0')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(factors_table)
    else:
        elements.append(Paragraph("No major threat factors detected.", body_style))
    elements.append(Spacer(1, 10))

    # ---------- 2. Email headers ----------
    elements.append(Paragraph("<b>2. Key Email Headers</b>", h2_style))
    header_rows = [["Header Field", "Value"]]
    for k, v in headers_dict.items():
        header_rows.append([Paragraph(f"<b>{k}</b>", body_style),
                            Paragraph(str(v), body_style)])
    headers_table = Table(header_rows, colWidths=[120, 420])
    headers_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E2E8F0')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    elements.append(headers_table)
    elements.append(Spacer(1, 10))

    # ---------- 3. Authentication results ----------
    if auth_results:
        elements.append(Paragraph("<b>3. Authentication Results (SPF / DKIM / DMARC / ARC)</b>", h2_style))
        auth_rows = [["Mechanism", "Result"]]
        for k, v in auth_results.items():
            auth_rows.append([Paragraph(f"<b>{k}</b>", body_style),
                              Paragraph(str(v), body_style)])
        auth_table = Table(auth_rows, colWidths=[140, 400])
        auth_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E2E8F0')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(auth_table)
        elements.append(Spacer(1, 10))

    # ---------- 4. Relay hop timeline ----------
    if relay_hops:
        elements.append(Paragraph("<b>4. Relay Hop Timeline</b>", h2_style))
        hop_rows = [["#", "From Host", "IP", "Timestamp", "Trust"]]
        for i, h in enumerate(relay_hops, 1):
            hop_rows.append([
                Paragraph(str(i), body_style),
                Paragraph(str(h.get("host", "—")), body_style),
                Paragraph(str(h.get("ip", "—")), body_style),
                Paragraph(str(h.get("ts", "—")), body_style),
                Paragraph(str(h.get("trust", "—")), body_style),
            ])
        hop_table = Table(hop_rows, colWidths=[25, 150, 110, 155, 100])
        hop_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E2E8F0')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(hop_table)
        elements.append(Spacer(1, 10))

    # ---------- 5. IPs + geolocation ----------
    elements.append(Paragraph("<b>5. Extracted IP Addresses & Geolocation</b>", h2_style))
    if geo_data:
        geo_rows = [["IP Address", "Status", "Country", "City", "ISP / ASN"]]
        for g in geo_data:
            if g.get("status") == "success":
                isp_asn = f"{g.get('isp', 'N/A')} ({g.get('asn', 'N/A')})"
                geo_rows.append([
                    Paragraph(g.get("ip", ""), body_style),
                    Paragraph("PUBLIC", body_style),
                    Paragraph(g.get("country", "N/A"), body_style),
                    Paragraph(g.get("city", "N/A"), body_style),
                    Paragraph(isp_asn, body_style),
                ])
            else:
                geo_rows.append([
                    Paragraph(g.get("ip", ""), body_style),
                    Paragraph(g.get("reason", "SKIPPED"), body_style),
                    Paragraph("—", body_style),
                    Paragraph("—", body_style),
                    Paragraph("—", body_style),
                ])
        geo_table = Table(geo_rows, colWidths=[100, 80, 100, 100, 160])
        geo_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E2E8F0')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(geo_table)
    else:
        elements.append(Paragraph("No IP addresses extracted.", body_style))
    elements.append(Spacer(1, 10))

    # ---------- 6. URLs (defanged) ----------
    elements.append(Paragraph("<b>6. Extracted URLs (defanged)</b>", h2_style))
    if urls:
        url_rows = [["#", "Extracted URL"]]
        for idx, u in enumerate(urls, 1):
            url_rows.append([Paragraph(str(idx), body_style),
                             Paragraph(f"<code>{_defang(u)}</code>", body_style)])
        url_table = Table(url_rows, colWidths=[30, 510])
        url_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E2E8F0')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(url_table)
    else:
        elements.append(Paragraph("No URLs extracted.", body_style))
    elements.append(Spacer(1, 10))

    # ---------- 7. XAI weighted breakdown ----------
    if xai_weights:
        elements.append(Paragraph("<b>7. XAI Weighted Breakdown</b>", h2_style))
        xai_rows = [["Feature", "Weight", "Direction"]]
        for w in xai_weights:
            xai_rows.append([
                Paragraph(str(w.get("feature", "")), body_style),
                Paragraph(f"{w.get('weight', 0):.3f}", body_style),
                Paragraph(str(w.get("direction", "")), body_style),
            ])
        xai_table = Table(xai_rows, colWidths=[280, 100, 160])
        xai_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E2E8F0')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(xai_table)
        elements.append(Spacer(1, 10))

    # ---------- 8. Contradiction alerts ----------
    if contradictions:
        elements.append(Paragraph("<b>8. Contradiction Alerts</b>", h2_style))
        for c in contradictions:
            elements.append(Paragraph(f"• {c}", body_style))
        elements.append(Spacer(1, 10))

    # ---------- 9. Chain of custody ----------
    if custody_timeline:
        elements.append(Paragraph("<b>9. Chain of Custody Timeline</b>", h2_style))
        cc_rows = [["Event", "Actor", "Timestamp", "Hash / Note"]]
        for ev in custody_timeline:
            cc_rows.append([
                Paragraph(str(ev.get("event", "")), body_style),
                Paragraph(str(ev.get("actor", "")), body_style),
                Paragraph(str(ev.get("ts", "")), body_style),
                Paragraph(str(ev.get("hash", ev.get("note", ""))), body_style),
            ])
        cc_table = Table(cc_rows, colWidths=[110, 100, 150, 180])
        cc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E2E8F0')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(cc_table)
        elements.append(Spacer(1, 15))

    # ---------- Legal disclaimer ----------
    disclaimer_box = [[Paragraph(
        "<b>LEGAL & FORENSIC DISCLAIMER:</b> This report is generated automatically based on "
        "static heuristics, regex analysis, and machine learning models. It is intended for "
        "educational, technical investigation, and security triage purposes. Verify all findings "
        "independently.",
        disclaimer_style
    )]]
    disclaimer_table = Table(disclaimer_box, colWidths=[540])
    disclaimer_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#FEF2F2')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#EF4444')),
        ('PADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(KeepTogether([disclaimer_table]))

    doc.build(elements, canvasmaker=NumberedCanvas)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes