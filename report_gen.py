import io
import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
try:
    from blockchain.anchor import anchor_evidence
except ImportError:
    anchor_evidence = None


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
    case_id: str = "PRAMAAN-AUTO",
    analyst: str = "Sneha Namrath",
    filename: str = "forensic_report.pdf"
) -> bytes:
    """Generate a comprehensive forensic PDF report using reportlab."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#1E293B'),
        spaceAfter=6
    )

    sub_title_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#64748B'),
        spaceAfter=15
    )

    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading2'],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#0F172A'),
        spaceBefore=12,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['Normal'],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#334155')
    )

    disclaimer_style = ParagraphStyle(
        'DisclaimerText',
        parent=styles['Normal'],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#991B1B')
    )

    elements = []

    # Title & Subtitle
    elements.append(Paragraph("<b>EML Forensics & Threat Analysis Report</b>", title_style))
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    elements.append(Paragraph(f"Generated: {now_str} | Target File SHA-256: <code>{sha256_hash[:16]}...</code>", sub_title_style))
        # ---- Executive Summary ----
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("<b>Executive Summary</b>", h2_style))

    verdict_word = "potentially malicious" if risk_score >= 65 else ("suspicious" if risk_score >= 35 else "likely benign")
    exec_summary = (
        f"This report presents a forensic analysis of the submitted email file. "
        f"The email was assessed as <b>{verdict_word}</b> with a threat score of "
        f"<b>{risk_score}/100</b> ({risk_level}). "
    )

    if urls:
        exec_summary += f"A total of <b>{len(urls)}</b> URL(s) and "
    else:
        exec_summary += "No URLs and "

    if ips:
        exec_summary += f"<b>{len(ips)}</b> IP address(es) were extracted for review. "
    else:
        exec_summary += "no IP addresses were extracted. "

    if risk_factors:
        exec_summary += "The primary risk contributors are listed in the Threat Factor Breakdown below. "

    exec_summary += (
        f"All findings are timestamped and cryptographically anchored "
        f"(Merkle root: <code>{merkle_root[:16]}...</code>) for verification."
    )

    elements.append(Paragraph(exec_summary, body_style))
    elements.append(Spacer(1, 10))
    # ---- End Executive Summary ----

    # Executive Summary Card Table
    if risk_score >= 65:
        score_color = colors.HexColor('#EF4444')
    elif risk_score >= 35:
        score_color = colors.HexColor('#F59E0B')
    else:
        score_color = colors.HexColor('#10B981')

    summary_table_data = [
        [
            Paragraph("<b>Overall Threat Score:</b>", body_style),
            Paragraph(f"<font color='{score_color.hexval()}'><b>{risk_score}/100 ({risk_level})</b></font>", body_style)
        ],
        [
            Paragraph("<b>ML Phishing Probability:</b>", body_style),
            Paragraph(f"<b>{ml_prob * 100:.1f}%</b>", body_style)
        ],
        [
            Paragraph("<b>File SHA-256 Hash:</b>", body_style),
            Paragraph(f"<code>{sha256_hash}</code>", body_style)
        ],
        [
            Paragraph("<b>Merkle Root Hash:</b>", body_style),
            Paragraph(f"<code>{merkle_root}</code>", body_style)
        ],
                [
            Paragraph("<b>Case ID:</b>", body_style),
            Paragraph(f"<b>PRAMAAN-{now_str[:10].replace('-', '')}-001</b>", body_style)
        ],
        [
            Paragraph("<b>Analyst:</b>", body_style),
            Paragraph("<b>Sneha Namrath</b>", body_style)
        ],
        [
            Paragraph("<b>Report Generated:</b>", body_style),
            Paragraph(f"{now_str}", body_style)
        ]
    ]

    summary_table = Table(summary_table_data, colWidths=[150, 390])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 10))

    # Section 1: Risk Factors
    elements.append(Paragraph("<b>1. Threat Factor Breakdown</b>", h2_style))
    if risk_factors:
        factors_data = [["Category", "Points", "Description"]]
        for f in risk_factors:
            factors_data.append([
                Paragraph(f["category"], body_style),
                Paragraph(f"+{f['points']}", body_style),
                Paragraph(f["description"], body_style)
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

    # Section 2: Key Email Headers
    elements.append(Paragraph("<b>2. Key Email Headers</b>", h2_style))
    header_rows = [["Header Field", "Value"]]
    for k, v in headers_dict.items():
        header_rows.append([
            Paragraph(f"<b>{k}</b>", body_style),
            Paragraph(str(v), body_style)
        ])
    headers_table = Table(header_rows, colWidths=[120, 420])
    headers_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E2E8F0')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    elements.append(headers_table)

    elements.append(Spacer(1, 10))

    # Section 3: Extracted IPs & Geolocation
    elements.append(Paragraph("<b>3. Extracted IP Addresses & Geolocation</b>", h2_style))
    if geo_data:
        geo_rows = [["IP Address", "Status", "Country", "City", "ISP / ASN"]]
        for g in geo_data:
            if g.get("status") == "success":
                isp_asn = f"{g.get('isp', 'N/A')} ({g.get('asn', 'N/A')})"
                geo_rows.append([
                    Paragraph(g.get("ip"), body_style),
                    Paragraph("PUBLIC", body_style),
                    Paragraph(g.get("country", "N/A"), body_style),
                    Paragraph(g.get("city", "N/A"), body_style),
                    Paragraph(isp_asn, body_style)
                ])
            else:
                geo_rows.append([
                    Paragraph(g.get("ip"), body_style),
                    Paragraph(g.get("reason", "SKIPPED"), body_style),
                    Paragraph("—", body_style),
                    Paragraph("—", body_style),
                    Paragraph("—", body_style)
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

    # Section 4: Extracted URLs
    elements.append(Paragraph("<b>4. Extracted URLs</b>", h2_style))
    if urls:
        url_rows = [["#", "Extracted URL"]]
        for idx, u in enumerate(urls, 1):
            url_rows.append([
                Paragraph(str(idx), body_style),
                Paragraph(f"<code>{u}</code>", body_style)
            ])
        url_table = Table(url_rows, colWidths=[30, 510])
        url_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E2E8F0')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(url_table)
    else:
        elements.append(Paragraph("No URLs extracted.", body_style))

    elements.append(Spacer(1, 15))
        # Chain-of-Custody Timeline
    elements.append(Paragraph("<b>Chain-of-Custody Timeline</b>", h2_style))
    elements.append(Spacer(1, 6))

    custody_data = [
        ["Stage", "Timestamp (UTC)", "Action"],
        ["Collected", now_str, "Email file ingested and SHA-256 computed."],
        ["Analyzed", now_str, "Headers, IOCs, and ML scoring completed."],
        ["Anchored", now_str, f"Merkle root recorded: {merkle_root[:16]}..."],
        ["Reported", now_str, "Forensic PDF generated for review."],
    ]

    custody_table = Table(custody_data, colWidths=[90, 150, 300])
    custody_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E293B')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#F8FAFC')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))

    elements.append(custody_table)
    elements.append(Spacer(1, 12))

        # Blockchain Anchoring
    elements.append(Paragraph("<b>Blockchain Anchoring</b>", h2_style))
    elements.append(Spacer(1, 6))

    if anchor_evidence is not None:
        anchor_result = anchor_evidence(
            case_id=case_id,
            merkle_root=merkle_root,
            file_sha256=sha256_hash,
            classification=risk_level,
        )
        blockchain_tx = anchor_result.get("tx_hash") or "Not anchored"
        etherscan_url = anchor_result.get("explorer_url") or "Not available"
        storage_status = anchor_result.get("storage", "UNKNOWN")
    else:
        blockchain_tx = "Blockchain module not available"
        etherscan_url = "N/A"
        storage_status = "N/A"

    chain_data = [
        ["Field", "Value"],
        ["Storage", storage_status],
        ["Merkle Root", f"{merkle_root[:32]}..."],
        ["Blockchain TX", f"{blockchain_tx[:40]}..."],
        ["Explorer Link", etherscan_url],
    ]

    chain_table = Table(chain_data, colWidths=[120, 420])
    chain_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E293B')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#F8FAFC')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))

    elements.append(chain_table)
    elements.append(Spacer(1, 12))

    # Section 5: Legal Disclaimer
    disclaimer_box_data = [[
        Paragraph(
            "<b>LEGAL & FORENSIC DISCLAIMER:</b> This report is generated automatically based on static heuristics, regex analysis, and machine learning models. It is intended for educational, technical investigation, and security triage purposes. Verify all findings independently.",
            disclaimer_style
        )
    ]]
    disclaimer_table = Table(disclaimer_box_data, colWidths=[540])
    disclaimer_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#FEF2F2')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#EF4444')),
        ('PADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(KeepTogether([disclaimer_table]))

    doc.build(elements)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
