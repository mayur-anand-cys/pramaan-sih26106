import streamlit as st
import email
from email import policy
import re
import hashlib
import ipaddress
from urllib.parse import urlparse
import pandas as pd
from pathlib import Path
import requests
import altair as alt
import pydeck as pdk

# Import custom modules
from model import predict_phishing_probability
import zkfv
import threat_intel
import graph_engine
from report_gen import generate_pdf_report

# Page Configuration
st.set_page_config(
    page_title="PRAMAAN | SOC Threat Intelligence & Digital Forensics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom SOC / SIEM CSS Theme Injection
st.markdown("""
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

    html, body, [data-testid="stAppViewContainer"] {
        background-color: #0b0d10 !important;
        color: #e2e8f0 !important;
        font-family: 'Inter', sans-serif !important;
    }

    /* Kill top padding */
    .block-container {
        padding-top: 1rem !important;
        padding-bottom: 1rem !important;
    }

    /* Tighten sidebar top padding */
    section[data-testid="stSidebar"] > div:first-child {
        padding-top: 0.5rem !important;
    }

    /* Hide Streamlit header bar */
    header[data-testid="stHeader"] {
        height: 0 !important;
        background: transparent !important;
    }

    /* Fix threat score card overflow */
    .threat-score-card {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 16px;
        padding: 12px 18px;
        background: #12151a;
        border: 1px solid #1e293b;
        border-radius: 8px;
        white-space: nowrap;
    }
    .threat-score-value {
        font-family: 'JetBrains Mono', monospace;
        font-size: 1.6rem;
        font-weight: 700;
        line-height: 1;
    }
    .threat-score-badge {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 4px;
        font-size: 0.7rem;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
        white-space: nowrap;
        letter-spacing: 0.5px;
    }
    
    [data-testid="stHeader"] {
        background-color: #0b0d10 !important;
    }

    /* Streamlit Deploy Button Highlight */
    .stAppDeployButton,
    [data-testid="stAppDeployButton"] {
        overflow: visible !important;
        display: inline-flex !important;
        align-items: center !important;
    }

    .stAppDeployButton button,
    [data-testid="stAppDeployButton"] button,
    [data-testid="stToolbar"] [data-testid="stAppDeployButton"] button,
    [data-testid="stHeader"] button[kind="header"]:has([data-testid="stAppDeployButton"]) {
        background: linear-gradient(135deg, #ff1744 0%, #d50000 100%) !important;
        background-color: #ff1744 !important;
        color: #ffffff !important;
        border: 1px solid #ff5252 !important;
        border-radius: 8px !important;
        font-weight: 700 !important;
        letter-spacing: 0.5px !important;
        padding: 6px 16px !important;
        box-shadow: 0 0 15px rgba(255, 23, 68, 0.85), 0 0 30px rgba(255, 23, 68, 0.5), 0 0 45px rgba(255, 23, 68, 0.25) !important;
        animation: deploy-glow-pulse 2s infinite ease-in-out !important;
        transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1) !important;
        cursor: pointer !important;
    }

    .stAppDeployButton button:hover,
    [data-testid="stAppDeployButton"] button:hover {
        background: linear-gradient(135deg, #ff5252 0%, #ff1744 100%) !important;
        background-color: #ff5252 !important;
        color: #ffffff !important;
        border-color: #ff8a80 !important;
        box-shadow: 0 0 25px rgba(255, 23, 68, 1), 0 0 50px rgba(255, 23, 68, 0.85), 0 0 70px rgba(255, 23, 68, 0.5) !important;
        transform: translateY(-1px) scale(1.04) !important;
    }

    .stAppDeployButton button span,
    .stAppDeployButton button p,
    [data-testid="stAppDeployButton"] button span,
    [data-testid="stAppDeployButton"] button p {
        color: #ffffff !important;
        font-weight: 700 !important;
        text-shadow: 0 1px 3px rgba(0, 0, 0, 0.6) !important;
    }

    .stAppDeployButton button svg,
    [data-testid="stAppDeployButton"] button svg {
        fill: #ffffff !important;
        stroke: #ffffff !important;
        filter: drop-shadow(0 0 2px rgba(255, 255, 255, 0.8)) !important;
    }

    @keyframes deploy-glow-pulse {
        0%, 100% {
            box-shadow: 0 0 12px rgba(255, 23, 68, 0.75), 0 0 25px rgba(255, 23, 68, 0.45);
        }
        50% {
            box-shadow: 0 0 22px rgba(255, 23, 68, 1), 0 0 42px rgba(255, 23, 68, 0.75), 0 0 60px rgba(255, 23, 68, 0.4);
        }
    }

    [data-testid="stSidebar"] {
        background-color: #12151a !important;
        border-right: 1px solid #1e293b !important;
    }

    .mono-font, code, pre, .stCodeBlock, [data-testid="stTextInput"] input {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* SOC Card Styling */
    .soc-card {
        background-color: #12151a;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 18px;
        margin-bottom: 16px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.4);
    }
    
    .soc-header {
        font-size: 1.5rem;
        font-weight: 700;
        color: #f8fafc;
        margin-bottom: 4px;
        letter-spacing: -0.5px;
    }
    
    .soc-subtitle {
        font-size: 0.9rem;
        color: #64748b;
        margin-bottom: 20px;
    }

    /* Semantic Status Badges */
    .badge-pass {
        background-color: rgba(61, 220, 151, 0.12);
        color: #3ddc97;
        border: 1px solid #3ddc97;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.85rem;
        font-family: 'JetBrains Mono', monospace;
    }

    .badge-fail {
        background-color: rgba(226, 75, 74, 0.12);
        color: #e24b4a;
        border: 1px solid #e24b4a;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.85rem;
        font-family: 'JetBrains Mono', monospace;
    }

    .badge-warn {
        background-color: rgba(251, 191, 109, 0.12);
        color: #fbbf6d;
        border: 1px solid #fbbf6d;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.85rem;
        font-family: 'JetBrains Mono', monospace;
    }

    .badge-info {
        background-color: rgba(125, 211, 252, 0.12);
        color: #7dd3fc;
        border: 1px solid #7dd3fc;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.85rem;
        font-family: 'JetBrains Mono', monospace;
    }

    /* Left Nav Chip Styling */
    .nav-chip {
        padding: 10px 14px;
        border-radius: 6px;
        margin-bottom: 8px;
        font-weight: 600;
        font-size: 0.9rem;
        cursor: pointer;
        background-color: #12151a;
        border-left: 4px solid #334155;
        color: #94a3b8;
    }
    
    .nav-chip-active {
        background-color: #1e293b;
        color: #f8fafc;
        border-left: 4px solid #7dd3fc;
    }
    
    /* Stepper Dots */
    .stepper-dot {
        display: inline-block;
        width: 28px;
        height: 28px;
        line-height: 28px;
        border-radius: 50%;
        text-align: center;
        font-size: 0.8rem;
        font-weight: 700;
        margin-right: 8px;
        background-color: #1e293b;
        color: #64748b;
        border: 1px solid #334155;
    }
    .stepper-dot-active {
        background-color: #7dd3fc;
        color: #0b0d10;
        border: 1px solid #7dd3fc;
    }
    .stepper-dot-visited {
        background-color: #3ddc97;
        color: #0b0d10;
        border: 1px solid #3ddc97;
    }
    </style>
""", unsafe_allow_html=True)

# Initialize Session State Navigation
if 'slide' not in st.session_state:
    st.session_state.slide = 0

SUSPICIOUS_KEYWORDS = [
    "urgent", "suspended", "verify", "password", "account", "bank",
    "unauthorized", "billing", "action required", "immediately",
    "security alert", "paypal", "crypto", "click here", "update details",
    "login", "confirm", "credit card", "security team", "disabled",
    "restore access", "fund", "wire transfer", "verification"
]

def compute_sha256(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()

@st.cache_data(ttl=3600)
def geolocate_ip(ip: str) -> dict:
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
            return {
                "ip": ip,
                "status": "skipped",
                "reason": "Private / Local IP",
                "lat": 37.7749,
                "lon": -122.4194
            }
    except ValueError:
        return {"ip": ip, "status": "error", "reason": "Invalid IP", "lat": 0.0, "lon": 0.0}

    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,as,lat,lon,query"
    try:
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "ip": ip,
                    "status": "success",
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "asn": data.get("as", "Unknown"),
                    "lat": data.get("lat", 37.7749),
                    "lon": data.get("lon", -122.4194)
                }
            else:
                return {
                    "ip": ip,
                    "status": "error",
                    "reason": data.get("message", "Lookup failed"),
                    "lat": 37.7749,
                    "lon": -122.4194
                }
    except Exception as e:
        return {
            "ip": ip,
            "status": "error",
            "reason": f"Connection error: {str(e)}",
            "lat": 37.7749,
            "lon": -122.4194
        }

    return {"ip": ip, "status": "error", "reason": "Unknown error", "lat": 0.0, "lon": 0.0}

def extract_email_body(msg: email.message.EmailMessage) -> str:
    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            if content_type == "text/plain" and "attachment" not in content_disposition:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        body_text += payload.decode(charset, errors='replace') + "\n"
                except Exception:
                    pass
            elif content_type == "text/html" and not body_text and "attachment" not in content_disposition:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        raw_html = payload.decode(charset, errors='replace')
                        cleaned = re.sub(r'<[^>]+>', ' ', raw_html)
                        body_text += cleaned + "\n"
                except Exception:
                    pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or 'utf-8'
                body_text = payload.decode(charset, errors='replace')
            else:
                body_text = msg.get_payload() or ""
        except Exception:
            body_text = str(msg.get_payload() or "")

    return body_text

def extract_urls(text: str) -> list:
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    matches = re.findall(url_pattern, text, re.IGNORECASE)
    cleaned_urls = []
    for url in matches:
        cleaned = re.sub(r'[.,;!)]+$', '', url)
        if cleaned not in cleaned_urls:
            cleaned_urls.append(cleaned)
    return cleaned_urls

def extract_ips(text: str) -> list:
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    candidates = re.findall(ip_pattern, text)
    valid_ips = []
    for candidate in candidates:
        try:
            ip_obj = ipaddress.ip_address(candidate)
            if not any(i["ip"] == candidate for i in valid_ips):
                valid_ips.append({
                    "ip": candidate,
                    "is_private": ip_obj.is_private,
                    "is_loopback": ip_obj.is_loopback,
                    "is_global": ip_obj.is_global
                })
        except ValueError:
            continue
    return valid_ips

def analyze_authentication_headers(msg: email.message.EmailMessage) -> dict:
    auth_results = []
    for h_name, h_val in msg.items():
        if h_name.lower() in ["authentication-results", "received-spf", "x-authentication-results"]:
            auth_results.append(str(h_val).lower())
    
    full_auth_str = " ".join(auth_results)

    spf_status = "UNKNOWN"
    if "spf=pass" in full_auth_str:
        spf_status = "PASS"
    elif any(term in full_auth_str for term in ["spf=fail", "spf=softfail", "spf=permerror", "spf=temperror", "spf=neutral"]):
        spf_status = "FAIL"

    dkim_status = "UNKNOWN"
    if "dkim=pass" in full_auth_str:
        dkim_status = "PASS"
    elif any(term in full_auth_str for term in ["dkim=fail", "dkim=softfail", "dkim=permerror", "dkim=neutral"]):
        dkim_status = "FAIL"

    dmarc_status = "UNKNOWN"
    if "dmarc=pass" in full_auth_str:
        dmarc_status = "PASS"
    elif any(term in full_auth_str for term in ["dmarc=fail", "dmarc=softfail", "dmarc=permerror", "dmarc=reject"]):
        dmarc_status = "FAIL"

    return {
        "spf": spf_status,
        "dkim": dkim_status,
        "dmarc": dmarc_status,
        "auth_header_raw": auth_results
    }

def calculate_risk_score(
    msg: email.message.EmailMessage,
    body: str,
    urls: list,
    ips: list,
    auth_info: dict,
    ml_prob: float
) -> tuple:
    score = 0
    factors = []

    subject = str(msg.get("Subject", "")).lower()
    from_header = str(msg.get("From", "")).lower()
    return_path = str(msg.get("Return-Path", "")).lower()
    reply_to = str(msg.get("Reply-To", "")).lower()

    # 1. Suspicious Keywords (Max +30)
    found_subject_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in subject]
    found_body_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in body.lower()]
    
    if found_subject_kw:
        pts = min(20, len(found_subject_kw) * 10)
        score += pts
        factors.append({
            "category": "Suspicious Keywords",
            "points": pts,
            "description": f"Urgent/Phishing keywords in Subject: {', '.join(found_subject_kw)}"
        })

    if found_body_kw:
        pts = min(20, len(set(found_body_kw)) * 5)
        score += pts
        factors.append({
            "category": "Suspicious Keywords",
            "points": pts,
            "description": f"Urgent/Phishing keywords in Body: {', '.join(list(set(found_body_kw))[:5])}"
        })

    # 2. URL Metrics (Max +30)
    if urls:
        pts = 5
        score += pts
        factors.append({
            "category": "URL Metrics",
            "points": pts,
            "description": f"Email contains {len(urls)} extracted URL(s)."
        })
        
        if len(urls) > 3:
            pts = 10
            score += pts
            factors.append({
                "category": "URL Metrics",
                "points": pts,
                "description": f"High number of links found ({len(urls)} links)."
            })

        ip_urls = [u for u in urls if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u)]
        if ip_urls:
            pts = 15
            score += pts
            factors.append({
                "category": "URL Metrics",
                "points": pts,
                "description": f"URL uses raw IP address instead of domain: {ip_urls[0]}"
            })

    # 3. Authentication Failures (Max +40)
    if auth_info["spf"] == "FAIL":
        pts = 15
        score += pts
        factors.append({
            "category": "Authentication",
            "points": pts,
            "description": "SPF authentication check failed or softfailed."
        })
    elif auth_info["spf"] == "UNKNOWN":
        pts = 5
        score += pts
        factors.append({
            "category": "Authentication",
            "points": pts,
            "description": "SPF header missing or status unknown."
        })

    if auth_info["dkim"] == "FAIL":
        pts = 15
        score += pts
        factors.append({
            "category": "Authentication",
            "points": pts,
            "description": "DKIM signature validation failed."
        })

    if auth_info["dmarc"] == "FAIL":
        pts = 20
        score += pts
        factors.append({
            "category": "Authentication",
            "points": pts,
            "description": "DMARC policy validation failed."
        })

    # 4. Header Mismatch / Spoofing Indicators (Max +20)
    if return_path and from_header:
        from_domain = from_header.split("@")[-1].strip("> ") if "@" in from_header else ""
        return_domain = return_path.split("@")[-1].strip("> ") if "@" in return_path else ""
        if from_domain and return_domain and from_domain != return_domain:
            pts = 10
            score += pts
            factors.append({
                "category": "Header Mismatch",
                "points": pts,
                "description": f"From domain ({from_domain}) does not match Return-Path domain ({return_domain})."
            })

    if reply_to and from_header and reply_to != from_header:
        pts = 5
        score += pts
        factors.append({
            "category": "Header Mismatch",
            "points": pts,
            "description": "Reply-To address differs from Sender (From) address."
        })

    # 5. Machine Learning Model (Max +25)
    if ml_prob > 0.3:
        ml_pts = int(round(ml_prob * 25))
        score += ml_pts
        factors.append({
            "category": "ML Classifier",
            "points": ml_pts,
            "description": f"TF-IDF Logistic Regression estimated {ml_prob * 100:.1f}% phishing probability."
        })

    final_score = min(100, max(0, score))
    return final_score, factors


# --- Sidebar Setup ---
with st.sidebar:
    st.markdown("### ⚙️ SOC Data Source")
    use_sample = st.checkbox("🧪 Use Sample Phishing EML", value=False)
    uploaded_file = st.file_uploader("Upload .eml File", type=["eml"])


raw_bytes = None
file_name = ""

if use_sample:
    sample_path = Path(__file__).parent / "gmail.eml"
    if sample_path.exists():
        raw_bytes = sample_path.read_bytes()
        file_name = "gmail.eml"
    else:
        st.error("gmail.eml file not found in directory.")
elif uploaded_file is not None:
    raw_bytes = uploaded_file.getvalue()
    file_name = uploaded_file.name

if raw_bytes is None:
    st.markdown("<div class='soc-card'>", unsafe_allow_html=True)
    st.markdown("<div class='soc-header'>🛡️ PRAMAAN Threat Intelligence</div>", unsafe_allow_html=True)
    st.markdown("<div class='soc-subtitle'>AI-Powered Threat Intelligence & Digital Forensics Platform</div>", unsafe_allow_html=True)
    st.warning("👈 Please upload an `.eml` file using the sidebar or check 'Use Sample Phishing EML' to initiate investigation.")
    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()
else:
    # --- Process Email Artifacts ---
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)
    sha256_hash = compute_sha256(raw_bytes)
    body_text = extract_email_body(msg)
    subject_text = str(msg.get("Subject", ""))

    urls = extract_urls(body_text + " " + subject_text)
    ips = extract_ips(body_text + " " + str(msg))
    auth_info = analyze_authentication_headers(msg)

    # ML Phishing Model Prediction
    full_text_for_ml = f"{subject_text}\n{body_text}"
    ml_prob = predict_phishing_probability(full_text_for_ml)

    # Risk Calculation
    risk_score, risk_factors = calculate_risk_score(msg, body_text, urls, ips, auth_info, ml_prob)

    # ZKFV Proof Generation
    zkfv_proof = zkfv.generate_evidence_proof(raw_bytes)
    merkle_root = zkfv_proof["merkle_root"]

    # IP Geolocation Processing
    geo_results = []
    for item in ips:
        ip_str = item["ip"]
        geo_info = geolocate_ip(ip_str)
        geo_results.append(geo_info)

    # Semantic Colors
    if risk_score >= 65:
        risk_level = "HIGH RISK"
        risk_color = "#e24b4a"
    elif risk_score >= 35:
        risk_level = "MODERATE RISK"
        risk_color = "#fbbf6d"
    else:
        risk_level = "LOW RISK"
        risk_color = "#3ddc97"

    headers_dict = {
        "Subject": subject_text or "N/A",
        "From": str(msg.get("From", "N/A")),
        "To": str(msg.get("To", "N/A")),
        "Date": str(msg.get("Date", "N/A")),
        "Reply-To": str(msg.get("Reply-To", "N/A")),
        "Return-Path": str(msg.get("Return-Path", "N/A")),
        "Message-ID": str(msg.get("Message-ID", "N/A"))
    }

    pdf_bytes = generate_pdf_report(
        sha256_hash=sha256_hash,
        risk_score=risk_score,
        risk_level=risk_level,
        headers_dict=headers_dict,
        urls=urls,
        ips=ips,
        geo_data=geo_results,
        risk_factors=risk_factors,
        ml_prob=ml_prob,
        merkle_root=merkle_root
    )

    # --- Top Header & Threat Gauge ---
    hdr_col1, hdr_col2 = st.columns([3, 1])

    with hdr_col1:
        st.markdown("<div class='soc-header'>🛡️ PRAMAAN FORENSIC DASHBOARD</div>", unsafe_allow_html=True)
        st.markdown(f"<div class='soc-subtitle'>AI-Powered Threat Intelligence & Digital Forensics Platform | Target: <code class='mono-font'>{file_name}</code></div>", unsafe_allow_html=True)

    with hdr_col2:
        st.markdown(f"""
        <div class="threat-score-card">
            <div>
                <div style="font-size: 0.7rem; text-transform: uppercase; letter-spacing: 1px; color: #64748b; font-weight: 600;">Threat Score</div>
                <div class="threat-score-value" style="color: {risk_color};">
                    {risk_score} <span style="font-size: 0.85rem; color: #64748b;">/ 100</span>
                </div>
            </div>
            <span class="threat-score-badge" style="background-color: {risk_color}20; border: 1px solid {risk_color}; color: {risk_color};">
                {risk_level}
            </span>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # --- Left Rail & Main Pane Layout ---
    left_rail, main_pane = st.columns([1, 4])

    with left_rail:
        st.markdown("<div style='font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px; color: #64748b; font-weight: 600; margin-bottom: 12px;'>Classification Rail</div>", unsafe_allow_html=True)
        
        categories = [
            ("📋 Header Summary", 0, "#7dd3fc"),
            ("🛡️ Authentication", 1, "#3ddc97" if auth_info["spf"] == "PASS" else "#e24b4a"),
            ("🤖 ML Classifier", 2, "#7dd3fc"),
            ("🌐 IP Geolocation", 3, "#fbbf6d"),
            ("🔗 Kill Chain Artifacts", 4, "#e24b4a"),
            ("📊 Threat Verdict", 5, risk_color)
        ]

        for label, idx, color in categories:
            is_active = (st.session_state.slide == idx)
            btn_label = f"▸ {label}" if is_active else f"   {label}"
            if st.button(btn_label, key=f"nav_btn_{idx}", use_container_width=True):
                st.session_state.slide = idx
                st.rerun()

    with main_pane:
        current_slide = st.session_state.slide

        # SLIDE 1: Header Summary
        if current_slide == 0:
            st.markdown("<div class='soc-card'>", unsafe_allow_html=True)
            st.markdown("### Header Summary & Metadata", unsafe_allow_html=True)
            st.caption("Extracted MIME headers in normalized key-value format.")
            
            for k, v in headers_dict.items():
                st.markdown(f"**{k}**")
                st.code(str(v), language="text")

            st.markdown("</div>", unsafe_allow_html=True)

        # SLIDE 2: Authentication Evidence
        elif current_slide == 1:
            st.markdown("<div class='soc-card'>", unsafe_allow_html=True)
            st.markdown("### Authentication Evidence & Cryptographic Proof", unsafe_allow_html=True)
            
            ac1, ac2, ac3 = st.columns(3)
            with ac1:
                st.markdown("**SPF Protocol**")
                if auth_info["spf"] == "PASS":
                    st.markdown('<span class="badge-pass">PASS</span>', unsafe_allow_html=True)
                elif auth_info["spf"] == "FAIL":
                    st.markdown('<span class="badge-fail">FAIL</span>', unsafe_allow_html=True)
                else:
                    st.markdown('<span class="badge-warn">UNKNOWN</span>', unsafe_allow_html=True)

            with ac2:
                st.markdown("**DKIM Protocol**")
                if auth_info["dkim"] == "PASS":
                    st.markdown('<span class="badge-pass">PASS</span>', unsafe_allow_html=True)
                elif auth_info["dkim"] == "FAIL":
                    st.markdown('<span class="badge-fail">FAIL</span>', unsafe_allow_html=True)
                else:
                    st.markdown('<span class="badge-warn">UNKNOWN</span>', unsafe_allow_html=True)

            with ac3:
                st.markdown("**DMARC Policy**")
                if auth_info["dmarc"] == "PASS":
                    st.markdown('<span class="badge-pass">PASS</span>', unsafe_allow_html=True)
                elif auth_info["dmarc"] == "FAIL":
                    st.markdown('<span class="badge-fail">FAIL</span>', unsafe_allow_html=True)
                else:
                    st.markdown('<span class="badge-warn">UNKNOWN</span>', unsafe_allow_html=True)

            st.markdown("---")
            st.markdown("#### 🔒 Zero-Knowledge Forensic Verification (ZKFV) Merkle Root")
            st.code(merkle_root, language="text")

            if st.button(" Verify Evidence Integrity", use_container_width=True):
                is_valid, curr_root, exp_root = zkfv.verify_evidence_proof(raw_bytes, zkfv_proof)
                if is_valid:
                    st.success("✅ **Evidence Verified**: Merkle root matches cryptographic proof!")
                else:
                    st.error("❌ **Verification Failed**: Cryptographic proof mismatch!")

            with st.expander("📜 View Forensic Chain-of-Custody Audit Ledger", expanded=False):
                audit_logs = zkfv.get_recent_audit_logs(10)
                if audit_logs:
                    st.dataframe(pd.DataFrame(audit_logs), use_container_width=True, hide_index=True)
                else:
                    st.caption("No audit log entries recorded yet.")

            st.markdown("</div>", unsafe_allow_html=True)

        # SLIDE 3: ML Classifier & Risk Score Breakdown
        elif current_slide == 2:
            st.markdown("<div class='soc-card'>", unsafe_allow_html=True)
            st.markdown("### ML Classifier & Risk Factor Breakdown", unsafe_allow_html=True)
            
            st.markdown(f"**TF-IDF + Logistic Regression Phishing Probability**: `<font color='#7dd3fc'>{ml_prob * 100:.2f}%</font>`", unsafe_allow_html=True)
            
            if risk_factors:
                st.markdown("#### Threat Score Contribution by Factor")
                df_factors = pd.DataFrame(risk_factors)
                
                chart = alt.Chart(df_factors).mark_bar().encode(
                    x=alt.X('sum(points):Q', title='Points Contribution'),
                    y=alt.Y('category:N', title='Factor Category', sort='-x'),
                    color=alt.Color('category:N', scale=alt.Scale(scheme='tableau10'), legend=None),
                    tooltip=['category', 'points', 'description']
                ).properties(height=180)
                
                st.altair_chart(chart, use_container_width=True)

                with st.expander("🔍 View Raw Factor Breakdown Table", expanded=False):
                    st.dataframe(df_factors, use_container_width=True, hide_index=True)
            else:
                st.success("No threat score penalty factors detected.")

            st.markdown("</div>", unsafe_allow_html=True)

        # SLIDE 4: IP Geolocation
        elif current_slide == 3:
            st.markdown("<div class='soc-card'>", unsafe_allow_html=True)
            st.markdown("### IP Geolocation & Network Intelligence", unsafe_allow_html=True)
            
            geo_map_data = []
            for g in geo_results:
                if g.get("status") == "success":
                    geo_map_data.append({
                        "lat": g.get("lat", 37.7749),
                        "lon": g.get("lon", -122.4194),
                        "ip": g.get("ip"),
                        "city": g.get("city"),
                        "country": g.get("country")
                    })

            if geo_map_data:
                map_df = pd.DataFrame(geo_map_data)
                st.map(map_df, latitude="lat", longitude="lon", zoom=3)
            else:
                st.info("No public IP coordinates found. Displaying default threat map overview.")
                fallback_df = pd.DataFrame([{"lat": 37.7749, "lon": -122.4194}])
                st.map(fallback_df, latitude="lat", longitude="lon", zoom=2)

            st.markdown("#### IP Geolocation Data Table")
            st.dataframe(pd.DataFrame(geo_results), use_container_width=True, hide_index=True)

            st.markdown("</div>", unsafe_allow_html=True)

        # SLIDE 5: Extracted URLs & IPs (Kill Chain & Graph Correlation)
        elif current_slide == 4:
            st.markdown("<div class='soc-card'>", unsafe_allow_html=True)
            st.markdown("### Extracted URLs & IPs (Kill Chain Artifacts)", unsafe_allow_html=True)
            
            st.markdown("#### 🛠️ Threat Infrastructure Relationship Graph")
            
            # Build and display live entity graph
            from_hdr = str(msg.get("From", ""))
            ret_hdr = str(msg.get("Return-Path", ""))
            graph_data = graph_engine.build_threat_infrastructure_graph(from_hdr, ret_hdr, urls, geo_results)
            plotly_fig = graph_engine.generate_plotly_threat_graph(graph_data)
            
            st.plotly_chart(plotly_fig, use_container_width=True)

            st.caption(f"Network Correlation Summary: {graph_data['num_nodes']} Entities, {graph_data['num_edges']} Threat Relationships")

            st.markdown("---")
            col_u, col_i = st.columns(2)
            with col_u:
                st.markdown("#### Extracted URLs & Threat Flags")
                if urls:
                    url_analysis = threat_intel.analyze_url_structure(urls)
                    for idx, u_info in enumerate(url_analysis, 1):
                        flags_str = f" ⚠️ {', '.join(u_info['flags'])}" if u_info['flags'] else " ✅ Clean"
                        st.code(f"[{idx}] {u_info['url']}{flags_str}", language="text")
                else:
                    st.caption("No URLs extracted.")

            with col_i:
                st.markdown("#### Extracted IP Addresses")
                if ips:
                    for idx, item in enumerate(ips, 1):
                        st.code(f"[{idx}] {item['ip']} (Private: {item['is_private']})", language="text")
                else:
                    st.caption("No IP addresses extracted.")

            st.markdown("</div>", unsafe_allow_html=True)

        # SLIDE 6: Final Threat Assessment & Verdict
        elif current_slide == 5:
            st.markdown("<div class='soc-card'>", unsafe_allow_html=True)
            st.markdown("### Final Threat Assessment & Incident Verdict", unsafe_allow_html=True)
            
            v_col1, v_col2 = st.columns(2)
            with v_col1:
                st.markdown("#### Overall Incident Verdict")
                st.markdown(f"<div style='font-size: 2.2rem; font-weight: 800; color: {risk_color}; font-family: \"JetBrains Mono\", monospace;'>{risk_level}</div>", unsafe_allow_html=True)
                st.markdown(f"Threat Score: **{risk_score}/100** | ML Phishing Probability: **{ml_prob * 100:.1f}%**")

            with v_col2:
                st.markdown("#### Executive Action & Export")
                st.download_button(
                    label="📥 Download Forensic PDF Report",
                    data=pdf_bytes,
                    file_name="forensic_report.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )

            st.markdown("---")
            st.markdown("#### Key Incident Evidence Summary")
            summary_rows = [
                ("File SHA-256", sha256_hash),
                ("Merkle Root", merkle_root),
                ("SPF Status", auth_info["spf"]),
                ("DKIM Status", auth_info["dkim"]),
                ("DMARC Status", auth_info["dmarc"]),
                ("Extracted URLs Count", str(len(urls))),
                ("Extracted IPs Count", str(len(ips)))
            ]
            for label_s, val_s in summary_rows:
                st.markdown(f"**{label_s}**: `<font color='#7dd3fc'>{val_s}</font>`", unsafe_allow_html=True)

            st.markdown("</div>", unsafe_allow_html=True)

        # --- Bottom Stepper Navigation & Teaser ---
        st.markdown("---")
        nav_col1, nav_col2, nav_col3 = st.columns([1, 2, 1])

        with nav_col1:
            if current_slide > 0:
                if st.button("⬅️ Previous", use_container_width=True):
                    st.session_state.slide -= 1
                    st.rerun()

        with nav_col2:
            teasers = [
                "Next: Authentication Evidence →",
                "Next: ML Classifier & Risk Breakdown →",
                "Next: IP Geolocation & Mapping →",
                "Next: Extracted URLs & IPs (Kill Chain) →",
                "Next: Final Threat Verdict & Report →",
                "Overview Complete"
            ]
            st.markdown(f"<div style='text-align: center; color: #64748b; font-size: 0.85rem; font-weight: 600;'>{teasers[current_slide]}</div>", unsafe_allow_html=True)

        with nav_col3:
            if current_slide < 5:
                if st.button("Next ➡️", use_container_width=True):
                    st.session_state.slide += 1
                    st.rerun()

# --- Collapsed Legal Disclaimer at Bottom ---
st.markdown("<div style='margin-top: 30px;'></div>", unsafe_allow_html=True)
with st.expander("⚖️ Legal & Forensic Disclaimer", expanded=False):
    st.caption(
        "This software is designed exclusively for educational, cybersecurity analysis, and digital forensics purposes. "
        "The calculated risk score and extracted threat artifacts are derived from automated regex heuristics, IP geolocation, ML models, and cryptographic hashes. "
        "Always perform full manual verification prior to taking administrative or legal action."
    )
