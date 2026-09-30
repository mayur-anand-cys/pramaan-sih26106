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
import plotly.graph_objects as go

# Custom modules
from model import predict_phishing_probability
import zkfv
import threat_intel
import graph_engine
import neo4j_engine
from report_gen import generate_pdf_report
from backend.detection.auth_check import verify_email_auth
from backend.detection.xai import (
    detect_contradictions,
    explain_prediction,
    flag_for_analyst_review,
    log_contradiction_to_audit
)


# Page Configuration
st.set_page_config(
    page_title="PRAMAAN | SOC Threat Intelligence & Digital Forensics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Authentication gate ---
from backend.auth.login_ui import render_login_page
from backend.auth.authenticator import get_current_user, logout as auth_logout

if not render_login_page():
    st.stop()

_user = get_current_user()
_role = _user["role"] if _user else "analyst"

# Helper for defanging URLs
def defang_url(url: str) -> str:
    s = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    parts = s.split("/")
    if len(parts) > 2:
        domain = parts[2]
        defanged_domain = domain.replace(".", "[.]")
        parts[2] = defanged_domain
        return "/".join(parts)
    return s.replace(".", "[.]")

# Helper to compute SHA256
def compute_sha256(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()

# IP Geolocation Helper
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
                "lon": -122.4194,
                "isp": "Private Network",
                "asn": "N/A",
                "country": "Local",
                "city": "Private"
            }
    except ValueError:
        return {"ip": ip, "status": "error", "reason": "Invalid IP", "lat": 0.0, "lon": 0.0, "isp": "Unknown", "asn": "N/A", "country": "Unknown", "city": "Unknown"}

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
                    "lon": -122.4194,
                    "isp": "Unknown",
                    "asn": "N/A",
                    "country": "Unknown",
                    "city": "Unknown"
                }
    except Exception as e:
        return {
            "ip": ip,
            "status": "error",
            "reason": f"Connection error: {str(e)}",
            "lat": 37.7749,
            "lon": -122.4194,
            "isp": "Unknown",
            "asn": "N/A",
            "country": "Unknown",
            "city": "Unknown"
        }

    return {"ip": ip, "status": "error", "reason": "Unknown error", "lat": 0.0, "lon": 0.0, "isp": "Unknown", "asn": "N/A", "country": "Unknown", "city": "Unknown"}

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
        if h_name.lower() in ["authentication-results", "received-spf", "x-authentication-results", "arc-authentication-results"]:
            auth_results.append(str(h_val).lower())
    
    full_auth_str = " ".join(auth_results)

    spf_status = "PASS" if "spf=pass" in full_auth_str else ("FAIL" if any(t in full_auth_str for t in ["spf=fail", "spf=softfail", "spf=permerror"]) else "UNKNOWN")
    dkim_status = "PASS" if "dkim=pass" in full_auth_str else ("FAIL" if any(t in full_auth_str for t in ["dkim=fail", "dkim=softfail"]) else "UNKNOWN")
    dmarc_status = "PASS" if "dmarc=pass" in full_auth_str else ("FAIL" if any(t in full_auth_str for t in ["dmarc=fail", "dmarc=softfail", "dmarc=reject"]) else "UNKNOWN")
    arc_status = "PASS" if "arc=pass" in full_auth_str else ("FAIL" if "arc=fail" in full_auth_str else "UNKNOWN")

    return {
        "spf": spf_status,
        "dkim": dkim_status,
        "dmarc": dmarc_status,
        "arc": arc_status,
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

    # 1. Suspicious Keywords
    found_subject_kw = [kw for kw in threat_intel.SUSPICIOUS_KEYWORDS if kw in subject]
    found_body_kw = [kw for kw in threat_intel.SUSPICIOUS_KEYWORDS if kw in body.lower()]
    
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

    # 2. URL Metrics
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

    # 3. Authentication Failures
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

    # 4. Header Mismatch
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

    # 5. Machine Learning Model
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


# --- Theme Configuration ---
if 'theme' not in st.session_state:
    st.session_state.theme = "Example A (Dark Blue)"

# Sidebar Theme Switcher & Data Source
with st.sidebar:
    st.markdown("### 🎨 Theme Configuration")
    theme_choice = st.radio(
        "Background Theme",
        ["Example A (Dark Blue)", "Example B (Dark Wine)"],
        index=0 if st.session_state.theme == "Example A (Dark Blue)" else 1
    )
    st.session_state.theme = theme_choice

    st.markdown("---")
    st.markdown("### ⚙️ SOC Data Source")
    use_sample = st.checkbox("🧪 Use Sample Phishing EML", value=False)
    uploaded_file = st.file_uploader("Upload .eml File", type=["eml"])

    st.markdown("---")
    if _user:
        st.caption(f"Signed in as **{_user.get('username', 'unknown')}** ({_role})")
    if st.button("Sign out", use_container_width=True):
        auth_logout()
        st.rerun()

# Dynamic CSS Theme Ingestion based on Selection
if st.session_state.theme == "Example A (Dark Blue)":
    bg_gradient = "linear-gradient(135deg, #0f1419 0%, #1a2332 100%)"
    card_bg = "#121926"
    card_border = "#1e293b"
else:
    bg_gradient = "linear-gradient(135deg, #1a0f14 0%, #2a1820 100%)"
    card_bg = "#22131b"
    card_border = "#3a202d"

st.markdown(f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

    html, body, [data-testid="stAppViewContainer"] {{
        background: {bg_gradient} !important;
        color: #e2e8f0 !important;
        font-family: 'Inter', sans-serif !important;
    }}
    
    [data-testid="stHeader"] {{
        background: transparent !important;
    }}

    [data-testid="stSidebar"] {{
        background-color: #0d1117 !important;
        border-right: 1px solid #1e293b !important;
    }}

    .mono-font, code, pre, .stCodeBlock, [data-testid="stTextInput"] input {{
        font-family: 'JetBrains Mono', monospace !important;
    }}

    .soc-card {{
        background-color: {card_bg};
        border: 1px solid {card_border};
        border-radius: 8px;
        padding: 20px;
        margin-bottom: 20px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
    }}

    .badge-pass {{
        background-color: rgba(61, 220, 151, 0.15);
        color: #3ddc97;
        border: 1px solid #3ddc97;
        padding: 4px 12px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.85rem;
        font-family: 'JetBrains Mono', monospace;
    }}

    .badge-fail {{
        background-color: rgba(226, 75, 74, 0.15);
        color: #e24b4a;
        border: 1px solid #e24b4a;
        padding: 4px 12px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.85rem;
        font-family: 'JetBrains Mono', monospace;
    }}

    .badge-warn {{
        background-color: rgba(251, 191, 109, 0.15);
        color: #fbbf6d;
        border: 1px solid #fbbf6d;
        padding: 4px 12px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.85rem;
        font-family: 'JetBrains Mono', monospace;
    }}

    .stAppDeployButton button, [data-testid="stAppDeployButton"] button {{
        background: linear-gradient(135deg, #ff1744 0%, #d50000 100%) !important;
        color: #ffffff !important;
        border: 1px solid #ff5252 !important;
        border-radius: 6px !important;
        font-weight: 700 !important;
        padding: 6px 18px !important;
        box-shadow: 0 0 15px rgba(255, 23, 68, 0.8) !important;
    }}

    /* Streamlit Tabs Styling */
    .stTabs [data-baseweb="tab-list"] {{
        gap: 12px;
        background-color: transparent;
        border-bottom: 2px solid #1e293b;
    }}

    .stTabs [data-baseweb="tab"] {{
        background-color: {card_bg};
        border-radius: 6px 6px 0 0;
        color: #94a3b8;
        padding: 10px 20px;
        font-weight: 600;
        border: 1px solid {card_border};
        border-bottom: none;
    }}

    .stTabs [aria-selected="true"] {{
        background-color: #1e293b !important;
        color: #7dd3fc !important;
        border-top: 3px solid #7dd3fc !important;
    }}
    </style>
""", unsafe_allow_html=True)


# --- UPLOAD FLOW HANDLING ---
raw_bytes = None
file_name = ""

if use_sample:
    sample_path = Path(__file__).parent / "gmail.eml"
    if sample_path.exists():
        raw_bytes = sample_path.read_bytes()
        file_name = "gmail.eml"
    else:
        st.error("gmail.eml file not found in repository.")
elif uploaded_file is not None:
    raw_bytes = uploaded_file.getvalue()
    file_name = uploaded_file.name


# --- LANDING PAGE (Pre-Upload) ---
if raw_bytes is None:
    st.markdown("<div style='margin-top: 40px;'></div>", unsafe_allow_html=True)
    
    landing_col1, landing_col2, landing_col3 = st.columns([1, 2, 1])
    with landing_col2:
        st.markdown("""
        <div class='soc-card' style='text-align: center; padding: 40px;'>
            <div style='font-size: 3rem; margin-bottom: 10px;'>🛡️</div>
            <div style='font-size: 2rem; font-weight: 800; color: #f8fafc; letter-spacing: -0.5px;'>PRAMAAN Threat Intelligence</div>
            <div style='font-size: 1rem; color: #7dd3fc; margin-bottom: 24px;'>AI-Powered Digital Forensics & Phishing Incident Response Engine</div>
            <div style='font-size: 0.9rem; color: #94a3b8; margin-bottom: 30px;'>
                Upload an <code>.eml</code> email file below or check the sample option to launch the 5-Tab SOC Forensic Inspection Dashboard.
            </div>
        </div>
        """, unsafe_allow_html=True)

        landing_upload = st.file_uploader("Drag & Drop `.eml` file here", type=["eml"], key="landing_uploader")
        if landing_upload is not None:
            raw_bytes = landing_upload.getvalue()
            file_name = landing_upload.name
            st.rerun()

        st.markdown("<div style='text-align: center; margin-top: 15px;'>", unsafe_allow_html=True)
        if st.checkbox("🧪 Use Sample Phishing EML (gmail.eml)", key="landing_sample"):
            sample_path = Path(__file__).parent / "gmail.eml"
            if sample_path.exists():
                raw_bytes = sample_path.read_bytes()
                file_name = "gmail.eml"
                st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)

    st.stop()


# --- DASHBOARD (Post-Upload) ---

# Process Email Artifacts
msg = email.message_from_bytes(raw_bytes, policy=policy.default)
sha256_hash = compute_sha256(raw_bytes)
body_text = extract_email_body(msg)
subject_text = str(msg.get("Subject", ""))

urls = extract_urls(body_text + " " + subject_text)
ips = extract_ips(body_text + " " + str(msg))
auth_info = analyze_authentication_headers(msg)

# ML Phishing Probability
full_text_for_ml = f"{subject_text}\n{body_text}"
ml_prob = predict_phishing_probability(full_text_for_ml)

# Risk Calculation
risk_score, risk_factors = calculate_risk_score(msg, body_text, urls, ips, auth_info, ml_prob)

# Email Authentication & XAI Contradiction Analysis
raw_text = raw_bytes.decode('utf-8', errors='replace')
try:
    source_ip = ips[0]["ip"] if ips else None
    auth_verification = verify_email_auth(raw_text, source_ip=source_ip)
except Exception:
    auth_verification = {
        "spf": {"dns_result": auth_info.get("spf", "none").lower(), "header_result": auth_info.get("spf", "none").lower()},
        "dkim": {"dns_result": auth_info.get("dkim", "none").lower(), "header_result": auth_info.get("dkim", "none").lower()},
        "dmarc": {"dns_result": auth_info.get("dmarc", "none").lower(), "header_result": auth_info.get("dmarc", "none").lower()},
        "header_trust_score": 50
    }

ml_result = {
    "probability": ml_prob,
    "prediction": "phishing" if ml_prob >= 0.5 else "legitimate",
    "confidence": round(abs(ml_prob - 0.5) * 200, 2),
    "threat_score": float(risk_score)
}
xai_result = detect_contradictions(ml_result, auth_verification)
xai_explanation = explain_prediction(raw_text, ml_result)

if xai_result.get("has_contradiction"):
    log_contradiction_to_audit(xai_result, email_id=sha256_hash)

# ZKFV Proof Generation
zkfv_proof = zkfv.generate_evidence_proof(raw_bytes)
merkle_root = zkfv_proof["merkle_root"]

# IP Geolocation Processing
geo_results = [geolocate_ip(item["ip"]) for item in ips]

# Semantic Risk Coloring
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

# --- Role-based routing ---
if _role == "citizen":
    from pramaan.citizen_view import render_citizen_portal
    render_citizen_portal(
        risk_score=risk_score,
        risk_level=risk_level,
        risk_factors=risk_factors,
        ml_prob=ml_prob,
    )
    st.stop()

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

# --- TOP MAIN HEADER (Flush with top) ---
top_col1, top_col2 = st.columns([3, 1])

with top_col1:
    analyst_badge = ""
    if xai_result.get("requires_analyst_review"):
        analyst_badge = """
        <span style="background-color: rgba(239, 68, 68, 0.18); border: 1.5px solid #ef4444; color: #ef4444; padding: 4px 12px; border-radius: 6px; font-weight: 800; font-size: 0.85rem; font-family: 'JetBrains Mono', monospace; margin-left: 12px; display: inline-block; vertical-align: middle;">
            ⚠️ ANALYST REVIEW REQUIRED
        </span>
        """
    st.markdown(f"""
    <div style="margin-top: -15px; margin-bottom: 8px;">
        <span style="font-size: 1.4rem; font-weight: 800; color: #f8fafc;">🛡️ Target Artifact:</span> 
        <code style="font-size: 1.2rem; color: #7dd3fc; background-color: #1e293b; padding: 4px 10px; border-radius: 6px;">{file_name}</code>
        {analyst_badge}
    </div>
    """, unsafe_allow_html=True)
    if st.button("🔄 Upload another .eml", key="reset_btn"):
        st.session_state.clear()
        st.rerun()


with top_col2:
    btn_c1, btn_c2 = st.columns(2)
    with btn_c1:
        st.download_button(
            label="📥 Download Report",
            data=pdf_bytes,
            file_name=f"PRAMAAN_Report_{file_name}.pdf",
            mime="application/pdf",
            use_container_width=True
        )
    with btn_c2:
        st.markdown("""
        <div class="stAppDeployButton">
            <button>🚀 Deploy</button>
        </div>
        """, unsafe_allow_html=True)

st.markdown("<div style='margin-bottom: 12px;'></div>", unsafe_allow_html=True)

# Helper function for legal disclaimer footer
def render_legal_disclaimer():
    st.markdown("<div style='margin-top: 30px;'></div>", unsafe_allow_html=True)
    with st.expander("⚖️ Legal & Forensic Disclaimer", expanded=False):
        st.caption(
            "This software is designed exclusively for educational, cybersecurity analysis, and digital forensics purposes. "
            "The calculated risk score and extracted threat artifacts are derived from automated regex heuristics, IP geolocation, ML models, and cryptographic hashes. "
            "Always perform full manual verification prior to taking administrative or legal action."
        )


# --- 5 HORIZONTAL TABS ---
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "Tab 1: Triage Overview",
    "Tab 2: Authentication",
    "Tab 3: Content & URL",
    "Tab 4: Relay & Route",
    "Tab 5: IP & Domain Intel"
])

# ==========================================
# TAB 1: TRIAGE OVERVIEW
# ==========================================
with tab1:
    st.markdown("<div class='soc-card'>", unsafe_allow_html=True)

    # CONTRADICTION ALERTS BANNER (Issue #4)
    if xai_result.get("severity") == "CRITICAL":
        crit_alerts = [a for a in xai_result.get("alerts", []) if a.get("severity") == "CRITICAL"]
        alert_desc = crit_alerts[0].get("description") if crit_alerts else "AI verdict directly conflicts with cryptographic authentication failure."
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, rgba(239, 68, 68, 0.25) 0%, rgba(153, 27, 27, 0.35) 100%);
                    border: 2px solid #ef4444; border-radius: 8px; padding: 16px 20px; margin-bottom: 20px;">
            <div style="display: flex; align-items: center; justify-content: space-between;">
                <div style="display: flex; align-items: center; gap: 14px;">
                    <span style="font-size: 2.2rem;">🚨</span>
                    <div>
                        <h3 style="color: #ef4444; margin: 0; font-size: 1.25rem; font-weight: 800;">CRITICAL XAI CONTRADICTION DETECTED</h3>
                        <p style="color: #fca5a5; margin: 4px 0 0 0; font-size: 0.95rem;">{alert_desc}</p>
                    </div>
                </div>
                <span style="background-color: #ef4444; color: #ffffff; padding: 6px 14px; border-radius: 9999px; font-weight: 800; font-size: 0.85rem; letter-spacing: 0.05em;">
                    ⚠️ ANALYST REVIEW REQUIRED
                </span>
            </div>
        </div>
        """, unsafe_allow_html=True)
    elif xai_result.get("severity") == "HIGH":
        high_alerts = [a for a in xai_result.get("alerts", []) if a.get("severity") == "HIGH"]
        alert_desc = high_alerts[0].get("description") if high_alerts else "AI flagged email as phishing but authentication passed."
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, rgba(249, 115, 22, 0.2) 0%, rgba(194, 65, 12, 0.25) 100%);
                    border: 2px solid #f97316; border-radius: 8px; padding: 16px 20px; margin-bottom: 20px;">
            <div style="display: flex; align-items: center; justify-content: space-between;">
                <div style="display: flex; align-items: center; gap: 14px;">
                    <span style="font-size: 2.2rem;">⚠️</span>
                    <div>
                        <h3 style="color: #f97316; margin: 0; font-size: 1.25rem; font-weight: 800;">HIGH XAI CONTRADICTION — POTENTIAL FALSE POSITIVE</h3>
                        <p style="color: #fdba74; margin: 4px 0 0 0; font-size: 0.95rem;">{alert_desc}</p>
                    </div>
                </div>
                <span style="background-color: #f97316; color: #ffffff; padding: 6px 14px; border-radius: 9999px; font-weight: 800; font-size: 0.85rem; letter-spacing: 0.05em;">
                    ⚠️ ANALYST REVIEW REQUIRED
                </span>
            </div>
        </div>
        """, unsafe_allow_html=True)
    elif xai_result.get("severity") == "AMBER":
        amber_alerts = [a for a in xai_result.get("alerts", []) if a.get("severity") == "AMBER"]
        alert_desc = amber_alerts[0].get("description") if amber_alerts else "Low model confidence amidst high threat score."
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, rgba(234, 179, 8, 0.2) 0%, rgba(161, 98, 7, 0.25) 100%);
                    border: 2px solid #eab308; border-radius: 8px; padding: 14px 18px; margin-bottom: 20px;">
            <div style="display: flex; align-items: center; gap: 14px;">
                <span style="font-size: 2rem;">⚡</span>
                <div>
                    <h3 style="color: #eab308; margin: 0; font-size: 1.15rem; font-weight: 800;">AMBER XAI CONTRADICTION — MODEL AMBIGUITY</h3>
                    <p style="color: #fef08a; margin: 4px 0 0 0; font-size: 0.95rem;">{alert_desc}</p>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # RADIAL THREAT SCORE METER (Center Circle)
    center_col1, center_col2, center_col3 = st.columns([1, 2, 1])
    with center_col2:
        stroke_dashoffset = int(283 * (1 - (risk_score / 100)))
        st.markdown(f"""
        <div style="text-align: center; padding: 15px;">
            <svg width="200" height="200" viewBox="0 0 100 100">
                <circle cx="50" cy="50" r="45" fill="none" stroke="#1e293b" stroke-width="8"/>
                <circle cx="50" cy="50" r="45" fill="none" stroke="{risk_color}" stroke-width="8"
                        stroke-dasharray="283" stroke-dashoffset="{stroke_dashoffset}"
                        stroke-linecap="round" transform="rotate(-90 50 50)"/>
                <text x="50" y="44" font-family="'JetBrains Mono', monospace" font-size="20" font-weight="800" fill="{risk_color}" text-anchor="middle">{risk_score}</text>
                <text x="50" y="60" font-family="'Inter', sans-serif" font-size="8" font-weight="600" fill="#94a3b8" text-anchor="middle">/ 100 THREAT SCORE</text>
            </svg>
            <div style="margin-top: 10px;">
                <span style="background-color: {risk_color}25; border: 1px solid {risk_color}; color: {risk_color}; padding: 6px 16px; border-radius: 6px; font-weight: 800; font-size: 1rem; font-family: 'JetBrains Mono', monospace;">
                    {risk_level}
                </span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    ov_c1, ov_c2 = st.columns(2)

    with ov_c1:
        st.markdown("#### 🔍 Executive Incident Verdict")
        st.markdown(f"**ML Phishing Probability**: `<font color='#7dd3fc'><b>{ml_prob * 100:.1f}%</b></font>`", unsafe_allow_html=True)
        st.markdown(f"**Target EML Hash**: `<code class='mono-font'>{sha256_hash}</code>`", unsafe_allow_html=True)
        st.button("📋 Copy Hash", key="copy_hash_t1", on_click=lambda: st.write("Copied!"))

        st.markdown("##### 📌 Key Threat Findings")
        if risk_factors:
            for factor in risk_factors:
                st.markdown(f"• **{factor['category']}** (+{factor['points']} pts): {factor['description']}")
        else:
            st.success("No critical threat factors detected in this email.")

    with ov_c2:
        st.markdown("#### 📊 Threat Factor Weight Breakdown")
        if risk_factors:
            df_f = pd.DataFrame(risk_factors)
            chart = alt.Chart(df_f).mark_bar().encode(
                x=alt.X('points:Q', title='Score Penalty Points'),
                y=alt.Y('category:N', title='Category', sort='-x'),
                color=alt.Color('category:N', scale=alt.Scale(scheme='dark2'), legend=None),
                tooltip=['category', 'points', 'description']
            ).properties(height=200)
            st.altair_chart(chart, use_container_width=True)
        else:
            st.info("Clean factor breakdown.")

    # SHAP Waterfall Chart Sub-Section
    st.markdown("---")
    st.markdown("#### 🔬 Explainable AI (XAI) — SHAP Model Attributions")
    st.caption("Local feature attributions calculated using SHAP (Shapley Additive exPlanations) for tokens shifting the Logistic Regression prediction.")

    w_data = xai_explanation.get("waterfall_data", {})
    if w_data and w_data.get("labels"):
        labels = w_data["labels"]
        vals = w_data["values"]
        base_v = w_data.get("base_value", 0.0)

        wf_measures = ["relative"] * len(labels) + ["total"]
        wf_x = labels + ["Total Model Impact"]
        wf_y = vals + [sum(vals)]

        fig = go.Figure(go.Waterfall(
            name="SHAP Attributions",
            orientation="v",
            measure=wf_measures,
            x=wf_x,
            y=wf_y,
            base=base_v,
            decreasing={"marker": {"color": "#3ddc97"}},
            increasing={"marker": {"color": "#ef4444"}},
            totals={"marker": {"color": "#38bdf8"}},
            connector={"line": {"color": "#64748b", "width": 1.5, "dash": "dot"}},
            text=[f"{v:+.3f}" for v in vals] + [f"{w_data.get('final_value', 0.0):.3f}"],
            textposition="outside"
        ))

        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(15, 23, 42, 0.6)",
            font=dict(color="#94a3b8", family="Inter"),
            xaxis=dict(title="Influential Tokens / N-Grams", gridcolor="#334155"),
            yaxis=dict(title="Attribution Weight (Log-Odds)", gridcolor="#334155"),
            height=360,
            margin=dict(l=20, r=20, t=30, b=30)
        )
        st.plotly_chart(fig, use_container_width=True)

        xai_c1, xai_c2 = st.columns(2)
        with xai_c1:
            st.markdown("##### 🚨 Top Phishing Signals (Positive Impact)")
            pos_f = xai_explanation.get("top_positive_features", [])
            if pos_f:
                st.dataframe(pd.DataFrame(pos_f).rename(columns={"feature": "Token Feature", "attribution": "SHAP Weight"}), use_container_width=True, hide_index=True)
            else:
                st.caption("No significant phishing tokens detected.")

        with xai_c2:
            st.markdown("##### 🛡️ Top Legitimate Signals (Negative Impact)")
            neg_f = xai_explanation.get("top_negative_features", [])
            if neg_f:
                st.dataframe(pd.DataFrame(neg_f).rename(columns={"feature": "Token Feature", "attribution": "SHAP Weight"}), use_container_width=True, hide_index=True)
            else:
                st.caption("No significant legitimate tokens detected.")

    st.markdown("</div>", unsafe_allow_html=True)
    render_legal_disclaimer()



# ==========================================
# TAB 2: AUTHENTICATION
# ==========================================
with tab2:
    st.markdown("<div class='soc-card'>", unsafe_allow_html=True)
    st.markdown("### 🛡️ Authentication Protocols & Domain Alignment Matrix")
    
    a1, a2, a3, a4 = st.columns(4)
    with a1:
        st.markdown("**SPF Protocol**")
        b_cls = "badge-pass" if auth_info["spf"] == "PASS" else ("badge-fail" if auth_info["spf"] == "FAIL" else "badge-warn")
        st.markdown(f'<span class="{b_cls}">{auth_info["spf"]}</span>', unsafe_allow_html=True)
    
    with a2:
        st.markdown("**DKIM Signature**")
        b_cls = "badge-pass" if auth_info["dkim"] == "PASS" else ("badge-fail" if auth_info["dkim"] == "FAIL" else "badge-warn")
        st.markdown(f'<span class="{b_cls}">{auth_info["dkim"]}</span>', unsafe_allow_html=True)

    with a3:
        st.markdown("**DMARC Policy**")
        b_cls = "badge-pass" if auth_info["dmarc"] == "PASS" else ("badge-fail" if auth_info["dmarc"] == "FAIL" else "badge-warn")
        st.markdown(f'<span class="{b_cls}">{auth_info["dmarc"]}</span>', unsafe_allow_html=True)

    with a4:
        st.markdown("**ARC Validation**")
        b_cls = "badge-pass" if auth_info["arc"] == "PASS" else ("badge-fail" if auth_info["arc"] == "FAIL" else "badge-warn")
        st.markdown(f'<span class="{b_cls}">{auth_info["arc"]}</span>', unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("#### 🌐 Domain Alignment Matrix")
    
    from_addr = str(msg.get("From", ""))
    ret_addr = str(msg.get("Return-Path", ""))
    rep_addr = str(msg.get("Reply-To", ""))
    
    align_data = threat_intel.analyze_domain_alignment(from_addr, ret_addr, rep_addr)
    
    matrix_df = pd.DataFrame([
        {"Header Path": "Sender (From)", "Address": from_addr, "Extracted Domain": align_data.get("from_domain"), "Alignment Status": "PRIMARY"},
        {"Header Path": "Return-Path", "Address": ret_addr, "Extracted Domain": align_data.get("return_domain"), "Alignment Status": "MATCH" if not align_data.get("is_spoofed") else "MISMATCH / SPOOFED"},
        {"Header Path": "Reply-To", "Address": rep_addr, "Extracted Domain": align_data.get("reply_to_domain"), "Alignment Status": "MATCH" if align_data.get("from_domain") == align_data.get("reply_to_domain") else "DIFFERENT REPLIER"}
    ])
    st.dataframe(matrix_df, use_container_width=True, hide_index=True)

    st.markdown("---")
    st.markdown("#### 🔒 Zero-Knowledge Forensic Verification (ZKFV) Proof")
    st.code(merkle_root, language="text")
    st.button("📋 Copy Merkle Root", key="copy_merkle_t2", on_click=lambda: st.write("Copied!"))

    if st.button("🛡️ Verify Cryptographic Proof", use_container_width=True):
        is_valid, curr_root, exp_root = zkfv.verify_evidence_proof(raw_bytes, zkfv_proof)
        if is_valid:
            st.success("✅ **Evidence Integrity Verified**: Merkle root matches cryptographic proof!")
        else:
            st.error("❌ **Verification Failed**: Proof mismatch!")

    with st.expander("📜 View Forensic Audit Ledger", expanded=False):
        audit_logs = zkfv.get_recent_audit_logs(10)
        if audit_logs:
            st.dataframe(pd.DataFrame(audit_logs), use_container_width=True, hide_index=True)
        else:
            st.caption("No audit log entries recorded yet.")

    st.markdown("</div>", unsafe_allow_html=True)
    render_legal_disclaimer()


# ==========================================
# TAB 3: CONTENT & URL
# ==========================================
with tab3:
    st.markdown("<div class='soc-card'>", unsafe_allow_html=True)
    st.markdown("### 🔗 Extracted URLs & Defanged Threat Analysis")

    if urls:
        url_analysis = threat_intel.analyze_url_structure(urls)
        url_rows = []
        for idx, u_info in enumerate(url_analysis, 1):
            defanged = defang_url(u_info["url"])
            flags = ", ".join(u_info["flags"]) if u_info["flags"] else "Clean"
            url_rows.append({
                "Index": idx,
                "Defanged URL": defanged,
                "Domain": u_info.get("domain", "N/A"),
                "TLD": u_info.get("tld", "N/A"),
                "Is IP": u_info.get("is_ip", False),
                "Threat Flags": flags
            })
        st.dataframe(pd.DataFrame(url_rows), use_container_width=True, hide_index=True)
    else:
        st.info("No URLs extracted from email body.")

    st.markdown("---")
    st.markdown("#### 📊 Stacked Factor Contribution Chart")
    if risk_factors:
        df_factors = pd.DataFrame(risk_factors)
        chart = alt.Chart(df_factors).mark_bar().encode(
            x=alt.X('sum(points):Q', title='Points Contribution'),
            y=alt.Y('category:N', title='Threat Category', sort='-x'),
            color=alt.Color('category:N', scale=alt.Scale(scheme='tableau10')),
            tooltip=['category', 'points', 'description']
        ).properties(height=200)
        st.altair_chart(chart, use_container_width=True)
    else:
        st.success("Zero threat score penalties detected.")

    st.markdown("---")
    st.markdown("#### 📋 Extracted MIME Headers")
    for k, v in headers_dict.items():
        st.markdown(f"**{k}**: `<code class='mono-font'>{v}</code>`", unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)
    render_legal_disclaimer()


# ==========================================
# TAB 4: RELAY & ROUTE
# ==========================================
with tab4:
    st.markdown("<div class='soc-card'>", unsafe_allow_html=True)
    st.markdown("### 🛤️ Received Chain Timeline & Relay Hop Analysis")

    # Received Hops Timeline
    received_headers = msg.get_all("Received", [])
    if received_headers:
        st.markdown("#### Received Hop Chain Timeline")
        hop_rows = []
        for idx, rh in enumerate(reversed(received_headers), 1):
            from_match = re.search(r'from\s+([^\s]+)', str(rh), re.IGNORECASE)
            by_match = re.search(r'by\s+([^\s]+)', str(rh), re.IGNORECASE)
            ip_match = re.search(r'\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]', str(rh))
            
            hop_ip = ip_match.group(1) if ip_match else "N/A"
            trust_level = "TRUSTED / INTERNAL" if (idx == 1 or "google.com" in str(rh).lower()) else "UNTRUSTED / PUBLIC"
            
            hop_rows.append({
                "Hop #": idx,
                "From Host": from_match.group(1) if from_match else "Unknown",
                "By Host": by_match.group(1) if by_match else "Unknown",
                "IP Address": hop_ip,
                "Trust Level": trust_level
            })
        st.dataframe(pd.DataFrame(hop_rows), use_container_width=True, hide_index=True)
    else:
        st.caption("No 'Received:' headers found in MIME data.")

    st.markdown("---")
    st.markdown("#### 🛠️ Threat Infrastructure Relationship Graph")
    
    graph_data = graph_engine.build_threat_infrastructure_graph(from_addr, ret_addr, urls, geo_results)
    plotly_fig = graph_engine.generate_plotly_threat_graph(graph_data)
    st.plotly_chart(plotly_fig, use_container_width=True)
    st.caption(f"Infrastructure Correlation: {graph_data['num_nodes']} Entities, {graph_data['num_edges']} Threat Relationships")

    st.markdown("</div>", unsafe_allow_html=True)
    render_legal_disclaimer()


# ==========================================
# TAB 5: IP & DOMAIN INTEL
# ==========================================
with tab5:
    st.markdown("<div class='soc-card'>", unsafe_allow_html=True)
    st.markdown("### 🗺️ Dynamic Geolocation Map & Campaign Intelligence")

    # Map with DYNAMIC pins
    map_data = []
    for g in geo_results:
        if g.get("status") == "success" and g.get("lat") and g.get("lon"):
            map_data.append({
                "lat": g.get("lat"),
                "lon": g.get("lon"),
                "ip": g.get("ip"),
                "city": g.get("city"),
                "country": g.get("country"),
                "asn": g.get("asn")
            })

    if map_data:
        df_map = pd.DataFrame(map_data)
        st.map(df_map, latitude="lat", longitude="lon", zoom=3)
    else:
        st.info("No public IP coordinates found. Displaying default threat map overview.")
        fallback_df = pd.DataFrame([{"lat": 37.7749, "lon": -122.4194}])
        st.map(fallback_df, latitude="lat", longitude="lon", zoom=2)

    st.markdown("---")
    st.markdown("#### 📡 Extracted IP & ASN Resolution Table")
    if geo_results:
        geo_rows = []
        for g in geo_results:
            ip_val = g.get("ip", "")
            geo_rows.append({
                "IP Address": ip_val,
                "Country": g.get("country", "N/A"),
                "City": g.get("city", "N/A"),
                "ISP": g.get("isp", "N/A"),
                "ASN": g.get("asn", "N/A"),
                "Status": g.get("status", "N/A")
            })
        st.dataframe(pd.DataFrame(geo_rows), use_container_width=True, hide_index=True)

        for g in geo_results:
            ip_val = g.get("ip", "")
            st.button(f"📋 Copy IP {ip_val}", key=f"copy_ip_{ip_val}", on_click=lambda: st.write("Copied!"))
    else:
        st.caption("No IP addresses extracted.")

    st.markdown("---")
    st.markdown("#### 🕸️ Neo4j Campaign Correlation Graph")
    
    neo_status = neo4j_engine.test_connection()
    st.markdown(f"**Neo4j Database Status**: `<span class='badge-info'>{neo_status['status']}</span>`", unsafe_allow_html=True)

    campaigns = neo4j_engine.correlate_campaigns()
    if campaigns:
        st.markdown(f"Detected **{len(campaigns)}** correlated threat campaign cluster(s):")
        st.dataframe(pd.DataFrame(campaigns), use_container_width=True, hide_index=True)
    else:
        st.caption("No multi-email campaign correlations detected.")

    st.markdown("</div>", unsafe_allow_html=True)
    render_legal_disclaimer()
