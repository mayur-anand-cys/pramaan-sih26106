import streamlit as st
import os
import datetime
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
from backend.detection.body_header_check import detect_body_header_spoofing
from backend.detection.xai import (
    detect_contradictions,
    explain_prediction,
    flag_for_analyst_review,
    log_contradiction_to_audit
)

from security_hardening import extract_headers_with_forensics

# Page Configuration
st.set_page_config(
    page_title="PRAMAAN | SOC Threat Intelligence & Digital Forensics",
    page_icon="",
    layout="wide",
    initial_sidebar_state="collapsed"
)
css_path = Path(__file__).parent / "soc" / "static" / "css" / "pramaan-soc.css"
if css_path.exists():
    st.markdown(f"<style>{css_path.read_text(encoding='utf-8')}</style>", unsafe_allow_html=True)
# --- Authentication gate ---
from backend.auth.login_ui import render_login_page
from backend.auth.authenticator import get_current_user, logout as auth_logout
from blockchain.anchor import blockchain_status

if not render_login_page():
    st.stop()

_user = get_current_user()
_role = _user["role"] if _user else "analyst"

# --- Auto-seed demo campaign for Tab 5 (once per session) ---
if (
    _user
    and os.getenv("PRAMAAN_DEMO_MODE", "false").lower() == "true"
    and "demo_seeded" not in st.session_state
):
    try:
        from neo4j_engine import seed_demo_data
        seed_demo_data()
        st.session_state["demo_seeded"] = True
    except Exception:
        pass

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


# --- Sidebar ---
with st.sidebar:
    if _user:
        _sb_uname = _user.get("username", "unknown")
        _sb_initial = _sb_uname[0].upper() if _sb_uname else "U"
        st.markdown(
            '<div style="display:inline-flex; align-items:center; gap:10px; '
            'background: rgba(6,182,212,0.08); '
            'border: 1px solid rgba(6,182,212,0.30); '
            'border-radius: 999px; '
            'padding: 6px 16px 6px 6px; '
            "font-family: 'JetBrains Mono', monospace; "
            'font-size: 0.85rem; color: #22D3EE; margin-bottom: 16px;">'
            '<span style="width:26px; height:26px; border-radius:50%; '
            'background: linear-gradient(135deg, #3b82f6, #2563EB); '
            'display:flex; align-items:center; justify-content:center; '
            'color:#fff; font-weight:800; font-size:0.72rem;">' + _sb_initial + '</span>'
            '<span>' + _sb_uname.upper() + '</span>'
            '</div>',
            unsafe_allow_html=True,
        )
    st.markdown('<div class="sidebar-nav-title">NAVIGATION</div>', unsafe_allow_html=True)
# Role-based theming — solid colors per SOC design system (#102)
# No gradients, no shadows. Color = meaning only.
if _role == "analyst":
    bg_gradient = "#070D14"
    card_bg = "#0F172A"
    card_border = "rgba(6, 182, 212, 0.15)"
else:
    bg_gradient = "#070D14"
    card_bg = "#0F172A"
    card_border = "rgba(6, 182, 212, 0.15)"

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
        background-color: #0F172A !important;
        border-right: 1px solid rgba(6, 182, 212, 0.20) !important;
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
        background-color: rgba(16, 185, 129, 0.15);
        color: #10B981;
        border: 1px solid #10B981;
        padding: 4px 12px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.85rem;
        font-family: 'JetBrains Mono', monospace;
    }}

    .badge-fail {{
        background-color: rgba(244, 63, 94, 0.15);
        color: #F43F5E;
        border: 1px solid #F43F5E;
        padding: 4px 12px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.85rem;
        font-family: 'JetBrains Mono', monospace;
    }}

    .badge-warn {{
        background-color: rgba(245, 158, 11, 0.15);
        color: #F59E0B;
        border: 1px solid #F59E0B;
        padding: 4px 12px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.85rem;
        font-family: 'JetBrains Mono', monospace;
    }}

    .stAppDeployButton, [data-testid="stAppDeployButton"] {{
        display: none !important;
    }}

    /* Streamlit Tabs Styling */
    .stTabs [data-baseweb="tab-list"] {{
        gap: 12px;
        background-color: transparent;
        border-bottom: 2px solid rgba(6, 182, 212, 0.20);
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
        background-color: rgba(6, 182, 212, 0.20) !important;
        color: #06B6D4 !important;
        border-top: 3px solid #06B6D4 !important;
    }}
    
    /* --- pramaan-soc.css --- */
/* ============================================================
   pramaan-soc.css
   PRAMAAN SOC theme — tab borders, chart panels, header pills
   ============================================================ */

/* --- Tabs: consistent bordered look --- */
.stTabs [data-baseweb="tab-list"] {{
    gap: 8px;
    background-color: transparent;
    border-bottom: 1px solid rgba(6, 182, 212, 0.20);
    padding-bottom: 6px;
}}

.stTabs [data-baseweb="tab"] {{
    background-color: #16213B;
    border: 1px solid rgba(6, 182, 212, 0.20);
    border-radius: 6px 6px 0 0;
    color: #94a3b8;
    padding: 10px 20px;
    font-weight: 600;
    font-family: 'Inter', sans-serif;
    transition: border-color 0.15s ease, color 0.15s ease;
}}

.stTabs [data-baseweb="tab"]:hover {{
    border-color: #06B6D4;
    color: #22D3EE;
}}

.stTabs [aria-selected="true"] {{
    background-color: rgba(6, 182, 212, 0.20) !important;
    color: #06B6D4 !important;
    border: 1px solid #06B6D4 !important;
    border-bottom: 1px solid rgba(6, 182, 212, 0.20) !important;
    box-shadow: 0 -2px 0 #06B6D4 inset;
}}

/* --- Chart panel: bordered container for analytical charts --- */
.soc-chart-panel {{
    background-color: rgba(15, 23, 42, 0.4);
    border: 1px solid rgba(6, 182, 212, 0.30);
    border-radius: 10px;
    padding: 16px;
    margin-top: 8px;
    margin-bottom: 20px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.25);
}}

/* --- Top header card --- */
.soc-header {{
    background-color: #16213B;
    border: 1px solid rgba(6, 182, 212, 0.20);
    border-radius: 8px;
    padding: 12px 16px;
    margin-bottom: 16px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.35);
}}

.soc-header-row {{
    display: flex;
    align-items: center;
    gap: 16px;
    justify-content: space-between;
}}

/* --- Status pills --- */
.soc-status-pill {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    border-radius: 9999px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    font-weight: 700;
    letter-spacing: 0.03em;
    border: 1px solid;
}}

.soc-status-ok {{
    background-color: rgba(16, 185, 129, 0.12);
    color: #10B981;
    border-color: #10B981;
}}

.soc-status-bad {{
    background-color: rgba(244, 63, 94, 0.12);
    color: #F43F5E;
    border-color: #F43F5E;
}}

.soc-status-warn {{
    background-color: rgba(245, 158, 11, 0.12);
    color: #F59E0B;
    border-color: #F59E0B;
}}

.soc-status-dot {{
    display: inline-block;
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background-color: currentColor;
}}

/* --- User profile chip --- */
.soc-user-chip {{
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 6px 12px;
    background-color: rgba(6, 182, 212, 0.20);
    border: 1px solid rgba(6, 182, 212, 0.30);
    border-radius: 6px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    color: #e2e8f0;
}}

.soc-user-role {{
    color: #06B6D4;
    font-weight: 700;
    text-transform: uppercase;
    font-size: 0.7rem;
    letter-spacing: 0.05em;
}}
    .soc-card-blue {{
        background: transparent !important;
        border: 1px solid rgba(96,180,255,0.20) !important;
        border-radius: 14px !important;
        box-shadow: none !important;
        backdrop-filter: none !important;
        -webkit-backdrop-filter: none !important;
        padding: 24px 32px 20px 32px;
        margin-bottom: 20px;
    }}

/* --- Search bar --- */
.soc-search input {{
    background-color: #0F172A !important;
    border: 1px solid rgba(6, 182, 212, 0.20) !important;
    color: #e2e8f0 !important;
    border-radius: 6px !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.85rem !important;
}}

.soc-search input:focus {{
    border-color: #06B6D4 !important;
    box-shadow: 0 0 0 2px rgba(6,182,212,0.2) !important;
}}
    [data-testid="stSidebar"] [role="radiogroup"] {{ display: flex; flex-direction: column; gap: 6px; }}
    [data-testid="stSidebar"] [role="radiogroup"] label {{ background-color: #16213B; border: 1px solid rgba(6, 182, 212, 0.20); border-radius: 6px; color: #94a3b8; padding: 10px 14px; font-weight: 600; font-family: 'Inter', sans-serif; font-size: 0.85rem; cursor: pointer; transition: border-color 0.15s ease, color 0.15s ease; }}
    [data-testid="stSidebar"] [role="radiogroup"] label:hover {{ border-color: #06B6D4; color: #22D3EE; }}
    [data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {{ background-color: rgba(6, 182, 212, 0.20) !important; color: #06B6D4 !important; border: 1px solid #06B6D4 !important; box-shadow: -3px 0 0 #06B6D4 inset; }}
    [data-testid="stSidebar"] [role="radiogroup"] label > div:first-child {{ display: none; }}
    [data-testid="stSidebar"] .sidebar-nav-title {{ color: #06B6D4; font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.14em; text-transform: uppercase; margin: 8px 0 12px; }}
    .findings-wrap {{ width: 100%; display: flex; flex-direction: column; gap: 8px; }}
    .finding-row {{ display: flex; align-items: center; gap: 14px; padding: 10px 14px; background: rgba(255,255,255,0.03); border-left: 3px solid #06B6D4; border-radius: 6px; }}
    .finding-row:hover {{ background: rgba(125,211,252,0.08); }}
    .finding-cat {{ font-family: 'Inter', sans-serif; font-weight: 700; font-size: 0.82rem; color: #06B6D4; white-space: nowrap; min-width: 150px; }}
    .finding-pts {{ font-family: 'JetBrains Mono', monospace; font-weight: 600; font-size: 0.8rem; color: #F59E0B; white-space: nowrap; background: rgba(245,158,11,0.10); padding: 3px 10px; border-radius: 4px; }}
    .finding-desc {{ font-family: 'Inter', sans-serif; font-size: 0.88rem; line-height: 1.4; color: #e2e8f0; flex: 1; }}
    /* Screenshot-matched full-width dashboard presentation */
    [data-testid="stAppViewContainer"] > .main .block-container {{ max-width: 100% !important; padding: 0.75rem 1.2rem 1rem !important; }}
    .dashboard-topbar {{ display:flex; align-items:center; gap:14px; background:#0F172A; border:1px solid rgba(6, 182, 212, 0.20); border-radius:8px; padding:8px 14px; margin-bottom:10px; }}
    .dashboard-brand {{ display:flex; align-items:center; gap:8px; color:#f8fafc; font-size:0.92rem; font-weight:800; letter-spacing:0.02em; white-space:nowrap; }}
    .dashboard-brand-icon {{ width:22px; height:22px; border-radius:5px; background:linear-gradient(135deg,#22D3EE,#3B82F6); display:inline-flex; align-items:center; justify-content:center; color:#e0f2fe; font-size:0.72rem; }}
    .dashboard-search input {{ background:#16213B !important; border:1px solid rgba(6, 182, 212, 0.30) !important; border-radius:999px !important; color:#94a3b8 !important; font-size:0.72rem !important; height:30px !important; }}
    .dashboard-alerts {{ color:#f8fafc; font-size:0.72rem; font-weight:700; white-space:nowrap; }}
    .dashboard-user {{ color:#e2e8f0; font-size:0.72rem; font-weight:700; text-align:right; white-space:nowrap; }}
    .dashboard-user small {{ color:#94a3b8; font-family:'JetBrains Mono',monospace; font-size:0.62rem; }}
    .dashboard-status-row {{ display:flex; justify-content:center; gap:8px; margin:-2px 0 8px; }}
    .dashboard-status-row .soc-status-pill {{ font-size:0.62rem; padding:3px 9px; }}
    .stTabs {{ margin-top:0 !important; }}
    .stTabs [data-baseweb="tab-list"] {{ gap:0 !important; border-bottom:1px solid rgba(6, 182, 212, 0.30) !important; }}
    .stTabs [data-baseweb="tab"] {{ font-size:0.68rem !important; padding:7px 12px !important; }}
    </style>
""", unsafe_allow_html=True)

# --- UPLOAD FLOW HANDLING ---
if "raw_bytes" not in st.session_state:
    st.session_state["raw_bytes"] = None
    st.session_state["file_name"] = ""

raw_bytes = st.session_state["raw_bytes"]
file_name = st.session_state["file_name"]

# --- LANDING PAGE (Pre-Upload) ---
if raw_bytes is None:

    st.markdown("""
    <style>
    @keyframes pramaan-page-in {
        0% {
            opacity: 0;
            transform: translateY(12px);
        }
        100% {
            opacity: 1;
            transform: translateY(0);
        }
    }

    html, body, [data-testid="stAppViewContainer"] {
        animation: pramaan-page-in 700ms cubic-bezier(0.22, 1, 0.36, 1);
    }

    /* Individual elements stagger in slightly for a premium feel */
    div[data-testid="stVerticalBlockBorderWrapper"] {
        animation: pramaan-page-in 700ms cubic-bezier(0.22, 1, 0.36, 1) 100ms backwards;
    }

    .landing-col1, .landing-col2, .landing-col3 {
        animation: pramaan-page-in 700ms cubic-bezier(0.22, 1, 0.36, 1) 200ms backwards;
    }
    section[data-testid="stSidebar"] {
        display: none !important;
        visibility: hidden !important;
        width: 0 !important;
    }
    [data-testid="collapsedControl"],
    [data-testid="stSidebarCollapsedControl"],
    [data-testid="stSidebarNav"] {
        display: none !important;
    }
    html, body {
        height: 100vh !important;
        overflow: hidden !important;
    }
    html, body, [data-testid="stAppViewContainer"] {
        background: radial-gradient(ellipse at 50% 40%,
            #0c2b52 0%, #0a1e3d 25%, #071428 55%, #030a18 100%) !important;
        background-attachment: fixed !important;
    }
    [data-testid="stAppViewContainer"] > .main,
    [data-testid="stMain"],
    .block-container {
        height: 100vh !important;
        overflow: hidden !important;
        padding-top: 0 !important;
        padding-bottom: 0 !important;
    }
    ::-webkit-scrollbar { display: none !important; }
    [data-testid="stAppViewContainer"]::-webkit-scrollbar { display: none !important; }
    [data-testid="stAppDeployButton"], .stAppDeployButton { display: none !important; }

    .circuit-overlay {
        position: fixed; inset: 0; pointer-events: none; z-index: 0;
        background-image:
            linear-gradient(rgba(96,180,255,0.18) 1px, transparent 1px),
            linear-gradient(90deg, rgba(96,180,255,0.18) 1px, transparent 1px);
        background-size: 52px 52px;
        mask-image: radial-gradient(circle at 50% 30%, black 0%, transparent 78%);
        -webkit-mask-image: radial-gradient(circle at 50% 30%, black 0%, transparent 78%);
        animation: gridDrift 30s linear infinite, gridPulse 6s ease-in-out infinite;
    }
    @keyframes gridDrift {
        0%   { background-position: 0px 0px, 0px 0px; }
        100% { background-position: 52px 52px, 52px 52px; }
    }
    @keyframes gridPulse {
        0%, 100% { opacity: 0.55; }
        50%      { opacity: 1; }
    }

    .landing-stars { position: fixed; inset: 0; pointer-events: none; z-index: 0; }
    .star {
        position: absolute; width: 2px; height: 2px; border-radius: 50%;
        background: #bae6fd; opacity: 0.5;
        box-shadow: 0 0 6px rgba(186,230,253,0.8);
        animation: twinkle 3.2s ease-in-out infinite;
    }
    @keyframes twinkle {
        0%, 100% { opacity: 0.15; transform: scale(1); }
        50%      { opacity: 1;    transform: scale(1.6); }
    }

    div[data-testid="stVerticalBlockBorderWrapper"] {
        background: linear-gradient(160deg, rgba(6,182,212,0.10) 0%, rgba(15,23,42,0.60) 100%) !important;
        border: 1px solid rgba(6,182,212,0.35) !important;
        border-radius: 14px !important;
        box-shadow: 0 12px 40px rgba(0,0,0,0.4), inset 0 1px 0 rgba(150,210,255,0.25) !important;
        padding: 4px 6px !important;
    }

    .landing-shield-wrap {
        position: relative; width: 72px; height: 72px;
        margin: 0 auto 2px auto;
        display: flex; align-items: center; justify-content: center;
    }
    .landing-shield-glow {
        position: absolute; width: 72px; height: 72px; border-radius: 50%;
        background: radial-gradient(circle, rgba(56,189,248,0.30) 0%, rgba(20,80,110,0.16) 45%, rgba(0,0,0,0) 72%);
        z-index: 0;
        animation: shieldBreathe 4s ease-in-out infinite;
    }
    @keyframes shieldBreathe {
        0%, 100% { transform: scale(1); opacity: 0.85; }
        50%      { transform: scale(1.08); opacity: 1; }
    }
    .landing-shield {
        width: 52px; height: 52px;
        position: relative; z-index: 1;
        filter: drop-shadow(0 0 18px rgba(56,189,248,0.65));
    }
    .trust-badge {
        display: inline-block;
        background: rgba(96,180,255,0.18);
        border: 1px solid rgba(96,180,255,0.55);
        color: #d4eeff;
        padding: 4px 11px; border-radius: 20px;
        font-size: 0.68rem; font-weight: 700; letter-spacing: 0.04em;
        margin: 0 4px 6px 4px;
        font-family: 'JetBrains Mono', monospace;
    }
    .soc-footer {
        position: fixed; bottom: 12px; right: 20px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.72rem; color: #64748b;
        background: rgba(5, 15, 28, 0.7);
        border: 1px solid rgba(56,189,248,0.15);
        padding: 6px 12px; border-radius: 6px;
        z-index: 100;
        display: flex; align-items: center; gap: 8px;
    }
    .soc-footer .pulse-dot {
        width: 7px; height: 7px; border-radius: 50%;
        background: #10B981; box-shadow: 0 0 8px #10B981;
        animation: pulse-green 2s ease-in-out infinite;
    }
    @keyframes pulse-green {
        0%, 100% { opacity: 1; }
        50%      { opacity: 0.4; }
    }

    .pramaan-title {
        font-size: 1.35rem !important;
        font-weight: 800;
        color: #f8fafc;
        letter-spacing: 1px;
        text-transform: uppercase;
        margin-top: 2px;
        line-height: 1.15;
    }
    .pramaan-sub {
        font-size: 0.82rem !important;
        color: #7dd3fc;
        margin-top: 2px;
        margin-bottom: 10px;
        font-weight: 600;
    }
    .pramaan-desc {
        font-size: 0.78rem !important;
        color: #94A3B8;
        margin-top: 8px;
        margin-bottom: 2px;
        line-height: 1.5;
    }

    /* ---- Aurora orbs ---- */
    .orb {
        position: fixed;
        border-radius: 50%;
        filter: blur(90px);
        opacity: 0.40;
        animation: orb-drift 24s ease-in-out infinite;
        pointer-events: none;
        z-index: 0;
    }
    .orb.o1 { width: 520px; height: 520px; background: #58a6ff; top: -15%; left: -10%; }
    .orb.o2 { width: 440px; height: 440px; background: #a371f7; bottom: -18%; left: 35%; animation-duration: 30s; animation-delay: -4s; }
    .orb.o3 { width: 400px; height: 400px; background: #3fb950; top: 40%; right: -12%; animation-duration: 36s; animation-delay: -10s; opacity: 0.22; }
    @keyframes orb-drift {
        0%, 100% { transform: translate(0, 0) scale(1); }
        33%      { transform: translate(60px, -40px) scale(1.08); }
        66%      { transform: translate(-50px, 50px) scale(0.94); }
    }

    /* ---- Floating particles ---- */
    .particle {
        position: fixed;
        width: 3px; height: 3px;
        border-radius: 50%;
        background: #58a6ff;
        box-shadow: 0 0 10px 2px rgba(88,166,255,0.7);
        animation: float-up 20s linear infinite;
        opacity: 0;
        pointer-events: none;
        z-index: 1;
    }
    .particle.p1 { left: 10%; animation-delay: 0s; }
    .particle.p2 { left: 25%; animation-delay: 4s; background: #a371f7; box-shadow: 0 0 10px 2px rgba(163,113,247,0.7); }
    .particle.p3 { left: 45%; animation-delay: 8s; }
    .particle.p4 { left: 62%; animation-delay: 2s; background: #3fb950; box-shadow: 0 0 10px 2px rgba(63,185,80,0.7); }
    .particle.p5 { left: 78%; animation-delay: 6s; }
    .particle.p6 { left: 92%; animation-delay: 10s; background: #a371f7; box-shadow: 0 0 10px 2px rgba(163,113,247,0.7); }
    @keyframes float-up {
        0%   { top: 100%; opacity: 0; }
        10%  { opacity: 0.9; }
        90%  { opacity: 0.9; }
        100% { top: -5%; opacity: 0; }
    }
    </style>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class='circuit-overlay'></div>
    <div class='orb o1'></div>
    <div class='orb o2'></div>
    <div class='orb o3'></div>
    <div class='particle p1'></div>
    <div class='particle p2'></div>
    <div class='particle p3'></div>
    <div class='particle p4'></div>
    <div class='particle p5'></div>
    <div class='particle p6'></div>
    """, unsafe_allow_html=True)

    star_positions = [
        (4, 10, 0.0), (8, 22, 0.3), (12, 78, 0.6), (16, 45, 0.9), (20, 62, 1.2),
        (24, 34, 0.5), (28, 88, 0.8), (32, 15, 1.1), (36, 72, 0.2), (40, 8, 0.7),
        (44, 55, 1.4), (48, 40, 0.4), (52, 92, 1.0), (56, 25, 0.6), (60, 68, 1.3),
        (64, 48, 0.1), (68, 85, 0.9), (72, 12, 0.5), (76, 58, 1.2), (80, 30, 0.3),
        (84, 75, 0.8), (88, 42, 1.1), (92, 20, 0.2), (96, 65, 0.7),
    ]
    stars_html = "<div class='landing-stars'>"
    for top, left, delay in star_positions:
        stars_html += f"<span class='star' style='top:{top}%; left:{left}%; animation-delay:{delay}s;'></span>"
    stars_html += "</div>"
    st.markdown(stars_html, unsafe_allow_html=True)

    st.markdown(f"""
    <div class="soc-footer">
        <span class="pulse-dot"></span>
        SOC Active · Pipeline Ready · {datetime.datetime.now().strftime('%H:%M:%S')}
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<div style='margin-top: 0px;'></div>", unsafe_allow_html=True)

    landing_col1, landing_col2, landing_col3 = st.columns([1, 2, 1])
    with landing_col2:
        st.markdown("""
            <div class='soc-card-blue' style='text-align: center; padding: 14px 26px 14px 26px;'>
            <div class='landing-shield-wrap'>
                <div class='landing-shield-glow'></div>
                <svg class='landing-shield' viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M50 6 L86 20 V48 C86 72 71 88 50 96 C29 88 14 72 14 48 V20 Z"
                          stroke="#7dd3fc" stroke-width="3" fill="rgba(56,189,248,0.10)"/>
                    <path d="M50 14 L78 25 V48 C78 68 66 81 50 88 C34 81 22 68 22 48 V25 Z"
                          stroke="#7dd3fc" stroke-width="1" stroke-opacity="0.5" fill="none"/>
                    <circle cx="50" cy="30" r="1.6" fill="#7dd3fc"/>
                    <circle cx="30" cy="45" r="1.6" fill="#7dd3fc"/>
                    <circle cx="70" cy="45" r="1.6" fill="#7dd3fc"/>
                    <circle cx="35" cy="70" r="1.6" fill="#7dd3fc"/>
                    <circle cx="65" cy="70" r="1.6" fill="#7dd3fc"/>
                    <path d="M50 30 L30 45 M50 30 L70 45 M30 45 L35 70 M70 45 L65 70"
                          stroke="#7dd3fc" stroke-width="0.6" stroke-opacity="0.55"/>
                    <rect x="38" y="50" width="24" height="19" rx="3"
                          stroke="#e6f7ff" stroke-width="2.4" fill="rgba(125,211,252,0.14)"/>
                    <path d="M42 50 V43 a8 8 0 0 1 16 0 V50"
                          stroke="#e6f7ff" stroke-width="2.4" fill="none" stroke-linecap="round"/>
                    <circle cx="50" cy="58" r="2.6" fill="#e6f7ff"/>
                    <line x1="50" y1="60.5" x2="50" y2="64" stroke="#e6f7ff" stroke-width="2" stroke-linecap="round"/>
                </svg>
            </div>
            <div class='pramaan-title'>PRAMAAN Threat Intelligence</div>
            <div class='pramaan-sub'>Enterprise-Grade Digital Forensics &amp; Phishing Incident Response</div>
            <div>
                <span class='trust-badge'>SHA-256 VERIFIED</span>
                <span class='trust-badge'>ZERO-KNOWLEDGE PROOF</span>
                <span class='trust-badge'>SOC ANALYST GRADE</span>
            </div>
            <div class='pramaan-desc'>
                Upload a suspect <code style='color:#06B6D4;'>.eml</code> file to begin a cryptographically-verified forensic
                inspection — authentication analysis, URL &amp; IP threat correlation, relay tracing,
                and geolocation intelligence, all anchored to tamper-evident blockchain evidence.
            </div>
        </div>
        """, unsafe_allow_html=True)

        _up1, _up2, _up3 = st.columns([1, 2, 1])
        with _up2:
            uploaded_landing = st.file_uploader(
                "Upload .eml file",
                type=["eml"],
                key="landing_upload",
                label_visibility="collapsed",
            )
        st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
        if _user:
            _uname = _user.get("username", "unknown")
            _initial = _uname[0].upper() if _uname else "U"
            st.markdown(f"""
            <div style="display:flex; justify-content:center; margin-top:6px;">
                <div style="display:inline-flex; align-items:center; gap:10px;
                            background: rgba(56,189,248,0.08);
                            border: 1px solid rgba(56,189,248,0.30);
                            border-radius: 999px;
                            padding: 6px 16px 6px 6px;
                            font-family: 'JetBrains Mono', monospace;
                            font-size: 0.88rem; color: #bae6fd;">
                    <span style="width:26px; height:26px; border-radius:50%;
                                 background: linear-gradient(135deg, #3b82f6, #2563EB);
                                 display:flex; align-items:center; justify-content:center;
                                 color:#fff; font-weight:800; font-size:0.75rem;">{_initial}</span>
                    <span>{_uname}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

        _so1, _so2, _so3 = st.columns([2, 1, 2])
        with _so2:
            if st.button("Sign out", key="landing_signout", use_container_width=True):
                auth_logout()
                st.rerun()

        if uploaded_landing is not None:
            st.session_state["raw_bytes"] = uploaded_landing.getvalue()
            st.session_state["file_name"] = uploaded_landing.name
            st.rerun()
        else:
            st.stop()

# --- DASHBOARD (Post-Upload) ---
# Auto-expand sidebar only on the dashboard (post-upload)
st.markdown(
    """
    <style>
    section[data-testid="stSidebar"] {
        display: block !important;
        visibility: visible !important;
        transform: translateX(0) !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Process Email Artifacts
msg = email.message_from_bytes(raw_bytes, policy=policy.default)
sha256_hash = compute_sha256(raw_bytes)
body_text = extract_email_body(msg)
subject_text = str(msg.get("Subject", ""))

urls = extract_urls(body_text + " " + subject_text)
ips = extract_ips(body_text + " " + str(msg))
auth_info = analyze_authentication_headers(msg)
header_forensics = extract_headers_with_forensics(msg)

# ML Phishing Probability
full_text_for_ml = f"{subject_text}\n{body_text}"
ml_prob = predict_phishing_probability(full_text_for_ml)

# Risk Calculation
risk_score, risk_factors = calculate_risk_score(msg, body_text, urls, ips, auth_info, ml_prob)

# Merge header injection anomalies into risk factors
for _anomaly in header_forensics.get("header_injection_anomalies", []):
    risk_factors.append({
        "category": "Header Injection",
        "points": _anomaly["risk_modifier"],
        "description": _anomaly["explanation"],
    })
    risk_score = min(100, risk_score + _anomaly["risk_modifier"])


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
    risk_color = "#F43F5E"
elif risk_score >= 35:
    risk_level = "MODERATE RISK"
    risk_color = "#F59E0B"
else:
    risk_level = "LOW RISK"
    risk_color = "#10B981"

from_addr = str(msg.get("From", ""))
ret_addr = str(msg.get("Return-Path", ""))
rep_addr = str(msg.get("Reply-To", ""))

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

# Relay Hop Extraction
hop_rows = []
received_headers = msg.get_all("Received", [])
for idx, rh in enumerate(reversed(received_headers), 1):
    from_match = re.search(r"from\s+([^\s]+)", str(rh), re.IGNORECASE)
    by_match = re.search(r"by\s+([^\s]+)", str(rh), re.IGNORECASE)
    ip_match = re.search(r"\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]", str(rh))
    hop_ip = ip_match.group(1) if ip_match else "N/A"
    trust_level = "TRUSTED / INTERNAL" if (idx == 1 or "google" in str(rh).lower()) else "UNKNOWN"
    hop_rows.append({
        "Hop #": idx,
        "From Host": from_match.group(1) if from_match else "Unknown",
        "By Host": by_match.group(1) if by_match else "Unknown",
        "IP Address": hop_ip,
        "Trust Level": trust_level,
    })

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
    merkle_root=merkle_root,
    case_id=f"PRAMAAN-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}",
    analyst="Sneha Namrath",
    relay_hops=hop_rows,
)

# --- 5 HORIZONTAL TABS ---
with st.sidebar:
    selected_tab = st.radio(
        "NAVIGATION",
        ["Triage Overview", "Auth & Content", "Relay & Route",
         "IP & Domain Intel"],
        label_visibility="collapsed",
        key="main_nav",
    )
    st.markdown("<div style='height: 24px;'></div>", unsafe_allow_html=True)
    st.markdown("---")
    if st.button("Sign out", key="sidebar_signout", use_container_width=True):
        auth_logout()
        st.rerun()
# --- TOP-LEVEL CONTRADICTION BANNER (shows on every tab) ---
# ---- CONTRADICTION BANNER (unchanged logic) ----
if xai_result.get("severity") == "CRITICAL":
    crit_alerts = [a for a in xai_result.get("alerts", []) if a.get("severity") == "CRITICAL"]
    alert_desc = crit_alerts[0].get("description") if crit_alerts else "AI verdict directly conflicts with cryptographic authentication failure."
    st.markdown(f"""
    <div style="background: linear-gradient(135deg, rgba(239, 68, 68, 0.25) 0%, rgba(153, 27, 27, 0.35) 100%);
                border: 2px solid #ef4444; border-radius: 8px; padding: 12px 18px; margin-bottom: 14px;">
        <div style="display: flex; align-items: center; justify-content: space-between;">
            <div>
                <h3 style="color: #ef4444; margin: 0; font-size: 1.05rem; font-weight: 800;">CRITICAL XAI CONTRADICTION DETECTED</h3>
                <p style="color: #fca5a5; margin: 3px 0 0 0; font-size: 0.85rem;">{alert_desc}</p>
            </div>
            <span style="background-color: #ef4444; color: #ffffff; padding: 5px 12px; border-radius: 9999px; font-weight: 800; font-size: 0.75rem;">ANALYST REVIEW REQUIRED</span>
        </div>
    </div>
    """, unsafe_allow_html=True)
elif xai_result.get("severity") == "HIGH":
    high_alerts = [a for a in xai_result.get("alerts", []) if a.get("severity") == "HIGH"]
    alert_desc = high_alerts[0].get("description") if high_alerts else "AI flagged email as phishing but authentication passed."
    st.markdown(f"""
    <div style="background: rgba(245, 158, 11, 0.10);
                border: 2px solid #F59E0B; border-radius: 8px; padding: 12px 18px; margin-bottom: 14px;">
        <h3 style="color: #F59E0B; margin: 0; font-size: 1.05rem; font-weight: 800;">HIGH XAI CONTRADICTION — POTENTIAL FALSE POSITIVE</h3>
        <p style="color: #F59E0B; margin: 3px 0 0 0; font-size: 0.85rem;">{alert_desc}</p>
    </div>
    """, unsafe_allow_html=True)
elif xai_result.get("severity") == "AMBER":
    amber_alerts = [a for a in xai_result.get("alerts", []) if a.get("severity") == "AMBER"]
    alert_desc = amber_alerts[0].get("description") if amber_alerts else "Low model confidence amidst high threat score."
    st.markdown(f"""
    <div style="background: rgba(245, 158, 11, 0.08);
                border: 2px solid #F59E0B; border-radius: 8px; padding: 10px 16px; margin-bottom: 14px;">
        <h3 style="color: #F59E0B; margin: 0; font-size: 1rem; font-weight: 800;">AMBER XAI CONTRADICTION — MODEL AMBIGUITY</h3>
        <p style="color: #F59E0B; margin: 3px 0 0 0; font-size: 0.85rem;">{alert_desc}</p>
    </div>
    """, unsafe_allow_html=True)

# --- STATUS PILLS ROW (Neo4j + Sepolia) ---
_neo = neo4j_engine.test_connection()
_neo_ok = _neo.get("mode") == "neo4j" or _neo.get("status") in ("CONNECTED", "Live Neo4j")
_neo_cls = "soc-status-ok" if _neo_ok else "soc-status-bad"
_neo_txt = "Neo4j " + ("CONNECTED" if _neo_ok else "OFFLINE")

try:
    _sep = blockchain_status()
    _sep_mode = _sep.get("mode", "SIMULATED")
    if _sep_mode == "LIVE":
        _sep_cls, _sep_txt = "soc-status-ok", "Sepolia LIVE"
    elif _sep.get("connected"):
        _sep_cls, _sep_txt = "soc-status-warn", "Sepolia READY"
    else:
        _sep_cls, _sep_txt = "soc-status-bad", "Sepolia OFFLINE"
except Exception:
    _sep_cls, _sep_txt = "soc-status-bad", "Sepolia OFFLINE"

st.markdown(
    '<div class="dashboard-status-row" style="display:flex; justify-content:center; gap:8px; margin:4px 0 12px;">'
    '<span class="soc-status-pill ' + _sep_cls + '">'
    '<span class="soc-status-dot"></span>' + _sep_txt + '</span>'
    '<span class="soc-status-pill ' + _neo_cls + '">'
    '<span class="soc-status-dot"></span>' + _neo_txt + '</span>'
    '</div>',
    unsafe_allow_html=True,
)
# ==========================================
# TAB 1: TRIAGE OVERVIEW
# ==========================================
if selected_tab == "Triage Overview":
    st.markdown("<div class='soc-card'>", unsafe_allow_html=True)

    # ---- ROW 1: Executive Summary + Gauge (single card row) ----
    r1_left, r1_right = st.columns([3, 1])

    with r1_left:
        st.markdown("#### Executive Summary")
        st.markdown(
            f"**Target Artifact:** <code style='color:#06B6D4;background:rgba(6, 182, 212, 0.20);padding:2px 8px;border-radius:4px;'>{file_name}</code>",
            unsafe_allow_html=True,
        )
        st.markdown(
            f"**Target EML Hash:** <code style='color:#10B981;font-family:JetBrains Mono,monospace;font-size:0.82rem;'>{sha256_hash}</code>",
            unsafe_allow_html=True,
        )
        st.markdown(
            f"**ML Phishing Probability:** <font color='#06B6D4'><b>{ml_prob * 100:.1f}%</b></font>",
            unsafe_allow_html=True,
        )

        b1, b2, b3 = st.columns(3)
        with b1:
            st.button("Copy Hash", key="copy_hash_t1", use_container_width=True)
        with b2:
            if st.button("Upload another .eml", key="reset_btn_t1", use_container_width=True):
                st.session_state["raw_bytes"] = None
                st.session_state["file_name"] = ""
                st.rerun()
        with b3:
            st.download_button(
                label="Download Report",
                data=pdf_bytes,
                file_name="PRAMAAN_Report_" + file_name + ".pdf",
                mime="application/pdf",
                use_container_width=True,
                key="dl_t1",
            )

    with r1_right:
        if risk_score >= 65:
            gauge_color = "#F43F5E"
        elif risk_score >= 35:
            gauge_color = "#F59E0B"
        else:
            gauge_color = "#10B981"

        gauge_fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=risk_score,
            number={
                "font": {"size": 34, "family": "JetBrains Mono, monospace", "color": gauge_color},
                "suffix": "<span style='font-size:13px;color:#8b949e'> / 100</span>",
            },
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "rgba(6, 182, 212, 0.15)",
                         "tickfont": {"size": 9, "color": "#6e7681"}, "dtick": 25},
                "bar": {"color": gauge_color, "thickness": 0.30},
                "bgcolor": "#0F172A",
                "borderwidth": 0,
                "steps": [
                    {"range": [0, 35],  "color": "rgba(63,185,80,0.08)"},
                    {"range": [35, 65], "color": "rgba(210,153,34,0.08)"},
                    {"range": [65, 100],"color": "rgba(248,81,73,0.08)"},
                ],
                "threshold": {"line": {"color": "#e6edf3", "width": 2},
                              "thickness": 0.75, "value": risk_score},
            },
        ))
        gauge_fig.update_layout(
            height=170,
            margin={"l": 0, "r": 0, "t": 0, "b": 0},
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font={"family": "Inter, sans-serif", "color": "#e6edf3"},
        )
        st.markdown(
            '<div style="border: 1px solid rgba(6, 182, 212, 0.30); '
            'border-radius: 10px; padding: 8px; '
            'background: rgba(15, 23, 42, 0.4);">',
            unsafe_allow_html=True,
        )
        st.plotly_chart(gauge_fig, use_container_width=True, config={"displayModeBar": False})
        st.markdown('</div>', unsafe_allow_html=True)
        st.markdown(
            f"""<div style="text-align:center;margin-top:-12px;">
                <span style="background:{gauge_color}22;border:1px solid {gauge_color};
                             color:{gauge_color};padding:3px 12px;border-radius:5px;
                             font-weight:800;font-size:0.78rem;
                             font-family:'JetBrains Mono',monospace;
                             letter-spacing:0.8px;">
                    {risk_level}
                </span>
            </div>""",
            unsafe_allow_html=True,
        )

    st.markdown("---")

    # ---- ROW 2: Findings (left) + Breakdown (right) ----
    r2_left, r2_right = st.columns([3, 2])

    with r2_left:
        st.markdown("#### Key Threat Findings")
        if risk_factors:
            for factor in sorted(risk_factors, key=lambda f: f["points"], reverse=True):
                st.markdown(
                    f"<div style='padding:5px 0;border-bottom:1px solid rgba(6,182,212,0.12);'>"
                    f"<span style='color:#06B6D4;font-weight:700;font-size:0.82rem;'>{factor['category']}</span> "
                    f"<span style='color:#F59E0B;font-family:JetBrains Mono,monospace;font-size:0.76rem;'>(+{factor['points']} pts)</span>: "
                    f"<span style='color:#e2e8f0;font-size:0.82rem;'>{factor['description']}</span>"
                    f"</div>",
                    unsafe_allow_html=True,
                )
        else:
            st.success("No critical threat factors detected in this email.")

    with r2_right:
        st.markdown("#### Threat Factor Weight Breakdown")
        if risk_factors:
            df_f = pd.DataFrame(risk_factors)
            chart = alt.Chart(df_f).mark_bar(
                cornerRadiusTopRight=4,
                cornerRadiusBottomRight=4,
                size=22,
            ).encode(
                x=alt.X(
                    'points:Q',
                    title='Score Penalty Points',
                    axis=alt.Axis(labelFontSize=10, titleFontSize=11,
                                  titleColor='#94a3b8', labelColor='#94a3b8',
                                  gridColor='rgba(6, 182, 212, 0.20)', gridDash=[3, 3],
                                  domain=True,
                                  domainColor='rgba(6, 182, 212, 0.30)',
                                  tickColor='rgba(6, 182, 212, 0.30)'),
                ),
                y=alt.Y(
                    'category:N',
                    title='',
                    sort='-x',
                    axis=alt.Axis(labelFontSize=11, labelColor='#e2e8f0',
                                  labelPadding=8, labelLimit=180,
                                  domain=True,
                                  domainColor='rgba(6, 182, 212, 0.30)',
                                  tickColor='rgba(6, 182, 212, 0.30)'),
                ),
                color=alt.Color(
                    'category:N',
                    scale=alt.Scale(
                        domain=['Suspicious Keywords', 'Authentication',
                                'ML Classifier', 'URL Metrics',
                                'Header Mismatch', 'Header Injection'],
                        range=['#06B6D4', '#3B82F6', '#A855F7',
                               '#F59E0B', '#EC4899', '#F43F5E'],
                    ),
                    legend=None,
                ),
                tooltip=[
                    alt.Tooltip('category:N', title='Category'),
                    alt.Tooltip('points:Q', title='Points'),
                    alt.Tooltip('description:N', title='Description'),
                ],
            ).properties(height=max(160, len(risk_factors) * 42))
            st.altair_chart(
                chart.configure_view(
                    stroke='rgba(6, 182, 212, 0.30)',
                    strokeWidth=1,
                ),
                width='stretch',
            )
        else:
            st.info("Clean factor breakdown.")

    st.markdown("---")

    # ---- ROW 3: Full-width SHAP Model Attributions ----
    st.markdown("#### Explainable AI (XAI) — SHAP Model Attributions")
    w_data = xai_explanation.get("waterfall_data", {})
    if w_data and w_data.get("labels"):
        labels = w_data["labels"]
        vals = w_data["values"]
        base_v = w_data.get("base_value", 0.0)
        wf_measures = ["relative"] * len(labels) + ["total"]
        wf_x = labels + ["Total"]
        wf_y = vals + [sum(vals)]
        fig = go.Figure(go.Waterfall(
            name="SHAP",
            orientation="v",
            measure=wf_measures,
            x=wf_x,
            y=wf_y,
            base=base_v,
            decreasing={"marker": {"color": "#10B981"}},
            increasing={"marker": {"color": "#F43F5E"}},
            totals={"marker": {"color": "#A855F7"}},
            connector={"line": {"color": "#64748b", "width": 1.2, "dash": "dot"}},
            text=[f"{v:+.3f}" for v in vals] + [f"{sum(vals):.3f}"],
            textposition="outside",
            textfont={"size": 10},
        ))
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(15, 23, 42, 0.6)",
            font=dict(color="#94a3b8", family="Inter", size=11),
            xaxis=dict(title="Influential Tokens / N-Grams", gridcolor="rgba(6, 182, 212, 0.30)", tickfont=dict(size=10)),
            yaxis=dict(title="Weight (Log-Odds)", gridcolor="rgba(6, 182, 212, 0.30)", tickfont=dict(size=10)),
            height=380,
            margin=dict(l=20, r=20, t=20, b=40),
        )
        st.markdown(
            '<div style="border: 1px solid rgba(6, 182, 212, 0.30); '
            'border-radius: 10px; padding: 8px; '
            'background: rgba(15, 23, 42, 0.4);">',
            unsafe_allow_html=True,
        )
        st.plotly_chart(fig, width='stretch')
        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.caption("No SHAP data available.")

    # ---- ROW 4: Positive and Negative Signal Tables ----
    signal_left, signal_right = st.columns(2)
    with signal_left:
        st.markdown("#### Top Phishing Signals (Positive Impact)")
        pos_f = xai_explanation.get("top_positive_features", [])
        if pos_f:
            st.dataframe(
                pd.DataFrame(pos_f).rename(columns={"feature": "Token Feature", "attribution": "SHAP Weight"}),
                width='stretch',
                hide_index=True,
            )
        else:
            st.caption("No significant phishing tokens detected.")
    with signal_right:
        st.markdown("#### Top Legitimate Signals (Negative Impact)")
        neg_f = xai_explanation.get("top_negative_features", [])
        if neg_f:
            st.dataframe(
                pd.DataFrame(neg_f).rename(columns={"feature": "Token", "attribution": "SHAP Weight"}),
                width='stretch',
                hide_index=True,
            )
        else:
            st.caption("No significant legitimate tokens detected.")
    st.markdown("</div>", unsafe_allow_html=True)
# ==========================================
# TAB 2: AUTHENTICATION
# ==========================================
elif selected_tab == "Auth & Content":
    st.markdown("<div class='soc-card'>", unsafe_allow_html=True)
    st.markdown("### Authentication Protocols & Domain Alignment Matrix")

    # --- ROW 1: Auth pills ---
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

    if header_forensics.get("header_injection_anomalies"):
        st.markdown("---")
        st.markdown("#### Header Injection Anomalies")
        for _a in header_forensics["header_injection_anomalies"]:
            st.error(
                "**HIGH** — Header injection: `" + _a["header"] + "` appears "
                + str(_a["count"]) + " times (+" + str(_a["risk_modifier"])
                + " risk). " + _a["explanation"]
            )

    # --- ROW 2: Domain Alignment Matrix (full width) ---
    st.markdown("---")
    st.markdown("#### Domain Alignment Matrix")


    align_data = threat_intel.analyze_domain_alignment(from_addr, ret_addr, rep_addr)

    matrix_df = pd.DataFrame([
        {"Header Path": "Sender (From)", "Address": from_addr,
         "Extracted Domain": align_data.get("from_domain"),
         "Alignment Status": "PRIMARY"},
        {"Header Path": "Return-Path", "Address": ret_addr,
         "Extracted Domain": align_data.get("return_domain"),
         "Alignment Status": "MATCH" if not align_data.get("is_spoofed") else "MISMATCH / SPOOFED"},
        {"Header Path": "Reply-To", "Address": rep_addr,
         "Extracted Domain": align_data.get("reply_to_domain"),
         "Alignment Status": "MATCH" if align_data.get("from_domain") == align_data.get("reply_to_domain") else "DIFFERENT REPLIER"}
    ])
    st.dataframe(matrix_df, width='stretch', hide_index=True)

    # ============================================
    # ROW 3: Incident Overview | Info Box
    # ============================================
    row1_left, row1_right = st.columns([3, 2])

    with row1_left:
        st.markdown("#### Incident Overview")
        st.markdown(
            f"**Subject:** {headers_dict.get('Subject', 'N/A')}<br>"
            f"**From:** {headers_dict.get('From', 'N/A')}<br>"
            f"**To:** {headers_dict.get('To', 'N/A')}<br>"
            f"**Date:** {headers_dict.get('Date', 'N/A')}",
            unsafe_allow_html=True,
        )

    with row1_right:
        st.markdown(
            '<div style="background: rgba(6,182,212,0.08); '
            'border: 1px solid rgba(6,182,212,0.25); '
            'border-radius: 8px; padding: 14px 16px; margin-top: 8px;">'
            '<p style="color: #06B6D4; margin: 0; font-size: 0.85rem; '
            'font-family: \'Inter\', sans-serif; line-height: 1.5;">'
            '<b>Extracted raw MIME and body-embedded headers</b> — '
            'forensic inspection of embedded headers, authentication '
            'proofs, and threat contribution factors.'
            '</p>'
            '</div>',
            unsafe_allow_html=True,
        )

    st.markdown("---")

    # ============================================
    # ROW 4: MIME Headers table | TEFV Proof
    # ============================================
    row2_left, row2_right = st.columns([1, 1])

    with row2_left:
        st.markdown("#### Extracted MIME Headers")
        mime_df = pd.DataFrame([
            {"Header": k, "Value": (v[:100] + "..." if len(str(v)) > 100 else v)}
            for k, v in headers_dict.items()
        ])
        st.dataframe(mime_df, width='stretch', hide_index=True)

    with row2_right:
        st.markdown("#### Tamper-Evident Forensic Verification (TEFV) Proof")
        st.code(merkle_root, language="text")
        st.button("Copy Merkle Root", key="copy_merkle_t2", on_click=lambda: st.write("Copied!"))

        st.markdown("**Verify a different file against this proof:**")
        st.markdown("<span style='font-size: 0.78rem; color: #94a3b8;'>Upload a file to check for tampering</span>", unsafe_allow_html=True)
        verify_file = st.file_uploader(
            "Upload a file to check for tampering",
            type=["eml", "txt", "pdf", "docx", "json"],
            key="verify_uploader_t2",
            label_visibility="collapsed",
        )

        if verify_file is not None:
            verify_bytes = verify_file.getvalue()
            if st.button("Verify Cryptographic Proof", width='stretch', key="verify_proof_btn"):
                is_valid, curr_root, exp_root = zkfv.verify_evidence_proof(verify_bytes, zkfv_proof)
                if is_valid:
                    st.success("Evidence Integrity Verified: Merkle root matches cryptographic proof!")
                else:
                    st.error("Verification Failed: Proof mismatch!")
                    st.write(f"**Expected root:** `{exp_root}`")
                    st.write(f"**Uploaded file root:** `{curr_root}`")
            with st.expander("View Forensic Audit Ledger", expanded=False):
                audit_logs = zkfv.get_recent_audit_logs(10)
                if audit_logs:
                    st.dataframe(pd.DataFrame(audit_logs), width='stretch', hide_index=True)
                else:
                    st.caption("No audit log entries recorded yet.")

    st.markdown("---")

    # ============================================
    # ROW 5: Extracted URLs (full width)
    # ============================================
    st.markdown("#### Extracted URLs & Defanged Threat Analysis")
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
        st.dataframe(pd.DataFrame(url_rows), width='stretch', hide_index=True)
    else:
        st.info("No URLs extracted from email body.")

    st.markdown("---")

    # ============================================
    # ROW 6: Stacked Factor Chart (full width)
    # ============================================
    st.markdown("#### Stacked Factor Contribution Chart")
    if risk_factors:
        df_factors = pd.DataFrame(risk_factors)
        chart = alt.Chart(df_factors).mark_bar().encode(
            x=alt.X('sum(points):Q', title='Points Contribution',
                    axis=alt.Axis(labelFontSize=10, titleFontSize=11,
                                  titleColor='#94a3b8', labelColor='#94a3b8',
                                  gridColor='rgba(6, 182, 212, 0.20)',
                                  domain=True,
                                  domainColor='rgba(6, 182, 212, 0.30)',
                                  tickColor='rgba(6, 182, 212, 0.30)')),
            y=alt.Y('category:N', title='', sort='-x',
                    axis=alt.Axis(labelFontSize=11, labelColor='#e2e8f0',
                                  domain=True,
                                  domainColor='rgba(6, 182, 212, 0.30)',
                                  tickColor='rgba(6, 182, 212, 0.30)'),),
            color=alt.Color(
                'category:N',
                scale=alt.Scale(
                    domain=['Suspicious Keywords', 'Authentication',
                            'ML Classifier', 'URL Metrics',
                            'Header Mismatch', 'Header Injection'],
                    range=['#06B6D4', '#3B82F6', '#A855F7',
                           '#F59E0B', '#EC4899', '#F43F5E'],
                ),
                legend=alt.Legend(orient='right',
                                  labelFontSize=10, titleFontSize=0,
                                  labelColor='#e2e8f0'),
            ),
            tooltip=['category', 'points', 'description']
        ).properties(height=200)
        st.altair_chart(
            chart.configure_view(
                stroke='rgba(6, 182, 212, 0.30)',
                strokeWidth=1,
            ),
            width='stretch',
        )
    else:
        st.success("Zero threat score penalties detected.")

    st.markdown("---")

    # ============================================
    # ROW 7: Body-Embedded Header Analysis (full width)
    # ============================================
    st.markdown("#### Body-Embedded Header Analysis")
    try:
        _body_hdr = detect_body_header_spoofing(msg)
        if _body_hdr.get("embedded_headers_found", 0) == 0 and not _body_hdr.get("mismatches"):
            st.success("No embedded headers detected in the email body.")
        else:
            _col_a, _col_b = st.columns(2)
            with _col_a:
                st.metric("Embedded header lines", _body_hdr.get("embedded_headers_found", 0))
            with _col_b:
                st.metric(
                    "Risk modifier",
                    f"+{_body_hdr.get('total_risk_modifier', 0)}",
                    delta="Suspicious" if _body_hdr.get("total_risk_modifier", 0) > 0 else None,
                )
            _mismatches = _body_hdr.get("mismatches", [])
            if _mismatches:
                _rows = []
                for _m in _mismatches:
                    _rows.append({
                        "Header": _m.get("header", ""),
                        "Severity": _m.get("severity", ""),
                        "Risk": f"+{_m.get('risk_modifier', 0)}",
                        "MIME value": (_m.get("mime_value", "") or "")[:80],
                        "Body claim": (_m.get("body_claim", "") or "")[:80],
                    })
                st.dataframe(pd.DataFrame(_rows), width='stretch', hide_index=True)
            else:
                st.info("Embedded headers found but no mismatches against MIME.")
    except Exception as _e:
        st.caption(f"Body-header analysis unavailable: {type(_e).__name__}")

    st.markdown("</div>", unsafe_allow_html=True)
elif selected_tab == "Relay & Route":
    st.markdown("<div class='soc-card'>", unsafe_allow_html=True)
    st.markdown("### Received Chain Timeline & Relay Hop Analysis")

    # Received Hops Timeline
    received_headers = msg.get_all("Received", [])
    hop_rows = []
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
        st.dataframe(pd.DataFrame(hop_rows), width='stretch', hide_index=True)
    else:
        st.caption("No 'Received:' headers found in MIME data.")

    st.markdown("---")
    st.markdown("#### Threat Infrastructure Relationship Graph")
    
    graph_data = graph_engine.build_threat_infrastructure_graph(from_addr, ret_addr, urls, geo_results)
    plotly_fig = graph_engine.generate_plotly_threat_graph(graph_data)
    st.markdown("<div class='soc-chart-panel'>", unsafe_allow_html=True)
    st.plotly_chart(plotly_fig, width='stretch')
    st.caption(f"Infrastructure Correlation: {graph_data['num_nodes']} Entities, {graph_data['num_edges']} Threat Relationships")
    st.markdown("""
    <div style="display: flex; gap: 24px; margin-top: 12px; font-size: 0.85rem; color: #94a3b8; flex-wrap: wrap;">
        <div><span style="display: inline-block; width: 12px; height: 12px; background: #06B6D4; border-radius: 50%; margin-right: 6px;"></span> Email</div>
        <div><span style="display: inline-block; width: 12px; height: 12px; background: #F59E0B; border-radius: 50%; margin-right: 6px;"></span> Domain</div>
        <div><span style="display: inline-block; width: 12px; height: 12px; background: #F43F5E; border-radius: 50%; margin-right: 6px;"></span> IP / URL</div>
        <div><span style="display: inline-block; width: 12px; height: 12px; background: #A855F7; border-radius: 50%; margin-right: 6px;"></span> ASN</div>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)


# ==========================================
# TAB 5: IP & DOMAIN INTEL
# ==========================================
elif selected_tab == "IP & Domain Intel":
    st.markdown("<div class='soc-card'>", unsafe_allow_html=True)
    st.markdown("### Dynamic Geolocation Map & Campaign Intelligence")

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

    # --- Relay hop geolocation for ArcLayer ---
    hop_geo = []
    if received_headers:
        _hop_ips = []
        for _rh in reversed(received_headers):
            _m = re.search(r"\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]", str(_rh))
            if _m:
                _hop_ips.append(_m.group(1))
        for _ip in _hop_ips:
            _g = geolocate_ip(_ip)
            if _g.get("status") == "success" and _g.get("lat") and _g.get("lon"):
                hop_geo.append({
                    "ip": _ip,
                    "lat": _g.get("lat"),
                    "lon": _g.get("lon"),
                    "city": _g.get("city", "Unknown"),
                    "country": _g.get("country", "Unknown"),
                })

    if hop_geo and len(hop_geo) >= 2:
        # Draw arcs between consecutive hops
        arcs = []
        for i in range(len(hop_geo) - 1):
            arcs.append({
                "from_lon": hop_geo[i]["lon"],
                "from_lat": hop_geo[i]["lat"],
                "to_lon": hop_geo[i + 1]["lon"],
                "to_lat": hop_geo[i + 1]["lat"],
                "from_ip": hop_geo[i]["ip"],
                "to_ip": hop_geo[i + 1]["ip"],
            })

        arc_layer = pdk.Layer(
            "ArcLayer",
            data=arcs,
            get_source_position="[from_lon, from_lat]",
            get_target_position="[to_lon, to_lat]",
            get_source_color=[6, 182, 212, 220],
            get_target_color=[244, 63, 94, 220],
            get_width=5,
            width_min_pixels=2,
            pickable=True,
            auto_highlight=True,
        )

        node_layer = pdk.Layer(
            "ScatterplotLayer",
            data=hop_geo,
            get_position="[lon, lat]",
            get_color=[6, 182, 212, 230],
            get_radius=35000,
            pickable=True,
            auto_highlight=True,
        )

        _center_lat = sum(h["lat"] for h in hop_geo) / len(hop_geo)
        _center_lon = sum(h["lon"] for h in hop_geo) / len(hop_geo)

        st.markdown(
            '<div style="border: 1px solid rgba(6, 182, 212, 0.30); '
            'border-radius: 10px; padding: 6px; '
            'background: rgba(15, 23, 42, 0.4);">',
            unsafe_allow_html=True,
        )
        st.pydeck_chart(pdk.Deck(
            layers=[arc_layer, node_layer],
            initial_view_state=pdk.ViewState(
                latitude=_center_lat,
                longitude=_center_lon,
                zoom=3.2,
                pitch=30,
            ),
            map_style="https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json",
            tooltip={"text": "{ip}\n{from_ip} -> {to_ip}"},
        ))
        st.markdown('</div>', unsafe_allow_html=True)

        st.caption(
            "Relay hops drawn as arcs (blue source -> red target). "
            "Hops with private / unresolvable IPs are not shown."
        )

    elif map_data:
        df_map = pd.DataFrame(map_data)
        _pts = df_map.to_dict("records")
        _pt_layer = pdk.Layer(
            "ScatterplotLayer",
            data=_pts,
            get_position="[lon, lat]",
            get_color=[6, 182, 212, 200],
            get_radius=40000,
            pickable=True,
            auto_highlight=True,
        )
        st.markdown(
            '<div style="border: 1px solid rgba(6, 182, 212, 0.30); '
            'border-radius: 10px; padding: 6px; '
            'background: rgba(15, 23, 42, 0.4);">',
            unsafe_allow_html=True,
        )
        st.pydeck_chart(pdk.Deck(
            layers=[_pt_layer],
            initial_view_state=pdk.ViewState(
                latitude=float(df_map["lat"].mean()),
                longitude=float(df_map["lon"].mean()),
                zoom=3.0,
                pitch=0,
            ),
            map_style="https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json",
            tooltip={"text": "{ip}\n{city}, {country}"},
        ), use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    else:
        st.info("No public IP coordinates found. Displaying default threat map overview.")
        _fallback_layer = pdk.Layer(
            "ScatterplotLayer",
            data=[{"lat": 37.7749, "lon": -122.4194, "ip": "Fallback", "city": "San Francisco", "country": "USA"}],
            get_position="[lon, lat]",
            get_color=[6, 182, 212, 200],
            get_radius=40000,
        )
        st.markdown(
            '<div style="border: 1px solid rgba(6, 182, 212, 0.30); '
            'border-radius: 10px; padding: 6px; '
            'background: rgba(15, 23, 42, 0.4);">',
            unsafe_allow_html=True,
        )
        st.pydeck_chart(pdk.Deck(
            layers=[_fallback_layer],
            initial_view_state=pdk.ViewState(
                latitude=20.0,
                longitude=0.0,
                zoom=3.0,
                pitch=0,
            ),
            map_style="https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json",
        ), use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)


    st.markdown("---")
    st.markdown("#### Extracted IP & ASN Resolution Table")
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
        st.dataframe(pd.DataFrame(geo_rows), width='stretch', hide_index=True)

        for g in geo_results:
            ip_val = g.get("ip", "")
            st.button(f" Copy IP {ip_val}", key=f"copy_ip_{ip_val}", on_click=lambda: st.write("Copied!"))
    else:
        st.caption("No IP addresses extracted.")

    st.markdown("---")
    st.markdown("#### Neo4j Campaign Correlation Graph")
    
    # --- Campaign Correlation Graph (visual) ---
    try:
        _graph_fig = neo4j_engine.generate_plotly_campaign_graph()
        if _graph_fig is not None:
            st.markdown(
                '<div style="border: 1px solid rgba(6, 182, 212, 0.30); '
                'border-radius: 10px; padding: 6px; '
                'background: rgba(15, 23, 42, 0.4); margin-bottom: 16px;">',
                unsafe_allow_html=True,
            )
            st.plotly_chart(_graph_fig, width='stretch', config={"displayModeBar": False})
            st.markdown('</div>', unsafe_allow_html=True)
            st.caption("Campaign correlation graph — Emails (cyan), Domains (amber), IPs (rose), URLs (purple).")
        else:
            st.info(
                "No campaign graph yet — seed the demo campaign or upload "
                "2+ emails with shared infrastructure to see correlations."
            )
    except Exception as _ge:
        st.caption(f"Campaign graph unavailable: {type(_ge).__name__}")

    neo_status = neo4j_engine.test_connection()
    mode = neo_status.get("mode", "memory")

    # --- Status badge (green = live, amber = in-memory) ---
    badge_color = neo_status.get("status_color", "amber")
    badge_label = neo_status.get("status", "Unknown")
    color_map = {
        "green": "#10B981",
        "amber": "#F59E0B",
        "red":   "#F43F5E",
    }
    hex_color = color_map.get(badge_color, color_map["amber"])

    st.markdown(
        f"**Neo4j Database Status**: "
        f"<span style='background:{hex_color}; color:white; padding:2px 8px; "
        f"border-radius:4px; font-weight:600;'>{badge_label}</span>",
        unsafe_allow_html=True,
    )

    # --- How to enable Neo4j expander (only when offline) ---
    if mode != "neo4j":
        with st.expander("How to enable Neo4j (persistent graph)", expanded=False):
            st.markdown(
                "Neo4j is not running. The app is currently using an "
                "**in-memory NetworkX fallback** - campaign correlations still work, "
                "but they are **not persisted** between restarts."
            )
            st.markdown("**To enable Neo4j, run:**")
            st.code("docker-compose up -d neo4j", language="bash")
            st.markdown(f"**Configured URI:** `{neo_status.get('uri', 'bolt://localhost:7687')}`")
            st.markdown(f"**Configured user:** `{neo_status.get('user', 'neo4j')}`")
            st.caption("After starting Neo4j, refresh this page.")
        st.caption(neo_status.get("message", ""))

    # --- Campaigns ---
    campaigns = neo4j_engine.correlate_campaigns()
    email_count = 0
    try:
        from neo4j_engine import _analyzed_emails  # type: ignore
        email_count = len(_analyzed_emails)
    except Exception:
        email_count = 0

    if campaigns:
        st.markdown(f"Detected **{len(campaigns)}** correlated threat campaign cluster(s):")
        df = pd.DataFrame(campaigns)
        preferred = ["campaign_id", "shared_ioc_type", "shared_ioc", "correlated_emails_count"]
        cols = [c for c in preferred if c in df.columns] + [c for c in df.columns if c not in preferred]
        st.dataframe(df[cols], width='stretch', hide_index=True)
    else:
        st.info(
            f"**No shared infrastructure across {email_count} analyzed email(s).** "
            "Campaign correlation requires 2 or more emails that share a domain, IP, "
            "or URL. Upload more emails, or click below to seed a synthetic campaign."
        )

    # --- Seed demo campaign button (always visible on Tab 5) ---
    if st.button("Seed demo campaign", key="seed_demo_btn", use_container_width=True):
        try:
            from neo4j_engine import seed_demo_data
            _seeded = seed_demo_data()
            if _seeded > 0:
                st.success(f"Seeded {_seeded} demo email(s). Scroll up to see the campaigns table.")
            else:
                st.info("All demo emails already present. Nothing to seed.")
        except Exception as _e:
            st.error(f"Seed failed: {_e}")

    st.markdown("</div>", unsafe_allow_html=True)


# --- GLOBAL LEGAL DISCLAIMER FOOTER ---
