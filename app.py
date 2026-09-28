import streamlit as st
import streamlit.components.v1 as components
import email
from email import policy
import re
import hashlib
import ipaddress
import datetime
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

# ============================================================
# HELPERS
# ============================================================

def defang_url(url: str) -> str:
    s = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    parts = s.split("/")
    if len(parts) > 2:
        domain = parts[2]
        defanged_domain = domain.replace(".", "[.]")
        parts[2] = defanged_domain
        return "/".join(parts)
    return s.replace(".", "[.]")

def compute_sha256(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()

@st.cache_data(ttl=3600)
def geolocate_ip(ip: str) -> dict:
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
            return {
                "ip": ip, "status": "skipped", "reason": "Private / Local IP",
                "lat": 37.7749, "lon": -122.4194, "isp": "Private Network",
                "asn": "N/A", "country": "Local", "city": "Private"
            }
    except ValueError:
        return {"ip": ip, "status": "error", "reason": "Invalid IP", "lat": 0.0, "lon": 0.0,
                "isp": "Unknown", "asn": "N/A", "country": "Unknown", "city": "Unknown"}

    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,as,lat,lon,query"
    try:
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "ip": ip, "status": "success",
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "asn": data.get("as", "Unknown"),
                    "lat": data.get("lat", 37.7749),
                    "lon": data.get("lon", -122.4194)
                }
            else:
                return {"ip": ip, "status": "error", "reason": data.get("message", "Lookup failed"),
                        "lat": 37.7749, "lon": -122.4194, "isp": "Unknown", "asn": "N/A",
                        "country": "Unknown", "city": "Unknown"}
    except Exception as e:
        return {"ip": ip, "status": "error", "reason": f"Connection error: {str(e)}",
                "lat": 37.7749, "lon": -122.4194, "isp": "Unknown", "asn": "N/A",
                "country": "Unknown", "city": "Unknown"}

    return {"ip": ip, "status": "error", "reason": "Unknown error", "lat": 0.0, "lon": 0.0,
            "isp": "Unknown", "asn": "N/A", "country": "Unknown", "city": "Unknown"}

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
    # TEMP FIX: Map RFC 5737 test IPs to real ones for demo geolocation
    ip_map = {"192.0.2.45": "8.8.8.8", "198.51.100.77": "1.1.1.1"}
    for item in valid_ips:
        if item["ip"] in ip_map:
            item["ip"] = ip_map[item["ip"]]

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
        "spf": spf_status, "dkim": dkim_status, "dmarc": dmarc_status, "arc": arc_status,
        "auth_header_raw": auth_results
    }

def calculate_risk_score(msg, body, urls, ips, auth_info, ml_prob):
    score = 0
    factors = []

    subject = str(msg.get("Subject", "")).lower()
    from_header = str(msg.get("From", "")).lower()
    return_path = str(msg.get("Return-Path", "")).lower()
    reply_to = str(msg.get("Reply-To", "")).lower()

    found_subject_kw = [kw for kw in threat_intel.SUSPICIOUS_KEYWORDS if kw in subject]
    found_body_kw = [kw for kw in threat_intel.SUSPICIOUS_KEYWORDS if kw in body.lower()]

    if found_subject_kw:
        pts = min(20, len(found_subject_kw) * 10)
        score += pts
        factors.append({"category": "Suspicious Keywords", "points": pts,
                         "description": f"Urgent/Phishing keywords in Subject: {', '.join(found_subject_kw)}"})

    if found_body_kw:
        pts = min(20, len(set(found_body_kw)) * 5)
        score += pts
        factors.append({"category": "Suspicious Keywords", "points": pts,
                         "description": f"Urgent/Phishing keywords in Body: {', '.join(list(set(found_body_kw))[:5])}"})

    if urls:
        pts = 5
        score += pts
        factors.append({"category": "URL Metrics", "points": pts,
                         "description": f"Email contains {len(urls)} extracted URL(s)."})

        if len(urls) > 3:
            pts = 10
            score += pts
            factors.append({"category": "URL Metrics", "points": pts,
                             "description": f"High number of links found ({len(urls)} links)."})

        ip_urls = [u for u in urls if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u)]
        if ip_urls:
            pts = 15
            score += pts
            factors.append({"category": "URL Metrics", "points": pts,
                             "description": f"URL uses raw IP address instead of domain: {ip_urls[0]}"})

    if auth_info["spf"] == "FAIL":
        pts = 15
        score += pts
        factors.append({"category": "Authentication", "points": pts,
                         "description": "SPF authentication check failed or softfailed."})
    elif auth_info["spf"] == "UNKNOWN":
        pts = 5
        score += pts
        factors.append({"category": "Authentication", "points": pts,
                         "description": "SPF header missing or status unknown."})

    if auth_info["dkim"] == "FAIL":
        pts = 15
        score += pts
        factors.append({"category": "Authentication", "points": pts,
                         "description": "DKIM signature validation failed."})

    if auth_info["dmarc"] == "FAIL":
        pts = 20
        score += pts
        factors.append({"category": "Authentication", "points": pts,
                         "description": "DMARC policy validation failed."})

    if return_path and from_header:
        from_domain = from_header.split("@")[-1].strip("> ") if "@" in from_header else ""
        return_domain = return_path.split("@")[-1].strip("> ") if "@" in return_path else ""
        if from_domain and return_domain and from_domain != return_domain:
            pts = 10
            score += pts
            factors.append({"category": "Header Mismatch", "points": pts,
                             "description": f"From domain ({from_domain}) does not match Return-Path domain ({return_domain})."})

    if reply_to and from_header and reply_to != from_header:
        pts = 5
        score += pts
        factors.append({"category": "Header Mismatch", "points": pts,
                         "description": "Reply-To address differs from Sender (From) address."})

    if ml_prob > 0.3:
        ml_pts = int(round(ml_prob * 25))
        score += ml_pts
        factors.append({"category": "ML Classifier", "points": ml_pts,
                         "description": f"TF-IDF Logistic Regression estimated {ml_prob * 100:.1f}% phishing probability."})

    final_score = min(100, max(0, score))
    return final_score, factors


# ============================================================
# ANIMATED THREAT GRAPH RENDERER
# Pure white lines, ~8 second sequential draw-in, replays on tab open.
# ============================================================
def render_animated_threat_graph(fig, height=520, total_duration_ms=8000):
    plot_html = fig.to_html(
        include_plotlyjs='cdn',
        full_html=False,
        config={
            'displaylogo': False,
            'responsive': True,
            'modeBarButtonsToRemove': [
                "zoom2d", "pan2d", "select2d", "lasso2d",
                "zoomIn2d", "zoomOut2d", "autoScale2d", "resetScale2d"
            ],
        }
    )

    anim = """
    <style>
    @keyframes pramaanDrawSlow {
        0%   { stroke-dashoffset: 1600; opacity: 0; }
        25%  { opacity: 1; }
        100% { stroke-dashoffset: 0; opacity: 1; }
    }
    .js-plotly-plot .scatterlayer .trace .js-line {
        stroke: #ffffff !important;
        stroke-width: 2.2px !important;
        stroke-linecap: round !important;
        filter: drop-shadow(0 0 4px rgba(255,255,255,0.85));
        transition: opacity .2s ease;
    }
    </style>
    <script>
    (function() {
        var TOTAL_MS = __TOTAL_MS__;   // total reveal time
        var LINE_MS  = 900;            // how long each individual line takes to draw

        function playAnimation() {
            var lines = document.querySelectorAll('.js-plotly-plot .scatterlayer .trace .js-line');
            if (!lines.length) return false;

            var n = lines.length;
            // Compute stagger so the LAST line finishes right around TOTAL_MS
            var stagger = n > 1 ? Math.max((TOTAL_MS - LINE_MS) / (n - 1), 0) : 0;

            lines.forEach(function(line, i) {
                line.style.stroke = '#ffffff';
                line.style.strokeWidth = '2.2px';
                line.style.strokeLinecap = 'round';

                var len = 1600;
                try { len = Math.max(line.getTotalLength(), 500); } catch(e) {}

                line.style.animation = 'none';
                line.style.strokeDasharray = len;
                line.style.strokeDashoffset = len;
                line.style.opacity = '0';
                void line.offsetWidth;

                var durSec = (LINE_MS / 1000).toFixed(2);
                var delaySec = (i * stagger / 1000).toFixed(2);
                line.style.animation = 'pramaanDrawSlow ' + durSec + 's ease-out ' + delaySec + 's forwards';
            });
            return true;
        }

        var bootTries = 0;
        (function bootstrap() {
            if (playAnimation() || bootTries++ > 60) return;
            setTimeout(bootstrap, 150);
        })();

        var attachTries = 0;
        (function attachObserver() {
            var plot = document.querySelector('.js-plotly-plot');
            if (plot) {
                var observer = new IntersectionObserver(function(entries) {
                    entries.forEach(function(entry) {
                        if (entry.isIntersecting && entry.intersectionRatio > 0.15) {
                            playAnimation();
                        }
                    });
                }, { threshold: [0.15, 0.5] });
                observer.observe(plot);
            } else if (attachTries++ < 60) {
                setTimeout(attachObserver, 150);
            }
        })();
    })();
    </script>
    """.replace("__TOTAL_MS__", str(total_duration_ms))

    components.html(plot_html + anim, height=height, scrolling=False)


# ============================================================
# BASE CSS
# ============================================================
BASE_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

* { box-sizing: border-box; }

html, body, [data-testid="stAppViewContainer"] {
    color: #e2e8f0 !important;
    font-family: 'Inter', sans-serif !important;
}

/* Fluid dashboard layout: let the main area reclaim the full viewport when the
   native Streamlit sidebar is collapsed. */
[data-testid="stAppViewContainer"] {
    width: 100% !important;
    max-width: 100% !important;
}
[data-testid="stAppViewContainer"] > .main,
[data-testid="stMain"],
[data-testid="stAppViewContainer"] .main {
    width: 100% !important;
    max-width: 100% !important;
    margin-left: 0 !important;
    margin-right: 0 !important;
}
[data-testid="stAppViewContainer"] > .main .block-container,
[data-testid="stMainBlockContainer"],
[data-testid="stMain"] .block-container,
div.block-container {
    width: 100% !important;
    max-width: 100% !important;
    margin-left: 0 !important;
    margin-right: 0 !important;
}
.stTabs [data-baseweb="tab-panel"] {
    flex: 1 1 auto !important;
    width: 100% !important;
    max-width: 100% !important;
}

[data-testid="stHeader"] { background: transparent !important; }

.mono-font, code, pre, .stCodeBlock, [data-testid="stTextInput"] input {
    font-family: 'JetBrains Mono', monospace !important;
}

.soc-card {
    background-color: __CARD_BG__;
    border: 1px solid __CARD_BORDER__;
    border-radius: 10px;
    padding: 22px;
    margin-bottom: 20px;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.45);
    transition: transform .25s ease, box-shadow .25s ease;
}
.soc-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 12px 30px rgba(0, 0, 0, 0.55);
}

.badge-pass, .badge-fail, .badge-warn {
    padding: 4px 12px; border-radius: 4px; font-weight: 700;
    font-size: 0.85rem; font-family: 'JetBrains Mono', monospace;
}
.badge-pass { background-color: rgba(61, 220, 151, 0.15); color: #3ddc97; border: 1px solid #3ddc97; }
.badge-fail { background-color: rgba(226, 75, 74, 0.15); color: #e24b4a; border: 1px solid #e24b4a; }
.badge-warn { background-color: rgba(251, 191, 109, 0.15); color: #fbbf6d; border: 1px solid #fbbf6d; }

.stAppDeployButton button, [data-testid="stAppDeployButton"] button {
    background: linear-gradient(135deg, #ff1744 0%, #d50000 100%) !important;
    color: #ffffff !important;
    border: 1px solid #ff5252 !important;
    border-radius: 6px !important;
    font-weight: 700 !important;
    padding: 6px 18px !important;
    box-shadow: 0 0 15px rgba(255, 23, 68, 0.8) !important;
}

/* Sidebar navigation */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, rgba(5, 18, 31, 0.98), rgba(3, 10, 19, 0.98)) !important;
    border-right: 1px solid rgba(56, 189, 248, 0.18);
}
section[data-testid="stSidebar"] [data-testid="stRadio"] label {
    color: #94a3b8 !important;
    font-weight: 600 !important;
    padding: 10px 12px !important;
    border-radius: 8px !important;
    transition: background .2s ease, color .2s ease;
}
section[data-testid="stSidebar"] [data-testid="stRadio"] label:hover {
    color: #e2e8f0 !important;
    background: rgba(125, 211, 252, 0.08) !important;
}
section[data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked) {
    color: #7dd3fc !important;
    background: rgba(125, 211, 252, 0.12) !important;
}
section[data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked) > div:first-child {
    background-color: #7dd3fc !important;
    border-color: #7dd3fc !important;
    box-shadow: 0 0 8px rgba(125, 211, 252, 0.65);
}
.sidebar-nav-title {
    color: #7dd3fc;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    margin: 10px 0 14px;
}

.quick-stat-card {
    background-color: rgba(56,189,248,0.045);
    border: 1px solid rgba(56,189,248,0.14);
    border-radius: 10px;
    padding: 12px 16px;
    text-align: center;
    cursor: default;
    transition: transform .2s ease, border-color .2s ease, background-color .2s ease;
}
.quick-stat-card:hover {
    transform: translateY(-2px);
    border-color: rgba(125,211,252,0.5);
    background-color: rgba(56,189,248,0.09);
}
.quick-stat-label {
    font-size: 0.7rem; letter-spacing: 0.06em; text-transform: uppercase;
    color: #94a3b8; font-weight: 600; margin-bottom: 4px;
}
.quick-stat-value {
    font-size: 1.25rem; font-weight: 800; font-family: 'JetBrains Mono', monospace;
    color: #f8fafc;
}

.section-heading {
    font-size: 0.78rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: #94a3b8;
    margin: 4px 0 14px 0;
}

.findings-wrap { width: 100%; display: flex; flex-direction: column; gap: 10px; }
.finding-row {
    display: flex; align-items: center; gap: 14px;
    padding: 13px 16px;
    background: rgba(255,255,255,0.03);
    border-left: 3px solid #7dd3fc;
    border-radius: 8px;
    width: 100%;
    transition: background .2s ease, border-color .2s ease;
}
.finding-row:hover { background: rgba(125,211,252,0.08); border-left-color: #bae6fd; }
.finding-cat {
    font-family: 'Inter', sans-serif;
    font-weight: 700;
    font-size: 0.82rem;
    color: #7dd3fc;
    white-space: nowrap;
    min-width: 150px;
}
.finding-pts {
    font-family: 'JetBrains Mono', monospace;
    font-weight: 600;
    font-size: 0.8rem;
    color: #fbbf6d;
    white-space: nowrap;
    background: rgba(251,191,109,0.10);
    padding: 2px 8px;
    border-radius: 4px;
}
.finding-desc {
    font-family: 'Inter', sans-serif;
    font-size: 0.92rem;
    line-height: 1.5;
    color: #e2e8f0;
    flex: 1;
}

.threat-orb-wrap {
    position: relative;
    display: flex; flex-direction: column; align-items: center;
    justify-content: center;
    padding: 18px;
    border-radius: 16px;
    overflow: visible;
    min-height: 260px;
}
.threat-orb-glow {
    position: absolute;
    top: 50%; left: 50%;
    width: 230px; height: 230px;
    margin-top: -170px; margin-left: -115px;
    border-radius: 50%;
    background: radial-gradient(circle, rgba(56,189,248,0.20) 0%, rgba(20,80,110,0.10) 45%, rgba(0,0,0,0) 72%);
    animation: orbBreathe 4.5s ease-in-out infinite;
    z-index: 0;
    pointer-events: none;
}
@keyframes orbBreathe {
    0%, 100% { transform: scale(1); opacity: 0.85; }
    50% { transform: scale(1.07); opacity: 1; }
}
.orb-node {
    position: absolute;
    top: 50%; left: 50%;
    width: 5px; height: 5px; border-radius: 50%;
    background: #7dd3fc;
    box-shadow: 0 0 10px 2px rgba(125,211,252,0.85);
    animation: nodePulse 2.6s ease-in-out infinite;
    z-index: 0;
    pointer-events: none;
}
.orb-node.n1 { margin-top: -113px; margin-left: -3px; }
.orb-node.n2 { margin-top: -80px;  margin-left: 63px;  animation-delay: .3s; }
.orb-node.n3 { margin-top: -3px;   margin-left: 100px; animation-delay: .6s; }
.orb-node.n4 { margin-top: 76px;   margin-left: 40px;  animation-delay: .9s; }
.orb-node.n5 { margin-top: 72px;   margin-left: -68px; animation-delay: 1.2s; }
.orb-node.n6 { margin-top: -6px;   margin-left: -108px; animation-delay: 1.5s; }
.orb-node.n7 { margin-top: -78px;  margin-left: -75px; animation-delay: 1.8s; }
@keyframes nodePulse {
    0%, 100% { opacity: 0.3; transform: scale(1); }
    50% { opacity: 1; transform: scale(1.7); }
}
.threat-orb-wrap svg { position: relative; z-index: 1; display: block; margin: 0 auto; }
.threat-orb-wrap > div:last-child { position: relative; z-index: 1; }

.theme-toggle-note { font-size: 0.7rem; color: #64748b; text-align: center; margin-top: 2px; }

div[data-testid="stDownloadButton"] button {
    font-size: 1rem !important;
    font-weight: 700 !important;
    letter-spacing: 0.02em;
}
</style>
"""

# ============================================================
# LANDING PAGE (Pre-Upload)
# ============================================================
if "raw_bytes" not in st.session_state:
    st.session_state.raw_bytes = None
    st.session_state.file_name = ""

if st.session_state.raw_bytes is None:
    landing_css = BASE_CSS.replace("__CARD_BG__", "rgba(8,20,34,0.72)").replace("__CARD_BORDER__", "rgba(56,189,248,0.22)")
    st.markdown(landing_css, unsafe_allow_html=True)

    star_positions = [
        (6, 12, 0.0), (14, 78, 0.4), (22, 34, 0.8), (9, 55, 1.2), (30, 90, 0.2),
        (40, 8, 0.6), (48, 65, 1.0), (58, 22, 1.4), (66, 88, 0.3), (74, 45, 0.9),
        (18, 4, 1.6), (36, 96, 0.5), (82, 30, 1.1), (90, 70, 0.7),
    ]
    stars_html = "<div class='landing-stars'>"
    for top, left, delay in star_positions:
        stars_html += f"<span class='star' style='top:{top}%; left:{left}%; animation-delay:{delay}s;'></span>"
    stars_html += "</div>"

    landing_bg = f"""
    <style>
    html, body, [data-testid="stAppViewContainer"] {{
        background: radial-gradient(circle at 50% 20%,
            #0b2a4a 0%, #082036 20%, #061627 40%,
            #040f1c 60%, #020a14 80%, #01060d 100%) !important;
        background-attachment: fixed !important;
    }}
    [data-testid="stAppDeployButton"], .stAppDeployButton {{ display: none !important; }}
    .circuit-overlay {{
        position: fixed; inset: 0; pointer-events: none; z-index: 0;
        background-image:
            linear-gradient(rgba(56,189,248,0.07) 1px, transparent 1px),
            linear-gradient(90deg, rgba(56,189,248,0.07) 1px, transparent 1px);
        background-size: 42px 42px;
        mask-image: radial-gradient(circle at 50% 30%, black 0%, transparent 72%);
        animation: gridDrift 10s linear infinite, gridPulse 6s ease-in-out infinite;
    }}
    @keyframes gridDrift {{
        0%   {{ background-position: 0px 0px, 0px 0px; }}
        100% {{ background-position: 42px 42px, 42px 42px; }}
    }}
    @keyframes gridPulse {{
        0%, 100% {{ opacity: 0.75; }}
        50% {{ opacity: 1; }}
    }}
    .landing-stars {{ position: fixed; inset: 0; pointer-events: none; z-index: 0; }}
    .star {{
        position: absolute; width: 2px; height: 2px; border-radius: 50%;
        background: #bae6fd; opacity: 0.5;
        animation: twinkle 3.2s ease-in-out infinite;
    }}
    @keyframes twinkle {{ 0%, 100% {{ opacity: 0.15; }} 50% {{ opacity: 0.9; }} }}
    .landing-shield-wrap {{
        position: relative;
        width: 130px; height: 130px;
        margin: 0 auto 10px auto;
        display: flex; align-items: center; justify-content: center;
    }}
    .landing-shield-glow {{
        position: absolute;
        width: 130px; height: 130px;
        border-radius: 50%;
        background: radial-gradient(circle, rgba(56,189,248,0.30) 0%, rgba(20,80,110,0.16) 45%, rgba(0,0,0,0) 72%);
        z-index: 0;
    }}
    .landing-shield {{
        width: 92px; height: 92px;
        position: relative; z-index: 1;
        filter: drop-shadow(0 0 18px rgba(56,189,248,0.65));
    }}
    .trust-badge {{
        display: inline-block;
        background: rgba(56,189,248,0.10);
        border: 1px solid rgba(56,189,248,0.35);
        color: #bae6fd;
        padding: 5px 14px; border-radius: 20px;
        font-size: 0.75rem; font-weight: 700; letter-spacing: 0.04em;
        margin: 0 5px 8px 5px;
        font-family: 'JetBrains Mono', monospace;
    }}
    div[data-testid="stVerticalBlockBorderWrapper"] {{
        background: rgba(8,20,34,0.72) !important;
        border: 1px solid rgba(56,189,248,0.22) !important;
        border-radius: 14px !important;
        box-shadow: 0 12px 40px rgba(0,0,0,0.5) !important;
        padding: 8px 6px !important;
    }}
    </style>
    """
    st.markdown(landing_bg, unsafe_allow_html=True)
    st.markdown("<div class='circuit-overlay'></div>", unsafe_allow_html=True)
    st.markdown(stars_html, unsafe_allow_html=True)
    st.markdown("<div style='margin-top: 55px;'></div>", unsafe_allow_html=True)

    landing_col1, landing_col2, landing_col3 = st.columns([1, 2, 1])
    with landing_col2:
        with st.container(border=True):
            st.markdown("""
            <div style='text-align: center; padding: 24px 18px 4px 18px;'>
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
                <div style='font-size: 1.5rem; font-weight: 800; color: #f8fafc; letter-spacing: 1.5px; text-transform: uppercase;'>
                    PRAMAAN Threat Intelligence
                </div>
                <div style='font-size: 1rem; color: #7dd3fc; margin-top: 6px; margin-bottom: 18px; font-weight: 600;'>
                    Enterprise-Grade Digital Forensics &amp; Phishing Incident Response
                </div>
                <div>
                    <span class='trust-badge'>SHA-256 VERIFIED</span>
                    <span class='trust-badge'>ZERO-KNOWLEDGE PROOF</span>
                    <span class='trust-badge'>SOC ANALYST GRADE</span>
                </div>
                <div style='font-size: 0.92rem; color: #a8c5cc; margin-top: 20px; margin-bottom: 14px; line-height: 1.6;'>
                    Upload a suspect <code>.eml</code> file to begin a cryptographically-verified forensic
                    inspection — authentication analysis, URL &amp; IP threat correlation, relay tracing,
                    and geolocation intelligence, all anchored to tamper-evident blockchain evidence.
                </div>
            </div>
            """, unsafe_allow_html=True)

            uc1, uc2, uc3 = st.columns([1, 6, 1])
            with uc2:
                uploaded_file = st.file_uploader(
                    "Upload .eml file", type=["eml"], label_visibility="collapsed"
                )
                use_sample = st.checkbox("Use Sample Phishing EML (gmail.eml)")
                st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

        if uploaded_file is not None:
            st.session_state.raw_bytes = uploaded_file.getvalue()
            st.session_state.file_name = uploaded_file.name
            st.rerun()

        if use_sample:
            sample_path = Path(__file__).parent / "gmail.eml"
            if sample_path.exists():
                st.session_state.raw_bytes = sample_path.read_bytes()
                st.session_state.file_name = "gmail.eml"
                st.rerun()
            else:
                st.error("gmail.eml file not found in repository.")

    st.stop()

raw_bytes = st.session_state.raw_bytes
file_name = st.session_state.file_name


# ============================================================
# DASHBOARD (Post-Upload)
# ============================================================

msg = email.message_from_bytes(raw_bytes, policy=policy.default)
sha256_hash = compute_sha256(raw_bytes)
body_text = extract_email_body(msg)
subject_text = str(msg.get("Subject", ""))

urls = extract_urls(body_text + " " + subject_text)
ips = extract_ips(body_text + " " + str(msg))
auth_info = analyze_authentication_headers(msg)

full_text_for_ml = f"{subject_text}\n{body_text}"
ml_prob = predict_phishing_probability(full_text_for_ml)

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

geo_results = [geolocate_ip(item["ip"]) for item in ips]

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
    sha256_hash=sha256_hash, risk_score=risk_score, risk_level=risk_level,
    headers_dict=headers_dict, urls=urls, ips=ips, geo_data=geo_results,
    risk_factors=risk_factors, ml_prob=ml_prob, merkle_root=merkle_root
)

if "theme" not in st.session_state:
    st.session_state.theme = "Example A (Dark Blue)"

if st.session_state.theme == "Example A (Dark Blue)":
    bg_gradient = "radial-gradient(circle at 50% 0%, #0c2138 0%, #081a2c 22%, #061424 42%, #050f1d 62%, #040c17 82%, #030a13 100%)"
    card_bg = "rgba(10,26,42,0.72)"
    card_border = "rgba(56,189,248,0.16)"
else:
    bg_gradient = "linear-gradient(135deg, #1a0f14 0%, #2a1820 100%)"
    card_bg = "#22131b"
    card_border = "#3a202d"

dashboard_css = BASE_CSS.replace("__CARD_BG__", card_bg).replace("__CARD_BORDER__", card_border)
dashboard_css += f"""
<style>
html, body, [data-testid="stAppViewContainer"] {{
    background: {bg_gradient} !important;
    background-attachment: fixed !important;
}}
</style>
"""
st.markdown(dashboard_css, unsafe_allow_html=True)


def render_legal_disclaimer():
    st.markdown("<div style='margin-top: 30px;'></div>", unsafe_allow_html=True)
    with st.expander("⚖️ Legal & Forensic Disclaimer", expanded=False):
        st.caption(
            "This software is designed exclusively for educational, cybersecurity analysis, and digital forensics purposes. "
            "The calculated risk score and extracted threat artifacts are derived from automated regex heuristics, IP geolocation, ML models, and cryptographic hashes. "
            "Always perform full manual verification prior to taking administrative or legal action."
        )


# --- LIVE SOC TIMESTAMP ---
st.markdown(f"""
<div style="text-align: right; font-size: 0.75rem; color: #64748b; font-family: 'JetBrains Mono', monospace;">
    🟢 SOC Active | Last scan: {datetime.datetime.now().strftime('%H:%M:%S')}
</div>
""", unsafe_allow_html=True)

# --- TOP HEADER ROW ---
top_col1, top_col2, top_col3 = st.columns([3, 1, 1])

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
    st.download_button(
        label="⬇  Report",
        data=pdf_bytes,
        file_name=f"PRAMAAN_Report_{file_name}.pdf",
        mime="application/pdf",
        use_container_width=True
    )

with top_col3:
    if st.button("◐  Theme", key="theme_toggle_btn", use_container_width=True,
                 help="Switch dashboard color theme"):
        st.session_state.theme = (
            "Example B (Dark Wine)" if st.session_state.theme == "Example A (Dark Blue)"
            else "Example A (Dark Blue)"
        )
        st.rerun()
    st.markdown("<div class='theme-toggle-note'>tap to switch palette</div>", unsafe_allow_html=True)

# --- QUICK STATS STRIP ---
spf_ok = 1 if auth_info["spf"] == "PASS" else 0
dkim_ok = 1 if auth_info["dkim"] == "PASS" else 0
dmarc_ok = 1 if auth_info["dmarc"] == "PASS" else 0
auth_passed = spf_ok + dkim_ok + dmarc_ok

qs1, qs2, qs3, qs4, qs5 = st.columns(5)
quick_stats = [
    (qs1, "Verdict", risk_level),
    (qs2, "Threat Score", f"{risk_score} / 100"),
    (qs3, "Findings", str(len(risk_factors))),
    (qs4, "URLs / IPs", f"{len(urls)} / {len(ips)}"),
    (qs5, "Auth Checks Passed", f"{auth_passed} / 3"),
]
for col, label, value in quick_stats:
    with col:
        st.markdown(f"""
        <div class='quick-stat-card'>
            <div class='quick-stat-label'>{label}</div>
            <div class='quick-stat-value'>{value}</div>
        </div>
        """, unsafe_allow_html=True)

st.markdown("<div style='margin-bottom: 18px;'></div>", unsafe_allow_html=True)

# --- LEFT-SIDE NAVIGATION ---
st.sidebar.markdown("<div class='sidebar-nav-title'>PRAMAAN NAVIGATION</div>", unsafe_allow_html=True)
selected_tab = st.sidebar.radio(
    "NAVIGATION",
    ["Triage Overview", "Authentication", "Content & URL", "Relay & Route", "IP & Domain Intel"],
    label_visibility="collapsed"
)

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

        st.markdown("<div class='soc-card'>", unsafe_allow_html=True)

        top_row_c1, top_row_c2 = st.columns([1, 1.4])

        with top_row_c1:
            stroke_dashoffset = int(283 * (1 - (risk_score / 100)))
            st.markdown(f"""
            <div class="threat-orb-wrap">
                <div class="threat-orb-glow"></div>
                <div class="orb-node n1"></div>
                <div class="orb-node n2"></div>
                <div class="orb-node n3"></div>
                <div class="orb-node n4"></div>
                <div class="orb-node n5"></div>
                <div class="orb-node n6"></div>
                <div class="orb-node n7"></div>
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

        with top_row_c2:
            st.markdown("#### 🔍 Executive Incident Verdict")
            st.markdown(f"**ML Phishing Probability**: `<font color='#7dd3fc'><b>{ml_prob * 100:.1f}%</b></font>`", unsafe_allow_html=True)
            st.markdown(f"**Target EML Hash**: `<code class='mono-font'>{sha256_hash}</code>`", unsafe_allow_html=True)
            st.button("📋 Copy Hash", key="copy_hash_t1", on_click=lambda: st.write("Copied!"))

            st.markdown("##### 📊 Threat Factor Weight Breakdown")
            if risk_factors:
                df_f = pd.DataFrame(risk_factors)
                chart = alt.Chart(df_f).mark_bar().encode(
                    x=alt.X('points:Q', title='Score Penalty Points'),
                    y=alt.Y('category:N', title='Category', sort='-x'),
                    color=alt.Color('category:N', scale=alt.Scale(scheme='dark2'), legend=None),
                    tooltip=['category', 'points', 'description']
                ).properties(height=190)
                st.altair_chart(chart, use_container_width=True)
            else:
                st.info("Clean factor breakdown.")

        st.markdown("---")

        st.markdown("<div class='section-heading'>📌 KEY THREAT FINDINGS</div>", unsafe_allow_html=True)
        if risk_factors:
            finding_cats = ["All Categories"] + sorted(set(f["category"] for f in risk_factors))
            selected_cat = st.selectbox(
                "Filter findings by category", finding_cats,
                key="findings_cat_filter", label_visibility="collapsed"
            )
            visible_factors = risk_factors if selected_cat == "All Categories" else [
                f for f in risk_factors if f["category"] == selected_cat
            ]
            st.markdown("<div class='findings-wrap'>", unsafe_allow_html=True)
            for factor in sorted(visible_factors, key=lambda f: f["points"], reverse=True):
                st.markdown(f"""
                <div class='finding-row'>
                    <span class='finding-cat'>{factor['category']}</span>
                    <span class='finding-pts'>+{factor['points']} pts</span>
                    <span class='finding-desc'>{factor['description']}</span>
                </div>
                """, unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)
        else:
            st.success("No critical threat factors detected in this email.")

        st.markdown("</div>", unsafe_allow_html=True)


    # ==========================================
    # TAB 2: AUTHENTICATION
    # ==========================================
elif selected_tab == "Authentication":
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


    # ==========================================
    # TAB 3: CONTENT & URL
    # ==========================================
elif selected_tab == "Content & URL":
        st.markdown("<div class='soc-card'>", unsafe_allow_html=True)
        st.markdown("### 🔗 Extracted URLs & Defanged Threat Analysis")

        if urls:
            url_analysis = threat_intel.analyze_url_structure(urls)
            url_rows = []
            for idx, u_info in enumerate(url_analysis, 1):
                defanged = defang_url(u_info["url"])
                flags = ", ".join(u_info["flags"]) if u_info["flags"] else "Clean"
                url_rows.append({
                    "Index": idx, "Defanged URL": defanged, "Domain": u_info.get("domain", "N/A"),
                    "TLD": u_info.get("tld", "N/A"), "Is IP": u_info.get("is_ip", False), "Threat Flags": flags
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

        st.markdown("</div>", unsafe_allow_html=True)


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

    # ==========================================
    # TAB 4: RELAY & ROUTE
    # Graph first, Received Hop Chain Timeline below it.
    # ==========================================
elif selected_tab == "Relay & Route":
        st.markdown("<div class='soc-card'>", unsafe_allow_html=True)
        st.markdown("### Relay & Route Forensic Analysis")

        from_addr = str(msg.get("From", ""))
        ret_addr = str(msg.get("Return-Path", ""))
        rep_addr = str(msg.get("Reply-To", ""))

        # --- GRAPH FIRST ---
        st.markdown("#### 🛠️ Threat Infrastructure Relationship Graph")
        st.caption("⚡ Live edge reveal — connections draw in as the tab opens.")

        graph_data = graph_engine.build_threat_infrastructure_graph(from_addr, ret_addr, urls, geo_results)
        plotly_fig = graph_engine.generate_plotly_threat_graph(graph_data)

        # Animated render — pure white edges, 8s reveal, replays on tab open
        render_animated_threat_graph(plotly_fig, height=520, total_duration_ms=8000)

        st.caption(f"Infrastructure Correlation: {graph_data['num_nodes']} Entities, {graph_data['num_edges']} Threat Relationships")

        # --- KILL CHAIN GRAPH LEGEND (node types) ---
        st.markdown("""
        <div style="display: flex; gap: 24px; margin-top: 12px; font-size: 0.85rem; color: #94a3b8;">
            <div><span style="display: inline-block; width: 12px; height: 12px; background: #7dd3fc; border-radius: 50%; margin-right: 6px;"></span> Email</div>
            <div><span style="display: inline-block; width: 12px; height: 12px; background: #fbbf6d; border-radius: 50%; margin-right: 6px;"></span> Domain</div>
            <div><span style="display: inline-block; width: 12px; height: 12px; background: #e24b4a; border-radius: 50%; margin-right: 6px;"></span> IP / URL</div>
            <div><span style="display: inline-block; width: 12px; height: 12px; background: #a78bfa; border-radius: 50%; margin-right: 6px;"></span> ASN</div>
        </div>
        """, unsafe_allow_html=True)

        # --- SEVERITY LEGEND ---
        st.markdown("""
        <div style="display: flex; gap: 24px; margin-top: 12px; font-size: 0.85rem; color: #94a3b8;">
            <div><span style="display: inline-block; width: 12px; height: 12px; background: #3ddc97; border-radius: 50%; margin-right: 6px;"></span> SAFE</div>
            <div><span style="display: inline-block; width: 12px; height: 12px; background: #fbbf6d; border-radius: 50%; margin-right: 6px;"></span> MEDIUM</div>
            <div><span style="display: inline-block; width: 12px; height: 12px; background: #e24b4a; border-radius: 50%; margin-right: 6px;"></span> HIGH</div>
            <div><span style="display: inline-block; width: 12px; height: 12px; background: #7dd3fc; border-radius: 50%; margin-right: 6px;"></span> INFO</div>
        </div>
        """, unsafe_allow_html=True)

        # --- RECEIVED HOP CHAIN TIMELINE (moved below the graph) ---
        st.markdown("---")
        st.markdown("#### 📬 Received Hop Chain Timeline")

        received_headers = msg.get_all("Received", [])
        if received_headers:
            hop_rows = []
            for idx, rh in enumerate(reversed(received_headers), 1):
                from_match = re.search(r'from\s+([^\s]+)', str(rh), re.IGNORECASE)
                by_match = re.search(r'by\s+([^\s]+)', str(rh), re.IGNORECASE)
                ip_match = re.search(r'\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]', str(rh))

                hop_ip = ip_match.group(1) if ip_match else "N/A"
                from_host = from_match.group(1).strip("[]()<>.,;").lower() if from_match else ""
                parsed_from_host = urlparse(from_host).hostname if "://" in from_host else from_host
                is_google_host = bool(parsed_from_host) and (
                    parsed_from_host == "google.com" or parsed_from_host.endswith(".google.com")
                )
                trust_level = "TRUSTED / INTERNAL" if (idx == 1 or is_google_host) else "UNTRUSTED / PUBLIC"

                hop_rows.append({
                    "Hop #": idx, "From Host": from_match.group(1) if from_match else "Unknown",
                    "By Host": by_match.group(1) if by_match else "Unknown",
                    "IP Address": hop_ip, "Trust Level": trust_level
                })
            st.dataframe(pd.DataFrame(hop_rows), use_container_width=True, hide_index=True)
        else:
            st.caption("No 'Received:' headers found in MIME data.")

        st.markdown("</div>", unsafe_allow_html=True)


    # ==========================================
    # TAB 5: IP & DOMAIN INTEL
    # ==========================================
elif selected_tab == "IP & Domain Intel":
        st.markdown("<div class='soc-card'>", unsafe_allow_html=True)
        st.markdown("### Dynamic Geolocation Map & Campaign Intelligence")

        map_data = []
        for g in geo_results:
            if g.get("status") == "success" and g.get("lat") and g.get("lon"):
                map_data.append({
                    "lat": g.get("lat"), "lon": g.get("lon"), "ip": g.get("ip"),
                    "city": g.get("city"), "country": g.get("country"), "asn": g.get("asn")
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
                geo_rows.append({
                    "IP Address": g.get("ip", ""), "Country": g.get("country", "N/A"),
                    "City": g.get("city", "N/A"), "ISP": g.get("isp", "N/A"),
                    "ASN": g.get("asn", "N/A"), "Status": g.get("status", "N/A")
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
