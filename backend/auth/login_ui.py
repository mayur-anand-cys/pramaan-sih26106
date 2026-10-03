"""Streamlit login page for PRAMAAN — enterprise split-screen layout."""
import streamlit as st
from .authenticator import authenticate, is_authenticated, init_auth


LOGIN_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

/* ============================================================
   GLOBAL SHELL — no visible split
   ============================================================ */
.auth-shell-wrap {
    position: fixed; inset: 0; z-index: 1;
    display: grid;
    grid-template-columns: 1.1fr 1fr;
    font-family: 'Inter', sans-serif;
    color: #e6edf3;
    overflow: hidden;
    background: #0a0e14;
}

/* ============================================================
   ANIMATED BACKGROUND — moving grid + aurora + particles
   ============================================================ */
.auth-bg {
    position: absolute; inset: 0; z-index: 0;
    overflow: hidden; pointer-events: none;
    background:
        radial-gradient(ellipse at 15% 20%, rgba(88,166,255,0.18), transparent 55%),
        radial-gradient(ellipse at 85% 80%, rgba(163,113,247,0.18), transparent 55%),
        radial-gradient(ellipse at 50% 50%, rgba(63,185,80,0.08), transparent 60%),
        #0a0e14;
}

/* Moving grid */
.auth-bg::before {
    content: '';
    position: absolute; inset: -50%;
    background-image:
        linear-gradient(rgba(88,166,255,0.05) 1px, transparent 1px),
        linear-gradient(90deg, rgba(88,166,255,0.05) 1px, transparent 1px);
    background-size: 44px 44px;
    animation: grid-move 40s linear infinite;
    mask-image: radial-gradient(ellipse at center, black 30%, transparent 80%);
    -webkit-mask-image: radial-gradient(ellipse at center, black 30%, transparent 80%);
}
@keyframes grid-move {
    0%   { transform: translate(0, 0); }
    100% { transform: translate(44px, 44px); }
}

/* Drifting aurora orbs */
.orb {
    position: absolute; border-radius: 50%;
    filter: blur(80px); opacity: 0.5;
    animation: drift 22s ease-in-out infinite;
}
.orb.o1 { width: 500px; height: 500px; background: #58a6ff; top: -15%; left: -10%; }
.orb.o2 { width: 420px; height: 420px; background: #a371f7; bottom: -18%; left: 40%; animation-duration: 28s; animation-delay: -4s; }
.orb.o3 { width: 380px; height: 380px; background: #3fb950; top: 45%; right: -12%; animation-duration: 34s; animation-delay: -10s; opacity: 0.3; }

@keyframes drift {
    0%, 100% { transform: translate(0, 0) scale(1); }
    33%      { transform: translate(60px, -40px) scale(1.1); }
    66%      { transform: translate(-50px, 50px) scale(0.92); }
}

/* Floating particles */
.particle {
    position: absolute;
    width: 3px; height: 3px;
    background: #58a6ff;
    border-radius: 50%;
    box-shadow: 0 0 10px 2px rgba(88,166,255,0.7);
    animation: float-up 18s linear infinite;
    opacity: 0;
}
.particle.p1 { left: 12%; animation-delay: 0s; }
.particle.p2 { left: 28%; animation-delay: 4s; background: #a371f7; box-shadow: 0 0 10px 2px rgba(163,113,247,0.7); }
.particle.p3 { left: 46%; animation-delay: 8s; }
.particle.p4 { left: 64%; animation-delay: 2s; background: #3fb950; box-shadow: 0 0 10px 2px rgba(63,185,80,0.7); }
.particle.p5 { left: 78%; animation-delay: 6s; }
.particle.p6 { left: 90%; animation-delay: 10s; background: #a371f7; box-shadow: 0 0 10px 2px rgba(163,113,247,0.7); }

@keyframes float-up {
    0%   { top: 100%; opacity: 0; }
    10%  { opacity: 0.9; }
    90%  { opacity: 0.9; }
    100% { top: -5%; opacity: 0; }
}

/* ============================================================
   LEFT PANEL — no visible border, blends into bg
   ============================================================ */
.auth-brand {
    position: relative; z-index: 2;
    overflow: hidden;
    padding: 64px 56px;
    display: flex; flex-direction: column; justify-content: space-between;
    background: transparent;   /* <-- no separate background anymore */
}

.auth-logo { display: flex; align-items: center; gap: 14px; margin-bottom: 8px; }
.auth-logo-mark {
    width: 44px; height: 44px; border-radius: 10px;
    background: linear-gradient(135deg, #58a6ff 0%, #a371f7 100%);
    display: flex; align-items: center; justify-content: center;
    font-weight: 800; font-size: 1.25rem; color: #0a0e14;
    box-shadow: 0 0 24px rgba(88,166,255,0.4);
    animation: logo-pulse 3s ease-in-out infinite;
}
@keyframes logo-pulse {
    0%, 100% { box-shadow: 0 0 24px rgba(88,166,255,0.4); }
    50%      { box-shadow: 0 0 40px rgba(163,113,247,0.6); }
}
.auth-logo-text { font-size: 1.5rem; font-weight: 800; letter-spacing: 1.5px; }
.auth-logo-text span { color: #58a6ff; }

.auth-tagline {
    font-size: 2.1rem; font-weight: 700; line-height: 1.2;
    margin-top: 40px; max-width: 520px; letter-spacing: -0.5px;
}
.auth-tagline span {
    background: linear-gradient(90deg, #58a6ff, #a371f7, #58a6ff);
    background-size: 200% auto;
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    animation: shine 4s linear infinite;
}
@keyframes shine {
    0%   { background-position: 0% center; }
    100% { background-position: 200% center; }
}

.auth-sub {
    font-size: 1rem; color: #8b949e; max-width: 480px;
    margin-top: 16px; line-height: 1.6;
}

/* ============================================================
   ANIMATED VISUAL — rings + orbiting nodes + pulsing core
   ============================================================ */
.auth-visual { position: relative; width: 100%; height: 280px; margin: 40px 0; }
.auth-visual .ring {
    position: absolute; top: 50%; left: 50%;
    border: 1px solid rgba(88,166,255,0.25);
    border-radius: 50%;
    transform: translate(-50%, -50%);
    animation: spin 20s linear infinite;
}
.auth-visual .ring.r1 { width: 120px; height: 120px; border-top-color: #58a6ff; }
.auth-visual .ring.r2 { width: 180px; height: 180px; border-right-color: #a371f7; animation-duration: 30s; animation-direction: reverse; }
.auth-visual .ring.r3 { width: 240px; height: 240px; border-bottom-color: #3fb950; animation-duration: 40s; }

.auth-visual .orbit {
    position: absolute; top: 50%; left: 50%;
    width: 180px; height: 180px;
    margin: -90px 0 0 -90px;
    border-radius: 50%;
    animation: spin 8s linear infinite;
}
.auth-visual .orbit.rev { animation-direction: reverse; animation-duration: 12s; width: 240px; height: 240px; margin: -120px 0 0 -120px; }
.auth-visual .orbit .node {
    position: absolute; top: -4px; left: 50%;
    width: 8px; height: 8px; margin-left: -4px;
    border-radius: 50%;
    background: #58a6ff;
    box-shadow: 0 0 14px 3px rgba(88,166,255,0.85);
}
.auth-visual .orbit.rev .node {
    background: #a371f7;
    box-shadow: 0 0 14px 3px rgba(163,113,247,0.85);
}
.auth-visual .dot {
    position: absolute; top: 50%; left: 50%;
    transform: translate(-50%, -50%);
    width: 14px; height: 14px;
    background: #58a6ff; border-radius: 50%;
    box-shadow: 0 0 24px 6px rgba(88,166,255,0.55);
    animation: pulse 2.5s ease-in-out infinite;
}
@keyframes spin { to { transform: translate(-50%, -50%) rotate(360deg); } }
@keyframes pulse {
    0%, 100% { box-shadow: 0 0 24px 6px rgba(88,166,255,0.55); transform: translate(-50%, -50%) scale(1); }
    50%      { box-shadow: 0 0 40px 14px rgba(88,166,255,0.9); transform: translate(-50%, -50%) scale(1.15); }
}

/* ============================================================
   TRUST BADGES
   ============================================================ */
.auth-badges { display: flex; flex-wrap: wrap; gap: 10px; }
.auth-badge {
    display: inline-flex; align-items: center; gap: 8px;
    padding: 6px 12px;
    border: 1px solid #30363d; border-radius: 6px;
    font-size: 0.72rem; font-weight: 600; letter-spacing: 0.4px;
    color: #8b949e;
    background: rgba(22, 27, 34, 0.6);
    backdrop-filter: blur(8px);
    text-transform: uppercase;
    transition: all 0.2s ease;
}
.auth-badge:hover {
    color: #e6edf3;
    border-color: #58a6ff;
    box-shadow: 0 0 12px rgba(88,166,255,0.25);
}
.auth-badge::before {
    content: ''; width: 6px; height: 6px; border-radius: 50%;
    background: #3fb950;
    animation: badge-blink 2s ease-in-out infinite;
}
@keyframes badge-blink {
    0%, 100% { opacity: 1; }
    50%      { opacity: 0.35; }
}

/* ============================================================
   RIGHT PANEL — no visible divider either
   ============================================================ */
.auth-form-wrap {
    position: relative; z-index: 2;
    display: flex; align-items: center; justify-content: center;
    padding: 64px 56px;
    background: transparent;   /* <-- same bg shows through */
}

.auth-card {
    width: 100%; max-width: 400px;
    padding: 40px 36px;
    background: rgba(22, 27, 34, 0.55);
    backdrop-filter: blur(18px);
    -webkit-backdrop-filter: blur(18px);
    border: 1px solid rgba(48, 54, 61, 0.9);
    border-radius: 12px;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5), 0 0 40px rgba(88,166,255,0.06);
}
.auth-card h2 { font-size: 1.5rem; font-weight: 700; margin: 0 0 4px 0; letter-spacing: -0.3px; }
.auth-card p.auth-hint { font-size: 0.85rem; color: #8b949e; margin: 0 0 28px 0; }
.auth-card label {
    color: #e6edf3 !important;
    font-size: 0.78rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.4px !important;
    text-transform: uppercase !important;
}
.auth-card .stTextInput input {
    background: #0a0e14 !important;
    border: 1px solid #30363d !important;
    color: #e6edf3 !important;
    border-radius: 6px !important;
    font-family: 'Inter', sans-serif !important;
    transition: all 0.2s ease !important;
}
.auth-card .stTextInput input:focus {
    border-color: #58a6ff !important;
    box-shadow: 0 0 0 3px rgba(88,166,255,0.15) !important;
}
.auth-card .stButton button,
.auth-card .stFormSubmitButton button {
    width: 100% !important;
    background: linear-gradient(90deg, #58a6ff, #a371f7) !important;
    color: #0a0e14 !important;
    font-weight: 700 !important;
    letter-spacing: 0.5px !important;
    border: none !important;
    border-radius: 6px !important;
    padding: 10px 16px !important;
    margin-top: 8px !important;
    transition: filter 0.15s ease !important;
    box-shadow: 0 4px 20px rgba(88,166,255,0.25) !important;
}
.auth-card .stButton button:hover,
.auth-card .stFormSubmitButton button:hover {
    filter: brightness(1.1);
    box-shadow: 0 6px 28px rgba(163,113,247,0.5) !important;
}
.auth-credentials {
    margin-top: 24px; padding-top: 20px;
    border-top: 1px solid #21262d;
    font-size: 0.75rem; color: #6e7681; line-height: 1.6;
}
.auth-credentials code {
    background: #161b22; padding: 2px 6px; border-radius: 4px;
    color: #58a6ff; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;
}

@media (max-width: 900px) {
    .auth-shell-wrap { grid-template-columns: 1fr; }
    .auth-brand { display: none; }
}
</style>
"""

def render_login_page() -> bool:
    """Render enterprise split-screen login. Returns True if authenticated."""
    init_auth()
    if is_authenticated():
        return True

    st.markdown(LOGIN_CSS, unsafe_allow_html=True)

    left, right = st.columns([1.1, 1])

    with left:
        st.markdown(
            """
            <div class="auth-bg">
                <div class="orb o1"></div>
                <div class="orb o2"></div>
                <div class="orb o3"></div>
                <div class="particle p1"></div>
                <div class="particle p2"></div>
                <div class="particle p3"></div>
                <div class="particle p4"></div>
                <div class="particle p5"></div>
                <div class="particle p6"></div>
            </div>
            <div class="auth-brand">
                <div>
                    <div class="auth-logo">
                        <div class="auth-logo-mark">P</div>
                        <div class="auth-logo-text">PRAMAAN<span>.</span></div>
                    </div>
                    <div class="auth-tagline">
                        Detect the Threat.<br>
                        Trace the Infrastructure.<br>
                        <span>Preserve the Evidence.</span>
                    </div>
                    <div class="auth-sub">
                        AI-powered email threat detection, geolocation, and
                        forensic intelligence platform for sovereign cyber defence.
                    </div>
                    <div class="auth-visual">
                        <div class="ring r1"></div>
                        <div class="ring r2"></div>
                        <div class="ring r3"></div>
                        <div class="dot"></div>
                    </div>
                </div>
                <div class="auth-badges">
                    <div class="auth-badge">SOC-Grade</div>
                    <div class="auth-badge">Blockchain Anchored</div>
                    <div class="auth-badge">DPDP Compliant</div>
                    <div class="auth-badge">SIH 2026</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with right:
        st.markdown(
            """
            <div class="auth-card">
                <h2>Secure Access</h2>
                <p class="auth-hint">Sign in to the analyst command center</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("Username", placeholder="pramaan")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            submit = st.form_submit_button("Sign In", use_container_width=True)

        if submit:
            user = authenticate(username.strip(), password)
            if user:
                st.session_state["auth_user"] = user
                st.rerun()
            else:
                st.error("Invalid credentials.")

        st.markdown(
            """
            <div class="auth-credentials">
                <b>DEMO CREDENTIALS</b><br>
                Analyst: <code>pramaan</code> / <code>admin123</code><br>
                Citizen: <code>citizen</code> / <code>citizen123</code>
            </div>
            """,
            unsafe_allow_html=True,
        )

    return is_authenticated()
