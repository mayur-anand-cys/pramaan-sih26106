"""Streamlit login page for PRAMAAN."""
import streamlit as st
from .authenticator import authenticate, is_authenticated, init_auth

LOGIN_CSS = """
<style>
.login-card {
  max-width: 420px; margin: 80px auto; padding: 32px;
  background: #161b22; border: 1px solid #30363d;
  border-radius: 10px;
}
.login-card h2 { color: #e6edf3; margin-bottom: 4px; }
.login-card p  { color: #7d8590; font-size: 0.9rem; margin-bottom: 24px; }
.login-card label { color: #e6edf3 !important; font-size: 0.85rem !important; }
</style>
"""


def render_login_page() -> bool:
    """Render login form. Returns True if authenticated this run."""
    init_auth()
    if is_authenticated():
        return True

    st.markdown(LOGIN_CSS, unsafe_allow_html=True)

    _, mid, _ = st.columns([1, 1.2, 1])
    with mid:
        st.markdown(
            '<div class="login-card"><h2>PRAMAAN</h2>'
            '<p>Email Threat Intelligence Platform</p></div>',
            unsafe_allow_html=True,
        )
        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("Username", placeholder="pramaan")
            password = st.text_input("Password", type="password", placeholder="••••••••")
            submit = st.form_submit_button("Sign in", use_container_width=True)

        if submit:
            user = authenticate(username.strip(), password)
            if user:
                st.session_state["auth_user"] = user
                st.rerun()
            else:
                st.error("Invalid credentials. Try pramaan / admin123")

        st.caption("Demo — Analyst: pramaan / admin123  ·  Citizen: citizen / citizen123")

    return is_authenticated()
