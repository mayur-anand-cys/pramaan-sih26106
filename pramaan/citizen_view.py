"""Citizen-facing simplified verdict view."""
import streamlit as st
from typing import Dict, List, Any

PLAIN_LANGUAGE = {
    "Authentication": "This email failed security checks that real companies always pass.",
    "Suspicious Keywords": "It uses urgent or threatening language to pressure you.",
    "URL Metrics": "The email contains links that look suspicious.",
    "Header Mismatch": "The sender's address does not match where the email actually came from.",
    "ML Classifier": "Our AI model detected patterns commonly used in phishing.",
}

VERDICT_STYLE = {
    "SAFE":       {"color": "#3fb950", "bg": "#0d2818", "text": "This email looks safe."},
    "SUSPICIOUS": {"color": "#d29922", "bg": "#2a1f08", "text": "Be careful with this email."},
    "DANGEROUS":  {"color": "#f85149", "bg": "#2d0f0f", "text": "Do NOT interact with this email."},
}


def _verdict_from_score(score: int) -> str:
    if score >= 65:
        return "DANGEROUS"
    if score >= 35:
        return "SUSPICIOUS"
    return "SAFE"


def render_citizen_portal(
    risk_score: int,
    risk_level: str,
    risk_factors: List[Dict[str, Any]],
    ml_prob: float,
) -> None:
    verdict = _verdict_from_score(risk_score)
    style = VERDICT_STYLE[verdict]

    st.markdown(
        f"""
        <div style="background:{style['bg']}; border:2px solid {style['color']};
                    border-radius:12px; padding:32px; text-align:center; margin:20px 0;">
            <div style="font-size:0.9rem; color:#7d8590; letter-spacing:0.1em;">VERDICT</div>
            <div style="font-size:3rem; font-weight:800; color:{style['color']}; margin:8px 0;">
                {verdict}
            </div>
            <div style="font-size:1.1rem; color:#e6edf3;">{style['text']}</div>
            <div style="font-size:0.85rem; color:#7d8590; margin-top:12px;">
                Confidence: {ml_prob * 100:.0f}%  ·  Score: {risk_score}/100
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("### Why?")
    if not risk_factors:
        st.success("No suspicious indicators were found.")
    else:
        seen = set()
        for f in risk_factors:
            cat = f.get("category", "")
            if cat in seen:
                continue
            seen.add(cat)
            explanation = PLAIN_LANGUAGE.get(cat, f.get("description", ""))
            st.markdown(f"- **{cat}** — {explanation}")

    st.markdown("### What should you do?")
    if verdict == "DANGEROUS":
        st.error(
            "1. Do **not** click any links or download attachments.\n"
            "2. Do **not** reply or send money.\n"
            "3. Report it to **cybercrime.gov.in** or call **1930**.\n"
            "4. Delete the email."
        )
    elif verdict == "SUSPICIOUS":
        st.warning(
            "1. Verify the sender by contacting the company directly.\n"
            "2. Hover over links to see the real URL before clicking.\n"
            "3. When in doubt, delete it."
        )
    else:
        st.success("Continue as normal, but always stay alert for unexpected requests.")

    with st.expander("Learn more — 5 signs of phishing"):
        st.markdown(
            "1. **Urgency** — 'Act now or your account will be closed.'\n"
            "2. **Unknown sender** — the address doesn't match the claimed company.\n"
            "3. **Suspicious links** — hover to check the real destination.\n"
            "4. **Requests for personal info** — banks never ask for passwords by email.\n"
            "5. **Too-good-to-be-true offers** — prizes, refunds, lottery wins."
        )

    st.caption("Legal: This is an automated assessment. Always verify with the sender directly.")
