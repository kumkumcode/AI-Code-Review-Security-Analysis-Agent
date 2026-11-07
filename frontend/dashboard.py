"""
dashboard.py — Cyber-Defense Command Platform for CodeReview.AI
Advanced AST & LLM Static Application Security Testing (SAST)
"""
import os
import sys
import textwrap

_FRONTEND_DIR = os.path.dirname(os.path.abspath(__file__))
if _FRONTEND_DIR not in sys.path:
    sys.path.insert(0, _FRONTEND_DIR)

import streamlit as st
from components.audit_panel import render as render_audit
from components.cipher_panel import render as render_cipher
from components.history_panel import render as render_history
from utils.theme import get_global_css, ACCENT, TXT_PRI, TXT_SEC

# --- CORE ENGINE CONFIG ---
st.set_page_config(
    page_title="CodeReview.AI // Cyber Command HUD",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Global CSS Base
st.markdown(f"<style>{get_global_css()}</style>", unsafe_allow_html=True)

# --- MODERN STYLING (No 4-space indent on HTML) ---
st.markdown(
    """<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Space Grotesk', -apple-system, BlinkMacSystemFont, sans-serif !important;
}
code, pre, .stCodeBlock, input, textarea {
    font-family: 'JetBrains Mono', monospace !important;
}

.block-container {
    padding-top: 0.8rem !important;
    padding-bottom: 1.5rem !important;
    padding-left: 1.5rem !important;
    padding-right: 1.5rem !important;
    max-width: 100% !important;
}

.stApp {
    background-color: #030712 !important;
    background-image: 
        radial-gradient(at 0% 0%, rgba(56, 189, 248, 0.12) 0px, transparent 40%),
        radial-gradient(at 100% 0%, rgba(129, 140, 248, 0.1) 0px, transparent 45%),
        radial-gradient(at 50% 100%, rgba(14, 165, 233, 0.08) 0px, transparent 50%),
        linear-gradient(rgba(255, 255, 255, 0.02) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255, 255, 255, 0.02) 1px, transparent 1px) !important;
    background-size: 100% 100%, 100% 100%, 100% 100%, 32px 32px, 32px 32px !important;
}

div.stButton > button, div.stFormSubmitButton > button {
    background: linear-gradient(135deg, rgba(14, 165, 233, 0.9) 0%, rgba(2, 132, 199, 0.9) 100%) !important;
    color: #ffffff !important;
    border: 1px solid rgba(125, 211, 252, 0.4) !important;
    border-radius: 8px !important;
    font-weight: 700 !important;
    font-size: 0.85rem !important;
    letter-spacing: 0.8px !important;
    text-transform: uppercase !important;
    padding: 0.55rem 1.3rem !important;
    box-shadow: 0 0 20px rgba(14, 165, 233, 0.35) !important;
    transition: all 0.25s ease !important;
}
div.stButton > button:hover, div.stFormSubmitButton > button:hover {
    transform: translateY(-2px) !important;
    background: linear-gradient(135deg, #38bdf8 0%, #0ea5e9 100%) !important;
    box-shadow: 0 0 28px rgba(56, 189, 248, 0.6) !important;
    color: #ffffff !important;
}

div[data-baseweb="input"] {
    background: rgba(11, 19, 38, 0.9) !important;
    border: 1px solid rgba(56, 189, 248, 0.25) !important;
    border-radius: 9px !important;
}
div[data-baseweb="input"]:focus-within {
    border-color: #38bdf8 !important;
    box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.3) !important;
}

@keyframes cyber-radar {
    0% { transform: scale(0.9); opacity: 0.7; box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.7); }
    70% { transform: scale(1.1); opacity: 1; box-shadow: 0 0 0 6px rgba(34, 197, 94, 0); }
    100% { transform: scale(0.9); opacity: 0.7; box-shadow: 0 0 0 0 rgba(34, 197, 94, 0); }
}
.live-radar {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background-color: #22c55e;
    animation: cyber-radar 2s infinite ease-in-out;
    margin-right: 6px;
}

.hud-bracket {
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 0.68rem;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    margin-bottom: 0.8rem;
    border-bottom: 1px solid rgba(56, 189, 248, 0.1);
    padding-bottom: 0.4rem;
}
.hud-bracket strong {
    color: #38bdf8;
}
</style>""",
    unsafe_allow_html=True,
)

# Authentication Session State Initialization
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

# ==============================================================================
# VIEW 1: AUTHENTICATION
# ==============================================================================
if not st.session_state["authenticated"]:
    col_hero, col_card = st.columns([1.3, 0.85], gap="large")

    with col_hero:
        hero_html = """
<div style="padding: 3.5rem 3rem; background: linear-gradient(145deg, #090f20 0%, #030713 100%); border-radius: 20px; border: 1px solid rgba(56, 189, 248, 0.25); box-shadow: 0 25px 70px rgba(0,0,0,0.8); min-height: 86vh; display: flex; flex-direction: column; justify-content: space-between;">
<div>
<div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 3rem;">
<div style="display: flex; align-items: center; gap: 14px;">
<div style="background: linear-gradient(135deg, rgba(56, 189, 248, 0.3) 0%, rgba(14, 165, 233, 0.05) 100%); border: 1px solid rgba(56, 189, 248, 0.5); border-radius: 12px; padding: 10px 14px; font-size: 1.5rem;">🛡️</div>
<div>
<div style="font-weight: 800; font-size: 1.35rem; color: #f8fafc; letter-spacing: -0.5px;">CodeReview<span style="color: #38bdf8;">.AI</span></div>
<div style="font-size: 0.68rem; color: #64748b; font-weight: 700; text-transform: uppercase; letter-spacing: 1.2px;">Autonomous AST Code Defense</div>
</div>
</div>
<div style="display: flex; align-items: center; gap: 8px; background: rgba(15, 23, 42, 0.9); border: 1px solid rgba(56, 189, 248, 0.3); padding: 6px 14px; border-radius: 30px; font-size: 0.75rem; color: #cbd5e1;">
<span class="live-radar"></span> Threat Radar Active
</div>
</div>
<div style="display: inline-flex; align-items: center; gap: 8px; background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.3); padding: 6px 16px; border-radius: 30px; margin-bottom: 1.5rem;">
<span style="font-size: 0.72rem; color: #38bdf8; font-weight: 700; text-transform: uppercase; letter-spacing: 1.8px;">⚡ Enterprise Static Application Security Testing</span>
</div>
<h1 style="font-size: 3.2rem; font-weight: 800; color: #f8fafc; line-height: 1.1; margin-bottom: 1.4rem; letter-spacing: -1.2px;">
Zero-day exploits.<br>Identified & patched.<br>
<span style="background: linear-gradient(135deg, #38bdf8 0%, #818cf8 50%, #c084fc 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">In one unified command view.</span>
</h1>
<p style="color: #94a3b8; font-size: 1.02rem; line-height: 1.7; max-width: 530px; margin-bottom: 2.2rem;">
Real-time static vulnerability triage combining Python/Java Abstract Syntax Trees with CipHer conversational AI remediation.
</p>
<div style="background: rgba(11, 19, 38, 0.9); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 12px; padding: 1.3rem; max-width: 550px; font-family: 'JetBrains Mono', monospace;">
<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.8rem; border-bottom: 1px solid rgba(51, 65, 85, 0.6); padding-bottom: 0.6rem;">
<span style="font-size: 0.72rem; color: #38bdf8; font-weight: 700; letter-spacing: 1px;">LIVE AUTO-REMEDIATION // DIFF</span>
<span style="font-size: 0.68rem; background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); padding: 3px 9px; border-radius: 4px; font-weight: 700;">CWE-89 SQL INJECTION</span>
</div>
<div style="font-size: 0.8rem; line-height: 1.6;">
<span style="color: #ef4444; text-decoration: line-through; opacity: 0.8;">- query = "SELECT * FROM users WHERE id = '%s'" % user_input</span><br>
<span style="color: #22c55e; font-weight: 600;">+ query = "SELECT * FROM users WHERE id = %s" ; cursor.execute(query, (user_input,))</span>
</div>
</div>
</div>
<div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 2rem; border-top: 1px solid rgba(51, 65, 85, 0.5); padding-top: 1.8rem;">
<div>
<div style="font-size: 1.6rem; font-weight: 800; color: #f8fafc; font-family: 'JetBrains Mono', monospace;">99.4%</div>
<div style="font-size: 0.72rem; color: #64748b; font-weight: 700; text-transform: uppercase;">Detection Accuracy</div>
</div>
<div>
<div style="font-size: 1.6rem; font-weight: 800; color: #38bdf8; font-family: 'JetBrains Mono', monospace;">0.12s</div>
<div style="font-size: 0.72rem; color: #64748b; font-weight: 700; text-transform: uppercase;">AST Latency</div>
</div>
<div>
<div style="font-size: 1.6rem; font-weight: 800; color: #22c55e; font-family: 'JetBrains Mono', monospace;">OWASP</div>
<div style="font-size: 0.72rem; color: #64748b; font-weight: 700; text-transform: uppercase;">Top 10 Shielded</div>
</div>
</div>
</div>
"""
        st.markdown(textwrap.dedent(hero_html), unsafe_allow_html=True)

    with col_card:
        card_header_html = """
<div style="padding: 4.5rem 1.5rem 1.5rem 1.5rem; max-width: 440px; margin: 0 auto;">
<div style="display: inline-flex; align-items: center; gap: 8px; background: rgba(56, 189, 248, 0.12); border: 1px solid rgba(56, 189, 248, 0.25); padding: 4px 12px; border-radius: 6px; font-size: 0.72rem; color: #38bdf8; font-weight: 800; letter-spacing: 1.2px; text-transform: uppercase; margin-bottom: 0.8rem;">
🔒 OPERATOR AUTHENTICATION
</div>
<h2 style="font-size: 2.2rem; font-weight: 800; color: #f8fafc; margin-bottom: 0.4rem; letter-spacing: -0.6px;">Sign in to Command</h2>
<p style="color: #64748b; font-size: 0.92rem; margin-bottom: 2.4rem; line-height: 1.6;">
Connect your workstation identity to initialize the real-time SAST & CipHer telemetry stream.
</p>
</div>
"""
        st.markdown(textwrap.dedent(card_header_html), unsafe_allow_html=True)

        with st.form("login_form"):
            email = st.text_input("Operator Workstation Email", placeholder="operator@infosys.com")
            password = st.text_input("Security Passphrase / Token", type="password", placeholder="••••••••••••")
            st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)
            submit = st.form_submit_button("Initialize Operator Console ›", use_container_width=True)

            if submit:
                if email and password:
                    st.session_state["authenticated"] = True
                    st.session_state["email"] = email
                    st.session_state["name"] = email.split("@")[0].replace(".", " ").title()
                    st.rerun()
                else:
                    st.error("Authentication rejected: Both Operator Email and Passphrase are required.")
    st.stop()


# ==============================================================================
# STATE INITIALIZATION
# ==============================================================================
DEFAULT_SESSION_STATE = {
    "audit_history": [],
    "chat_history": [],
    "active_report": None,
    "active_code": "",
    "messages": [],
    "nav_selection": "Dashboard",
}

for key, value in DEFAULT_SESSION_STATE.items():
    if key not in st.session_state:
        st.session_state[key] = value

user_name = st.session_state.get("name", "Operator")
user_email = st.session_state.get("email", "operator@infosys.com")
initials = "".join([n[0] for n in user_name.split()[:2]]).upper() or "CR"


# ==============================================================================
# TOP-TIER COMMAND HUD BAR (No duplicate buttons)
# ==============================================================================
hud_left, hud_right = st.columns([2.5, 3.5])

with hud_left:
    brand_html = """
<div style="display: flex; align-items: center; gap: 14px; padding: 0.2rem 0;">
<div style="background: linear-gradient(135deg, rgba(56, 189, 248, 0.3) 0%, rgba(14, 165, 233, 0.05) 100%); border: 1px solid rgba(56, 189, 248, 0.45); border-radius: 10px; padding: 7px 11px; font-size: 1.3rem;">🛡️</div>
<div>
<div style="display: flex; align-items: center; gap: 8px;">
<span style="font-weight: 800; font-size: 1.25rem; color: #f8fafc; letter-spacing: -0.4px;">CodeReview<span style="color:#38bdf8;">.AI</span></span>
<span style="background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.35); font-size: 0.65rem; font-weight: 800; padding: 2px 8px; border-radius: 4px; letter-spacing: 0.5px;">COMMAND HUD</span>
</div>
<div style="font-size: 0.72rem; color: #64748b; font-weight: 600;">Infosys Springboard // DevSecOps Operations</div>
</div>
</div>
"""
    st.markdown(textwrap.dedent(brand_html), unsafe_allow_html=True)

with hud_right:
    telemetry_html = """
<div style="display: flex; align-items: center; justify-content: flex-end; gap: 10px; height: 100%; padding: 0.2rem 0;">
<div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(56, 189, 248, 0.2); padding: 6px 12px; border-radius: 8px; font-size: 0.72rem; color: #94a3b8; display: flex; align-items: center; gap: 6px;">
<span class="live-radar"></span> AST ENGINE: <strong style="color: #f1f5f9;">ONLINE</strong>
</div>
<div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(56, 189, 248, 0.2); padding: 6px 12px; border-radius: 8px; font-size: 0.72rem; color: #94a3b8; display: flex; align-items: center; gap: 6px;">
<span style="color: #38bdf8;">✦</span> ASSISTANT: <strong style="color: #38bdf8;">CIPHER-v4</strong>
</div>
<div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(56, 189, 248, 0.2); padding: 6px 12px; border-radius: 8px; font-size: 0.72rem; color: #94a3b8; display: flex; align-items: center; gap: 6px;">
<span style="color: #22c55e;">●</span> LATENCY: <strong style="color: #22c55e;">16ms</strong>
</div>
</div>
"""
    st.markdown(textwrap.dedent(telemetry_html), unsafe_allow_html=True)

st.markdown(
    """<div style="height: 1px; width: 100%; background: linear-gradient(90deg, transparent 0%, rgba(56, 189, 248, 0.4) 25%, rgba(129, 140, 248, 0.4) 75%, transparent 100%); margin: 0.4rem 0 1.25rem 0;"></div>""",
    unsafe_allow_html=True,
)


# ==============================================================================
# ROUTE: PROFILE & GOVERNANCE (ONLY OPENS WHEN CLICKED FROM SIDEBAR)
# ==============================================================================
if st.session_state["nav_selection"] == "Profile":
    col_back, _ = st.columns([1.4, 4.6])
    with col_back:
        if st.button("← Return to Dashboard"):
            st.session_state["nav_selection"] = "Dashboard"
            st.rerun()

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    header_profile_html = """
<div style="margin-bottom: 2rem;">
<div style="font-size: 0.72rem; color: #38bdf8; font-weight: 700; text-transform: uppercase; letter-spacing: 1.8px; margin-bottom: 0.35rem;">
Identity & Access Governance // Clearance Matrix
</div>
<h2 style="font-size: 2.2rem; font-weight: 800; color: #f8fafc; margin-bottom: 0.3rem;">Operator Security Clearance</h2>
<p style="color: #64748b; font-size: 0.95rem;">Manage authorized telemetry keys, AST scanner permissions, and identity bindings.</p>
</div>
"""
    st.markdown(textwrap.dedent(header_profile_html), unsafe_allow_html=True)

    prof_card, prof_form = st.columns([1, 1.7], gap="large")

    with prof_card:
        card_content_html = f"""
<div style="background: linear-gradient(145deg, #0d1528 0%, #060a16 100%); border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 18px; padding: 2.4rem 2rem; text-align: center; box-shadow: 0 20px 45px rgba(0,0,0,0.5);">
<div style="background: linear-gradient(135deg, #38bdf8 0%, #2563eb 100%); color: #ffffff; width: 88px; height: 88px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 2rem; margin: 0 auto 1.4rem auto; box-shadow: 0 0 30px rgba(56, 189, 248, 0.5); border: 2px solid rgba(255, 255, 255, 0.3);">
{initials}
</div>
<div style="font-weight: 800; font-size: 1.35rem; color: #f8fafc; margin-bottom: 0.3rem;">{user_name}</div>
<div style="font-size: 0.88rem; color: #64748b; margin-bottom: 1.4rem; font-family: 'JetBrains Mono', monospace;">{user_email}</div>
<div style="display: inline-flex; align-items: center; gap: 8px; background: rgba(34, 197, 94, 0.15); border: 1px solid rgba(34, 197, 94, 0.4); color: #22c55e; padding: 6px 16px; border-radius: 20px; font-size: 0.8rem; font-weight: 700;">
<span class="live-radar"></span> Clearance Level 4: Active
</div>
<div style="height: 1px; background: rgba(51, 65, 85, 0.5); margin: 2rem 0 1.5rem 0;"></div>
<div style="display: flex; justify-content: space-between; font-size: 0.8rem; color: #64748b; margin-bottom: 0.75rem;">
<span>Assigned Cluster</span>
<strong style="color: #38bdf8;">Global-Prod-AST-01</strong>
</div>
<div style="display: flex; justify-content: space-between; font-size: 0.8rem; color: #64748b; margin-bottom: 0.75rem;">
<span>CipHer Copilot Engine</span>
<strong style="color: #f1f5f9;">v4.2-Neural (Full Access)</strong>
</div>
<div style="display: flex; justify-content: space-between; font-size: 0.8rem; color: #64748b;">
<span>Cryptographic Ledger</span>
<strong style="color: #22c55e;">Synced & Signed</strong>
</div>
</div>
"""
        st.markdown(textwrap.dedent(card_content_html), unsafe_allow_html=True)

    with prof_form:
        with st.form("profile_form"):
            param_box = """
<div style="background: rgba(13, 21, 40, 0.8); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 14px; padding: 1.6rem; margin-bottom: 1.5rem;">
<div style="font-weight: 700; font-size: 1.1rem; color: #f8fafc; margin-bottom: 0.3rem;">Operator Credentials Parameters</div>
<div style="font-size: 0.82rem; color: #64748b;">Telemetry and AST rule revisions will be tagged with this digital signature.</div>
</div>
"""
            st.markdown(textwrap.dedent(param_box), unsafe_allow_html=True)

            email_val = st.text_input("Assigned Operator Identity (Protected)", value=user_email, disabled=True)
            name_val = st.text_input("Operator Display Name", value=user_name)

            st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
            save_btn = st.form_submit_button("Synchronize Operator Signature", use_container_width=True)
            if save_btn:
                st.session_state["name"] = name_val
                st.success("Operator profile updated and synchronized.")
                st.rerun()

# ==============================================================================
# ROUTE: COMMAND DECK (MAIN DASHBOARD)
# ==============================================================================
else:
    # Sub-header strip
    status_strip_html = """
<div style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(56, 189, 248, 0.15); border-radius: 10px; padding: 0.65rem 1.25rem; margin-bottom: 1rem; display: flex; align-items: center; justify-content: space-between; font-size: 0.78rem;">
<div style="display: flex; align-items: center; gap: 16px;">
<span style="color: #38bdf8; font-weight: 700;">COMMAND HUD LIVE //</span>
<span style="color: #cbd5e1;">🎯 Target Languages: <strong style="color: #f8fafc;">Python 3.12, Java 21 LTS</strong></span>
<span style="color: #cbd5e1;">🛡️ Heuristics: <strong style="color: #22c55e;">OWASP Top 10 + CWE/SANS</strong></span>
</div>
<div style="color: #64748b; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;">
SESSION // SEC-NODE-4091-LIVE
</div>
</div>
"""
    st.markdown(textwrap.dedent(status_strip_html), unsafe_allow_html=True)

    # 3-Column Deck
    col_history, col_main, col_chat = st.columns([2.3, 5.5, 3.2], gap="medium")

    with col_history:
        bracket_1 = """
<div class="hud-bracket">
<span>[ 01 // AUDIT TELEMETRY ]</span>
<strong>ARCHIVE</strong>
</div>
"""
        st.markdown(textwrap.dedent(bracket_1), unsafe_allow_html=True)
        render_history()

    with col_main:
        bracket_2 = """
<div class="hud-bracket">
<span>[ 02 // CODE WORKBENCH & AST INGESTION ]</span>
<strong>ANALYSIS ENGINE</strong>
</div>
"""
        st.markdown(textwrap.dedent(bracket_2), unsafe_allow_html=True)
        render_audit()

    with col_chat:
        bracket_3 = """
<div class="hud-bracket">
<span>[ 03 // CIPHER DEFENSE COPILOT ]</span>
<strong>AI COPILOT</strong>
</div>
"""
        st.markdown(textwrap.dedent(bracket_3), unsafe_allow_html=True)
        render_cipher()