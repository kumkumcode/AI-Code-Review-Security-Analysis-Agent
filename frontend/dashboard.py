"""
dashboard.py — Main entry point for CodeReview.AI
"""
import os
import sys

_FRONTEND_DIR = os.path.dirname(os.path.abspath(__file__))
if _FRONTEND_DIR not in sys.path:
    sys.path.insert(0, _FRONTEND_DIR)

import streamlit as st
from components.audit_panel import render as render_audit
from components.cipher_panel import render as render_cipher
from components.history_panel import render as render_history
from utils.theme import get_global_css, ACCENT, TXT_PRI, TXT_SEC

st.set_page_config(
    page_title="CodeReview.AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Inject Global CSS safely
st.markdown(f"<style>{get_global_css()}</style>", unsafe_allow_html=True)

# Custom layout adjustments & Professional Button Styling
st.markdown(
    """
    <style>
        .block-container {
            padding-top: 1rem !important;
            padding-bottom: 1rem !important;
            padding-left: 1.5rem !important;
            padding-right: 1.5rem !important;
            max-width: 100% !important;
        }
        div.stButton > button, div.stFormSubmitButton > button {
            background-color: #0f172a !important;
            color: #ffffff !important;
            border: 1px solid #334155 !important;
            border-radius: 6px !important;
            font-weight: 600 !important;
            transition: all 0.2s ease-in-out;
        }
        div.stButton > button:hover, div.stFormSubmitButton > button:hover {
            background-color: #1e293b !important;
            border-color: #38bdf8 !important;
            color: #38bdf8 !important;
        }
    </style>
""",
    unsafe_allow_html=True,
)

# Initialize authentication state
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

# --- SPLIT-SCREEN LOGIN PAGE ---
if not st.session_state["authenticated"]:
    col_left, col_right = st.columns([1.1, 0.9], gap="large")

    with col_left:
        st.markdown(
            """
            <div style="padding: 4rem 2.5rem; background: linear-gradient(135deg, #0b1329 0%, #111827 100%); border-radius: 12px; height: 86vh; display: flex; flex-direction: column; justify-content: space-between; border: 1px solid #1e293b;">
                <div>
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 3rem;">
                        <span style="font-size: 1.4rem; background: rgba(56, 189, 248, 0.1); padding: 8px; border-radius: 8px; border: 1px solid rgba(56, 189, 248, 0.2);">🛡️</span>
                        <span style="font-weight: 600; font-size: 1.0rem; color: #f8fafc; letter-spacing: 0.5px;">CodeReview.AI Security Platform</span>
                    </div>
                    <div style="font-size: 0.72rem; text-transform: uppercase; letter-spacing: 2px; color: #38bdf8; margin-bottom: 1rem; font-weight: 600;">
                        ✦ AI-POWERED RESILIENCE PLATFORM
                    </div>
                    <h1 style="font-size: 2.8rem; font-weight: 800; color: #f8fafc; line-height: 1.15; margin-bottom: 1.5rem;">
                        Turn vulnerability into <span style="color: #38bdf8;">secured code</span>.
                    </h1>
                    <p style="color: #94a3b8; font-size: 0.92rem; line-height: 1.6; max-width: 440px;">
                        One command center for automated static analysis, vulnerability detection, and AI-driven code remediation.
                    </p>
                </div>
                <div style="display: flex; gap: 3rem; border-top: 1px solid #1e293b; padding-top: 1.5rem;">
                    <div>
                        <div style="font-size: 1.1rem; font-weight: 700; color: #f8fafc;">24/7</div>
                        <div style="font-size: 0.72rem; color: #94a3b8;">Security scans</div>
                    </div>
                    <div>
                        <div style="font-size: 1.1rem; font-weight: 700; color: #f8fafc;">AST & LLM</div>
                        <div style="font-size: 0.72rem; color: #94a3b8;">Analysis engine</div>
                    </div>
                    <div>
                        <div style="font-size: 1.1rem; font-weight: 700; color: #22c55e;">Live</div>
                        <div style="font-size: 0.72rem; color: #94a3b8;">Operations signal</div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_right:
        st.markdown(
            """
            <div style="padding: 4rem 1.5rem 1rem 1.5rem; max-width: 420px; margin: 0 auto;">
                <div style="font-size: 0.7rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 0.5rem; font-weight: 600;">
                    🔒 SECURE OPERATIONS ACCESS
                </div>
                <h2 style="font-size: 1.7rem; font-weight: 700; color: #f8fafc; margin-bottom: 0.3rem;">
                    Welcome Back
                </h2>
                <p style="color: #94a3b8; font-size: 0.85rem; margin-bottom: 2rem;">
                    Sign in to your account to continue
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        with st.form("login_form"):
            email = st.text_input("Email Address", placeholder="you@example.com")
            password = st.text_input("Password", type="password", placeholder="••••••••")
            st.markdown("<div style='height: 5px;'></div>", unsafe_allow_html=True)
            submit = st.form_submit_button("Sign In ›", use_container_width=True)

            if submit:
                if email and password:
                    st.session_state["authenticated"] = True
                    st.session_state["email"] = email
                    st.session_state["name"] = email.split("@")[0].replace(".", " ").title()
                    st.rerun()
                else:
                    st.error("Please enter both email and password.")
    st.stop()


# --- DEFAULT SESSION STATES ---
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


# --- TOP BAR HEADER (Cleaned up, removed top-right text) ---
st.markdown(
    f"""
    <div>
        <h3 style='margin:0; font-size:1.1rem; color:{TXT_PRI};'>CodeReview.AI Command Center</h3>
        <p style='margin:0; font-size:0.75rem; color:{TXT_SEC};'>Infosys Springboard — Security Operations</p>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    '<hr style="border-color:#1e293b;margin:10px 0 15px 0;">',
    unsafe_allow_html=True,
)


# --- ROUTING (Dashboard vs Profile) ---
if st.session_state["nav_selection"] == "Profile":
    user_name = st.session_state.get("name", "User")
    initials = "".join([n[0] for n in user_name.split()[:2]]).upper()

    # Back to Dashboard button
    if st.button("← Back to Dashboard"):
        st.session_state["nav_selection"] = "Dashboard"
        st.rerun()

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    st.markdown(
        f"""
        <div style="margin-bottom: 1.5rem;">
            <h2 style="font-size: 1.6rem; font-weight: 700; color: {TXT_PRI}; margin-bottom: 0.2rem;">My Profile</h2>
            <p style="color: {TXT_SEC}; font-size: 0.85rem;">Manage your personal information and account settings.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    prof_col1, prof_col2 = st.columns([1, 1.5], gap="medium")
    
    with prof_col1:
        st.markdown(
            f"""
            <div style="background: #0b1329; border: 1px solid #1e293b; border-radius: 12px; padding: 2rem; text-align: center;">
                <div style="background: #38bdf8; color: #0f172a; width: 64px; height: 64px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 1.5rem; margin: 0 auto 1rem auto;">
                    {initials}
                </div>
                <div style="font-weight: 700; font-size: 1.1rem; color: {TXT_PRI};">{user_name}</div>
                <div style="font-size: 0.8rem; color: {TXT_SEC}; margin-bottom: 1rem;">{st.session_state.get("email")}</div>
                <span style="background: rgba(34, 197, 94, 0.15); color: #22c55e; padding: 4px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 600;">Active Account</span>
                <div style="font-size: 0.7rem; color: {TXT_SEC}; margin-top: 1.5rem;">Member since August 2026</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with prof_col2:
        with st.form("profile_form"):
            st.markdown(
                f"""
                <div style="font-weight: 700; font-size: 1rem; color: {TXT_PRI}; margin-bottom: 0.2rem;">Personal Information</div>
                <div style="font-size: 0.75rem; color: {TXT_SEC}; margin-bottom: 1rem;">Email address cannot be changed.</div>
                """,
                unsafe_allow_html=True,
            )
            
            email_val = st.text_input("Email Address", value=st.session_state.get("email"), disabled=True)
            name_val = st.text_input("Full Name", value=user_name)
            
            save_btn = st.form_submit_button("Save changes")
            if save_btn:
                st.session_state["name"] = name_val
                st.success("Profile updated successfully!")
                st.rerun()

else:
    # Main Three-Column Dashboard View
    col_history, col_main, col_chat = st.columns([2.2, 5.2, 3.1], gap="medium")

    with col_history:
        render_history()

    with col_main:
        render_audit()

    with col_chat:
        render_cipher()