"""
history_panel.py — Left panel: Analysis history, chat sessions, and user profile/logout footer.
"""
import os
import sys

_PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import streamlit as st
from utils.theme import ACCENT, TXT_MUT, TXT_PRI, TXT_SEC


def render():
    st.markdown(
        f"""
    <div style="font-size:1.0rem;font-weight:700;color:{TXT_PRI};margin-bottom:8px;">
      History
    </div>
    <hr style="border-color:#2a2a45;margin:4px 0 12px 0;">
    <div style="font-size:0.75rem;font-weight:700;letter-spacing:0.8px;color:{TXT_SEC};margin-bottom:8px;text-transform:uppercase;">
      📁 Analysis History
    </div>
    """,
        unsafe_allow_html=True,
    )

    audit_history = st.session_state.get("audit_history", [])

    if not audit_history:
        st.markdown(
            f"""
        <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px;margin-bottom:12px;">
            <div style="font-size:0.8rem;color:{TXT_SEC};">No scans yet.</div>
            <div style="font-size:0.75rem;color:#64748b;margin-top:2px;">Run your first audit to see history here.</div>
        </div>
        """,
            unsafe_allow_html=True,
        )
    else:
        for idx, item in enumerate(audit_history):
            score = item.get("score", 0)
            score_color = (
                "#22c55e"
                if score >= 80
                else "#f59e0b"
                if score >= 50
                else "#ef4444"
            )
            
            btn_label = f"Scan #{idx+1} — Score: {score}/100"
            if st.button(btn_label, key=f"hist_scan_{idx}", use_container_width=True):
                st.session_state["active_report"] = item.get("report")
                st.session_state["active_code"] = item.get("code", "")
                st.rerun()

    st.markdown(
        f"""
    <div style="font-size:0.75rem;font-weight:700;letter-spacing:0.8px;color:{TXT_SEC};margin-top:16px;margin-bottom:8px;text-transform:uppercase;">
      💬 Chat History
    </div>
    """,
        unsafe_allow_html=True,
    )

    chat_history = st.session_state.get("chat_history", [])
    if not chat_history:
        st.markdown(
            f"""
        <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px;margin-bottom:12px;">
            <div style="font-size:0.8rem;color:{TXT_SEC};">No saved sessions yet.</div>
        </div>
        """,
            unsafe_allow_html=True,
        )
    else:
        for idx, chat in enumerate(chat_history):
            chat_label = f"Session #{idx+1} ({chat.get('count', 0)} msgs)"
            if st.button(chat_label, key=f"hist_chat_{idx}", use_container_width=True):
                st.session_state["messages"] = chat.get("messages", [])
                st.rerun()

    # Security Tip box
    st.markdown(
        f"""
    <div style="background:rgba(99,102,241,0.08);border:1px solid rgba(99,102,241,0.2);border-radius:8px;padding:10px;margin-top:16px;">
        <div style="font-size:0.75rem;font-weight:700;color:#818cf8;margin-bottom:4px;">
            💡 SECURITY TIP
        </div>
        <div style="font-size:0.75rem;color:{TXT_SEC};line-height:1.4;">
            Never build SQL queries with string concatenation — always use parameterised queries.
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    # --- PROFILE & LOGOUT FOOTER ---
    st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)
    st.markdown(
        '<hr style="border-color:#2a2a45;margin:8px 0;">',
        unsafe_allow_html=True,
    )

    user_name = st.session_state.get("name", "User")
    initials = "".join([n[0] for n in user_name.split()[:2]]).upper()

    st.markdown(
        f"""
        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
            <div style="background: #38bdf8; color: #0f172a; width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 0.75rem;">
                {initials}
            </div>
            <div style="font-size: 0.8rem; font-weight: 600; color: {TXT_PRI};">
                {user_name}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_prof, col_logout = st.columns(2)
    with col_prof:
        if st.button(
            "👤 Profile",
            use_container_width=True,
            key="hist_profile_btn",
        ):
            st.session_state["nav_selection"] = "Profile"
            st.rerun()
    with col_logout:
        if st.button(
            "Logout",
            use_container_width=True,
            key="hist_logout_btn",
        ):
            st.session_state["authenticated"] = False
            st.session_state.clear()
            st.rerun()