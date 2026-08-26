"""
cipher_panel.py — Right panel: AI security assistant chat interface.
"""
import os
import sys

_PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import streamlit as st
from backend.remediation_agent import ask_cipher
from utils.theme import ACCENT, TXT_MUT, TXT_PRI, TXT_SEC


def render():
    st.markdown(
        f"""
    <div style="margin-bottom:4px; display:flex; align-items:center; justify-content:space-between;">
      <div>
        <div style="font-size:1.0rem;font-weight:700;color:{TXT_PRI};">
          🔓 CipHer
        </div>
        <div style="font-size:0.72rem;color:{TXT_SEC};margin-top:1px;">
          <span style="color:#22c55e;">●</span> Online · AI Security Assistant
        </div>
      </div>
    </div>
    <hr style="border-color:#2a2a45;margin:4px 0 8px 0;">
    """,
        unsafe_allow_html=True,
    )

    # Custom CSS to style chat message backgrounds and hide default avatars cleanly
    st.markdown(
        """
        <style>
            /* Hide the default avatar circles */
            [data-testid="stChatMessageAvatar"] {
                display: none !important;
            }
            
            /* User message styling: distinct background & alignment */
            [data-testid="stChatMessage"]:has(div[data-testid="stChatMessageAvatar"] img[alt="user"]) {
                background-color: rgba(99, 102, 241, 0.12) !important;
                border: 1px solid rgba(99, 102, 241, 0.3) !important;
                border-radius: 8px;
                padding: 8px;
                margin-bottom: 6px;
            }

            /* Assistant/Computer message styling: distinct background */
            [data-testid="stChatMessage"]:has(div[data-testid="stChatMessageAvatar"] img[alt="assistant"]) {
                background-color: rgba(30, 41, 59, 0.7) !important;
                border: 1px solid #334155 !important;
                border-radius: 8px;
                padding: 8px;
                margin-bottom: 6px;
            }
        </style>
        """,
        unsafe_allow_html=True,
    )

    # Check if audit has run
    active_report = st.session_state.get("active_report")
    active_code = st.session_state.get("active_code")

    if not active_report:
        st.markdown(
            f"""
        <div style="font-size:0.75rem;color:#38bdf8;background:rgba(56,189,248,0.08);padding:6px 10px;border-radius:6px;border:1px solid rgba(56,189,248,0.2);margin-bottom:8px;">
          ℹ️ Run audit first for code context.
        </div>
        """,
            unsafe_allow_html=True,
        )

    # Fixed height scrollable container for chat messages
    chat_container = st.container(height=390)

    with chat_container:
        messages = st.session_state.get("messages", [])

        if not messages:
            st.markdown(
                f"""
            <div style="background:#1e293b;border:1px solid #334155;padding:12px;border-radius:8px;margin-top:4px;">
              <div style="font-weight:600;color:{TXT_PRI};font-size:0.85rem;margin-bottom:4px;">
                👋 Hi, I'm CipHer
              </div>
              <div style="color:{TXT_SEC};font-size:0.78rem;line-height:1.4;">
                Ask me about your code or security practices.
              </div>
            </div>
            """,
                unsafe_allow_html=True,
            )
        else:
            for message in messages:
                with st.chat_message(message["role"]):
                    st.markdown(message["content"])

    # Chat input scoped right inside the right panel column
    if prompt := st.chat_input("Ask about your code…", key="cipher_chat_input"):
        if not active_report:
            st.warning(
                "Please run a security audit first so CipHer has code context."
            )
        else:
            st.session_state["messages"].append(
                {"role": "user", "content": prompt}
            )

            with chat_container:
                with st.chat_message("user"):
                    st.markdown(prompt)

                with st.chat_message("assistant"):
                    with st.spinner("CipHer is thinking…"):
                        try:
                            history_tuples = [
                                (m["role"], m["content"])
                                for m in st.session_state["messages"][:-1]
                            ]
                            answer = ask_cipher(
                                prompt=prompt,
                                code=active_code,
                                report=active_report,
                                history=history_tuples,
                            )
                            st.markdown(answer)
                            st.session_state["messages"].append(
                                {"role": "assistant", "content": answer}
                            )

                            chat_hist = st.session_state.get(
                                "chat_history", []
                            )
                            if not chat_hist or chat_hist[-1].get(
                                "active_report"
                            ) != hash(active_report):
                                chat_hist.append(
                                    {
                                        "time": "Just now",
                                        "count": len(
                                            st.session_state["messages"]
                                        ),
                                        "active_report": hash(active_report),
                                    }
                                )
                                st.session_state["chat_history"] = chat_hist

                        except Exception as e:
                            err_msg = f"Error generating response: {e}"
                            st.error(err_msg)
                            st.session_state["messages"].append(
                                {"role": "assistant", "content": err_msg}
                            )
            st.rerun()