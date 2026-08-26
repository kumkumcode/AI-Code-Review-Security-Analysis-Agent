"""
audit_panel.py — Center panel: code input, analysis, report, 3 charts, PDF export.
"""
import os
import re
import sys
import time as _time
from datetime import datetime

import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

_PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.remediation_agent import analyze_and_remediate_stream
from utils.helpers import (
    build_findings,
    field,
    find_table,
    grade,
    grade_color,
    guess_lang,
    risk_score,
    strip_code_fences,
)
from utils.pdf_generator import generate_pdf
from utils.theme import ACCENT, SEV_COLOR, SEV_ICON, TXT_PRI, TXT_SEC


def _metric_card(
    label: str, value: str, sub: str, border_color: str = None
) -> str:
    border = f"border-left:3px solid {border_color};" if border_color else ""
    return f"""
    <div class="mc" style="{border}">
      <div class="mc-label">{label}</div>
      <div class="mc-value">{value}</div>
      <div class="mc-sub">{sub}</div>
    </div>"""


def _section_header(icon: str, title: str) -> str:
    return (
        f'<div class="shdr">{icon} {title}'
        f'<div class="shdr-line"></div></div>'
    )


def _run_analysis(code_input: str):
    progress = st.empty()
    start = _time.time()

    def _update_progress(partial_text: str):
        elapsed = _time.time() - start
        progress.markdown(
            f"🔍 **Cipher is analysing your code…** "
            f"`{elapsed:.1f}s elapsed · {len(partial_text):,} characters generated`"
        )

    try:
        _update_progress("")
        report_text = analyze_and_remediate_stream(
            code_input, on_chunk=_update_progress
        )
        progress.empty()

        st.session_state["active_report"] = report_text
        st.session_state["active_code"] = code_input
        st.session_state["messages"] = []

        lang = field(r"Detected Language.*?[:\-]?\s*([A-Za-z+#]+)", report_text)
        sev = field(
            r"Overall Severity Rating.*?(Critical|High|Medium|Informational|Low)",
            report_text,
        )
        quality = field(
            r"Quality Score.*?(\d{1,2}\s*/\s*10|\d{1,2})", report_text
        )
        dup = field(
            r"Code Duplication Rating.*?(High|Medium|Low|None Detected)",
            report_text,
        )
        flist = build_findings(find_table(report_text))
        score = risk_score(flist)

        st.session_state["audit_history"].append(
            {
                "time": datetime.now().strftime("%H:%M · %d %b"),
                "lang": lang,
                "severity": sev if sev != "N/A" else "Low",
                "quality": quality,
                "duplication": dup,
                "findings_count": len(flist),
                "score": score,
                "report": report_text,
                "code": code_input,  # <--- Stored code properly here
            }
        )

        elapsed_total = _time.time() - start
        st.success(
            f"✅ Audit complete in {elapsed_total:.1f}s — report ready below."
        )
        st.rerun()

    except Exception as exc:
        progress.empty()
        st.error(f"Analysis failed: {exc}")


def _render_metrics(report_text: str, flist: list):
    lang = field(r"Detected Language.*?[:\-]?\s*([A-Za-z+#]+)", report_text)
    sev = field(
        r"Overall Severity Rating.*?(Critical|High|Medium|Informational|Low)",
        report_text,
    )
    quality = field(r"Quality Score.*?(\d{1,2}\s*/\s*10|\d{1,2})", report_text)
    dup = field(
        r"Code Duplication Rating.*?(High|Medium|Low|None Detected)", report_text
    )
    score = risk_score(flist)
    gl, gw = grade(score)
    gc = grade_color(score)
    sc = SEV_COLOR.get(sev, ACCENT)

    cols = st.columns(5)
    cards = [
        (
            cols[0],
            "Health Score",
            f'<span style="color:{gc};">{score}</span>',
            "out of 100",
        ),
        (cols[1], "Grade", f'<span style="color:{gc};">{gl}</span>', gw),
        (cols[2], "Language", lang, "detected"),
        (cols[3], "Quality", quality, "code quality"),
        (
            cols[4],
            "Severity",
            f'<span style="color:{sc};">{SEV_ICON.get(sev,"⚪")} {sev}</span>',
            f"Duplication: {dup}",
        ),
    ]
    for col, label, val, sub in cards:
        with col:
            st.markdown(
                _metric_card(label, val, sub), unsafe_allow_html=True
            )

    return score, gl, gw, gc, lang, quality, dup, sev


def _render_report_summary(flist: list, score: int, gl: str, gw: str, gc: str):
    by_sev = {}
    for f in flist:
        severity = f.get("severity", "Low")
        by_sev[severity] = by_sev.get(severity, 0) + 1

    if not flist:
        txt = "No security vulnerabilities or code quality issues were detected in the submitted code."
    else:
        parts = []
        for label in ("Critical", "High", "Medium", "Low", "Informational"):
            count = by_sev.get(label, 0)
            if count:
                parts.append(f"{count} {label}")
        severity_text = ", ".join(parts)
        txt = (
            f"The audit identified <strong>{len(flist)} issue(s)</strong> "
            f"({severity_text}). The overall health score is "
            f'<strong style="color:{gc};">{score}/100 '
            f"({gl} — {gw})</strong>."
        )

    st.markdown(f'<div class="exec-box">{txt}</div>', unsafe_allow_html=True)


def _render_three_charts(flist: list, score: int):
    import pandas as pd

    col1, col2, col3 = st.columns(3)

    with col1:
        sev_df = (
            pd.DataFrame({"Severity": [f.get("severity", "Low") for f in flist]})
            if flist
            else pd.DataFrame({"Severity": ["None"]})
        )
        sev_cnt = sev_df["Severity"].value_counts().reset_index()
        sev_cnt.columns = ["Severity", "Count"]

        fig1 = px.pie(
            sev_cnt,
            names="Severity",
            values="Count",
            color="Severity",
            color_discrete_map={**SEV_COLOR, "None": "#334155"},
            hole=0.55,
            title="1. Severity Breakdown",
        )
        fig1.update_traces(textinfo="label+value", textfont_size=9)
        fig1.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(t=25, b=5, l=5, r=5),
            height=180,
            font=dict(color="#94a3b8", size=9),
            showlegend=False,
        )
        st.plotly_chart(
            fig1, use_container_width=True, config={"displayModeBar": False}
        )

    with col2:
        cat_df = (
            pd.DataFrame(
                {"Category": [f.get("category", "General") for f in flist]}
            )
            if flist
            else pd.DataFrame({"Category": ["Clean Code"]})
        )
        cat_cnt = cat_df["Category"].value_counts().reset_index()
        cat_cnt.columns = ["Category", "Count"]

        fig2 = px.bar(
            cat_cnt,
            x="Category",
            y="Count",
            title="2. Issues by Category",
            color="Category",
            color_discrete_sequence=["#6366f1", "#a855f7", "#ec4899", "#3b82f6"],
        )
        fig2.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(t=25, b=5, l=5, r=5),
            height=180,
            font=dict(color="#94a3b8", size=9),
            showlegend=False,
            xaxis=dict(showticklabels=True),
        )
        st.plotly_chart(
            fig2, use_container_width=True, config={"displayModeBar": False}
        )

    with col3:
        fig3 = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=score,
                title={
                    "text": "3. Code Health Index",
                    "font": {"size": 11, "color": "#94a3b8"},
                },
                gauge={
                    "axis": {
                        "range": [0, 100],
                        "tickwidth": 1,
                        "tickcolor": "white",
                    },
                    "bar": {"color": "#6366f1"},
                    "bgcolor": "#1e293b",
                    "borderwidth": 2,
                    "bordercolor": "#334155",
                    "steps": [
                        {
                            "range": [0, 50],
                            "color": "rgba(239, 68, 68, 0.3)",
                        },
                        {
                            "range": [50, 80],
                            "color": "rgba(234, 179, 8, 0.3)",
                        },
                        {
                            "range": [80, 100],
                            "color": "rgba(34, 197, 94, 0.3)",
                        },
                    ],
                },
            )
        )
        fig3.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(t=30, b=5, l=15, r=15),
            height=180,
            font=dict(color="white", size=9),
        )
        st.plotly_chart(
            fig3, use_container_width=True, config={"displayModeBar": False}
        )


def _render_full_report(report_text: str):
    parts = re.split(r"\n(?=#{1,3}\s*\d+\.)", report_text)
    shown = False
    for part in parts:
        part = part.strip()
        if not part:
            continue
        hm = re.match(r"#{1,3}\s*(\d+)\.\s*(.+)", part)
        if hm:
            num = hm.group(1)
            title = re.sub(r"\*+", "", hm.group(2).strip())
            body = part[hm.end() :].strip()
            if (
                "refactored" in title.lower()
                or "secure code" in title.lower()
            ):
                continue
            with st.expander(f"{num}. {title}", expanded=(num == "1")):
                st.markdown(strip_code_fences(body))
            shown = True
    if not shown:
        with st.expander("View Full Report", expanded=True):
            st.markdown(strip_code_fences(report_text))


def _render_refactored_code(report_text: str):
    code_blocks = re.findall(r"```(?:\w+)?\n(.*?)```", report_text, re.DOTALL)
    if code_blocks:
        st.code(code_blocks[-1], language=guess_lang(code_blocks[-1]))
    else:
        st.info("No refactored code block was returned for this report.")


def _render_pdf_export(
    report_text: str,
    flist: list,
    lang: str,
    score: int,
    gl: str,
    gw: str,
    quality: str,
    dup: str,
    sev: str,
):
    try:
        pdf_bytes = generate_pdf(
            report_text, flist, lang, score, gl, gw, quality, dup, sev
        )
        st.download_button(
            label="📄  Download PDF Audit Report",
            data=pdf_bytes,
            file_name=f"CodeReviewAI_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
            mime="application/pdf",
            use_container_width=True,
        )
    except Exception as err:
        st.error(f"PDF generation error: {err}")


def render():
    st.markdown(
        f"""
    <div style="margin-bottom:4px;">
      <div style="font-size:1.0rem;font-weight:700;color:{TXT_PRI};">
        🔍 Security Audit
      </div>
      <div style="font-size:0.75rem;color:{TXT_SEC};margin-top:1px;">
        Paste or upload code — Cipher analyses vulnerabilities & quality.
      </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    tab_paste, tab_upload = st.tabs(["📝  Paste", "📁  Upload"])
    code_input = ""

    with tab_paste:
        # Tied to active_code in session state so history restores code properly
        pasted = st.text_area(
            "code_paste",
            value=st.session_state.get("active_code", ""),
            height=110,
            placeholder="# Paste your Python or Java code here…",
            label_visibility="collapsed",
            key="paste_area",
        )
        if pasted.strip():
            code_input = pasted

    with tab_upload:
        upl = st.file_uploader(
            "Upload .py or .java",
            type=["py", "java"],
            label_visibility="collapsed",
        )
        if upl:
            code_input = upl.read().decode("utf-8")

    if st.button(
        "⚡  Run Security Audit", type="primary", use_container_width=True
    ):
        if not code_input.strip():
            st.warning("Please paste or upload some code first.")
        else:
            _run_analysis(code_input)

    # Wrap the entire audit report results inside a fixed-height scrollable container
    with st.container(height=480):
        if st.session_state.get("active_report"):
            report_text = st.session_state["active_report"]
            flist = build_findings(find_table(report_text))

            st.markdown(
                '<hr style="border-color:#2a2a45;margin:6px 0;">',
                unsafe_allow_html=True,
            )

            score, gl, gw, gc, lang, quality, dup, sev = _render_metrics(
                report_text, flist
            )
            st.markdown("<div style='margin:4px 0;'></div>", unsafe_allow_html=True)

            # Report Summary
            st.markdown(
                _section_header("📋", "Report Summary"), unsafe_allow_html=True
            )
            _render_report_summary(flist, score, gl, gw, gc)

            # Full Technical Report
            st.markdown(
                _section_header("📄", "Full Technical Report"),
                unsafe_allow_html=True,
            )
            _render_full_report(report_text)

            # Refactored Secure Code
            st.markdown(
                _section_header("✅", "Refactored Secure Code"),
                unsafe_allow_html=True,
            )
            _render_refactored_code(report_text)

            # Charts
            st.markdown(
                _section_header("📊", "Audit Telemetry & Analytics"),
                unsafe_allow_html=True,
            )
            _render_three_charts(flist, score)

            # PDF Export
            meta = (report_text, flist, lang, score, gl, gw, quality, dup, sev)
            st.markdown(
                _section_header("📥", "Export Report"), unsafe_allow_html=True
            )
            _render_pdf_export(*meta)
        else:
            st.info(
                "💡 No active audit results yet. Paste or upload code above and click **Run Security Audit**."
            )