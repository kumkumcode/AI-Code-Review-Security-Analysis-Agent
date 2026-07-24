import streamlit as st
import sys
import os
import io
import re
from datetime import datetime

# Add root directory to sys.path so backend modules can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.remediation_agent import analyze_and_remediate

# ReportLab imports for PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# ============================================================
# BRANDING
# ============================================================
APP_NAME = "AI Code Review & Security Analysis"
APP_TAGLINE = "Multi-agent code quality and vulnerability analysis"

# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(
    page_title=APP_NAME,
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# STYLING — High contrast for visibility on dark/light modes
# ============================================================
st.markdown("""
<style>
.badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 10px;
    font-weight: 600;
    font-size: 0.8rem;
}
.badge-critical { background-color: #fee2e2; color: #991b1b; }
.badge-high     { background-color: #ffedd5; color: #9a3412; }
.badge-medium   { background-color: #fef9c3; color: #854d0e; }
.badge-informational { background-color: #e0f2fe; color: #0369a1; }
.badge-low      { background-color: #dcfce7; color: #166534; }

.finding-card {
    padding: 12px 14px;
    margin-bottom: 8px;
    border-left: 4px solid #d1d5db;
    background-color: rgba(255, 255, 255, 0.03);
    border-radius: 0 6px 6px 0;
}
.finding-card.critical { border-left-color: #dc2626; }
.finding-card.high     { border-left-color: #ea580c; }
.finding-card.medium   { border-left-color: #ca8a04; }
.finding-card.informational { border-left-color: #0284c7; }
.finding-card.low      { border-left-color: #16a34a; }

.finding-title { 
    font-size: 1rem; 
    font-weight: 700; 
    color: #ffffff !important; 
}
.finding-meta { 
    font-size: 0.82rem; 
    color: #cbd5e1 !important; 
    margin: 4px 0 6px 0; 
}
.finding-explain { 
    font-size: 0.9rem; 
    color: #e2e8f0 !important; 
}

.tip-text {
    font-size: 0.82rem;
    color: #94a3b8;
    font-style: italic;
}

.history-line {
    font-size: 0.82rem;
    color: #cbd5e1;
    padding: 3px 0;
}
</style>
""", unsafe_allow_html=True)

# ============================================================
# SESSION STATE INIT
# ============================================================
if "history" not in st.session_state:
    st.session_state["history"] = []
if "last_report" not in st.session_state:
    st.session_state["last_report"] = None

# ============================================================
# HELPERS
# ============================================================
def extract_field(pattern, text, default="N/A"):
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1).strip() if match else default


def find_first_markdown_table(text):
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        if lines[i].strip().startswith("|"):
            table_lines = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                table_lines.append(lines[i])
                i += 1
            rows = []
            for line in table_lines:
                line = line.strip()
                if re.match(r"^\|[\s\-:|]+\|$", line):
                    continue
                cells = [c.strip() for c in line.strip("|").split("|")]
                rows.append(cells)
            if rows:
                return rows
        i += 1
    return []


def build_findings(table_rows):
    if not table_rows or len(table_rows) < 2:
        return []

    header = [h.strip().lower() for h in table_rows[0]]

    def col(*keywords):
        for idx, h in enumerate(header):
            if any(k in h for k in keywords):
                return idx
        return None

    idx_problem = col("problem")
    idx_line = col("line")
    idx_severity = col("severity")
    idx_category = col("category")

    findings = []
    for row in table_rows[1:]:
        def get(idx, default="-"):
            return row[idx] if idx is not None and idx < len(row) else default

        raw_problem = get(idx_problem, "Issue")
        cwe_match = re.search(r"\(CWE-\d+\)", raw_problem)
        cwe_tag = cwe_match.group(0) if cwe_match else ""
        clean_problem = re.sub(r"\s*\(CWE-\d+\)", "", raw_problem).strip()

        findings.append({
            "problem": clean_problem,
            "cwe": cwe_tag,
            "line": get(idx_line),
            "severity": get(idx_severity, "Medium"),
            "category": get(idx_category, ""),
        })
    return findings


FRIENDLY_EXPLANATIONS = [
    (["sql injection", "sql"], "Attackers could manipulate database queries to steal, change, or delete data."),
    (["xss", "cross-site scripting"], "Attackers could inject scripts that run in other users' browsers."),
    (["hardcoded secret", "hardcoded password", "hardcoded key", "cryptographic"],
     "A password or key is stored directly in the code, where anyone with code access can read it."),
    (["csrf"], "Attackers could trick a logged-in user into taking an action without their consent."),
    (["deserialization"], "Loading untrusted data this way could let attackers run their own code on your server."),
    (["input validation"], "The code doesn't check that incoming data is safe before using it."),
    (["access control", "authorization"], "Users might be able to reach data or actions they shouldn't have access to."),
    (["duplication"], "This logic is repeated elsewhere — a bug fixed in one copy may be missed in the others."),
    (["type", "runtime"], "The code doesn't guard against unexpected input types, which can crash it at runtime."),
    (["font glyph", "unicode"], "A character used in the text might not render correctly across all system default fonts."),
]


def get_friendly_explanation(problem_text, category_text):
    combined = (problem_text + " " + category_text).lower()
    for keywords, explanation in FRIENDLY_EXPLANATIONS:
        if any(k in combined for k in keywords):
            return explanation
    return "Flagged as a potential risk or quality issue — see the full report for technical detail."


SEVERITY_ICON = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Informational": "🔵", "Low": "🟢"}


def render_finding_card(finding):
    sev = finding["severity"].capitalize() if finding["severity"] else "Medium"
    sev_class = sev.lower() if sev.lower() in ("critical", "high", "medium", "informational", "low") else "medium"
    icon = SEVERITY_ICON.get(sev, "⚪")
    explanation = get_friendly_explanation(finding["problem"], finding["category"])
    meta_parts = [f"Line {finding['line']}", finding["category"], sev]
    if finding["cwe"]:
        meta_parts.append(finding["cwe"])
    meta_line = "  ·  ".join(p for p in meta_parts if p)

    st.markdown(f"""
    <div class="finding-card {sev_class}">
        <div class="finding-title">{icon} {finding['problem']}</div>
        <div class="finding-meta">{meta_line}</div>
        <div class="finding-explain">{explanation}</div>
    </div>
    """, unsafe_allow_html=True)


def guess_syntax_language(text):
    lower = text.lower()
    if "public class" in lower or "system.out.println" in lower or "import java" in lower:
        return "java"
    return "python"


SECURITY_TIPS = [
    "Never build SQL queries with string concatenation — always use parameterized queries.",
    "Store secrets and API keys in environment variables, never directly in source code.",
    "Validate and sanitize all user input before using it in a database or system command.",
    "Use bcrypt, scrypt, or Argon2 for password hashing — never MD5 or SHA1.",
    "Keep dependencies updated — outdated libraries are a leading source of vulnerabilities.",
    "Always enforce access control checks server-side, never by hiding a button or URL.",
    "Avoid deserializing untrusted data — prefer JSON over pickle or native serialization.",
    "Log authentication failures, but never log passwords or tokens.",
    "Disable debug mode and verbose error messages before going to production.",
    "Rate-limit login endpoints to blunt brute-force and credential-stuffing attacks.",
]

# ============================================================
# SIDEBAR
# ============================================================
with st.sidebar:
    st.markdown(
        """
        <div style="margin-bottom: 5px;">
            <img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRCE-RNyVt2O8xIo_lrS4qURTJz4FSnFH7xVNkb4YUIotu9DtbnWkKk7tEQ&s=10" 
                 style="width: 100%; max-width: 160px; height: auto; display: block;">
        </div>
        """, 
        unsafe_allow_html=True
    )
    # Added a graduation cap / briefcase emoji for a professional touch
    st.caption("🎓 Virtual Internship Project")
    st.divider()

    st.markdown(f"**🛡️ {APP_NAME}**")
    st.caption(APP_TAGLINE)
    st.divider()

    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Informational": 0, "Low": 0}
    for entry in st.session_state["history"]:
        if entry["severity"] in sev_counts:
            sev_counts[entry["severity"]] += 1
    total_scans = len(st.session_state["history"])

    st.caption("SESSION")
    st.markdown(
        f"{total_scans} scans &nbsp;·&nbsp; "
        f"🔴{sev_counts['Critical']} 🟠{sev_counts['High']} 🟡{sev_counts['Medium']} 🔵{sev_counts['Informational']} 🟢{sev_counts['Low']}"
    )

    st.caption("HISTORY")
    if not st.session_state["history"]:
        st.markdown("<span class='history-line'>No scans yet.</span>", unsafe_allow_html=True)
    else:
        for i, entry in enumerate(reversed(st.session_state["history"])):
            real_idx = len(st.session_state["history"]) - 1 - i
            label = f"{entry['time']} · {entry['lang']} · {entry['severity']}"
            if st.button(label, key=f"hist_{real_idx}", use_container_width=True):
                st.session_state["last_report"] = entry["report"]
                st.rerun()

    st.divider()
    st.caption("TIP")
    tip = SECURITY_TIPS[total_scans % len(SECURITY_TIPS)]
    st.markdown(f"<span class='tip-text'>{tip}</span>", unsafe_allow_html=True)
# ============================================================
# HEADER
# ============================================================
st.title(f"🛡️ {APP_NAME}")
st.caption("Paste or upload Python/Java source code — the agent auto-detects the language, analyzes vulnerabilities and quality, and generates a fixed version.")

# ============================================================
# CODE INPUT
# ============================================================
tab_paste, tab_upload = st.tabs(["📝 Paste Code", "📁 Upload File"])

code_input = ""

with tab_paste:
    pasted = st.text_area(
        "Paste your Python or Java code here:",
        height=250,
        placeholder="def my_function(): ...   /   public class Example { ... }"
    )
    if pasted.strip():
        code_input = pasted

with tab_upload:
    uploaded_file = st.file_uploader("Upload a .py or .java file", type=["py", "java"])
    if uploaded_file is not None:
        code_input = uploaded_file.read().decode("utf-8")
        ext = uploaded_file.name.split(".")[-1]
        st.code(code_input, language="java" if ext == "java" else "python")

run_clicked = st.button("⚡ Run Security Audit", type="primary", use_container_width=True)

# ============================================================
# RUN ANALYSIS
# ============================================================
if run_clicked:
    if not code_input.strip():
        st.warning("Please paste or upload some code first!")
    else:
        with st.spinner("Analyzing code for vulnerabilities..."):
            try:
                report = analyze_and_remediate(code_input)
                st.session_state["last_report"] = report

                detected_lang = extract_field(r"Detected Language.*?[:\-]?\s*([A-Za-z+#]+)", report)
                overall_severity = extract_field(r"Overall Severity Rating.*?(Critical|High|Medium|Informational|Low)", report)

                st.session_state["history"].append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "lang": detected_lang,
                    "severity": overall_severity if overall_severity != "N/A" else "Medium",
                    "report": report,
                })
                st.success("Audit completed successfully!")

            except Exception as e:
                st.error(f"An error occurred during analysis: {e}")

# ============================================================
# DISPLAY REPORT
# ============================================================
if st.session_state["last_report"]:
    report_text = st.session_state["last_report"]
    st.divider()

    quality_score = extract_field(r"Quality Score.*?(\d{1,2}\s*/\s*10|\d{1,2})", report_text)
    overall_severity = extract_field(r"Overall Severity Rating.*?(Critical|High|Medium|Informational|Low)", report_text)
    duplication = extract_field(r"Code Duplication Rating.*?(High|Medium|Low|None Detected)", report_text)
    detected_lang = extract_field(r"Detected Language.*?[:\-]?\s*([A-Za-z+#]+)", report_text)

    severity_class = {
        "Critical": "badge-critical", "High": "badge-high",
        "Medium": "badge-medium", "Informational": "badge-informational", "Low": "badge-low",
    }.get(overall_severity, "badge-low")

    st.markdown("#### Findings")
    table_rows = find_first_markdown_table(report_text)
    findings = build_findings(table_rows)

    if findings:
        for f in findings:
            render_finding_card(f)
    else:
        st.info("No structured findings table detected in this report — see the full report below.")

    with st.expander("View full technical report"):
        st.markdown(report_text)

    st.markdown("#### Refactored secure code")
    code_blocks = re.findall(r"```(?:\w+)?\n(.*?)```", report_text, re.DOTALL)
    if code_blocks:
        st.code(code_blocks[-1], language=guess_syntax_language(code_blocks[-1]))
    else:
        st.info("No refactored code block was returned in this report.")

    st.divider()
    st.markdown("#### Summary")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Language", detected_lang)
    col2.metric("Quality Score", quality_score)
    col3.metric("Duplication", duplication)
    with col4:
        st.markdown("Overall Severity")
        st.markdown(f"<span class='badge {severity_class}'>{overall_severity}</span>", unsafe_allow_html=True)

    # ============================================================
    # PDF EXPORT
    # ============================================================
    st.divider()
    st.markdown("#### Export report")

    def markdown_table_to_data(md_table_text):
        rows = []
        for line in md_table_text.strip().split("\n"):
            line = line.strip()
            if not line.startswith("|"):
                continue
            if re.match(r"^\|[\s\-:|]+\|$", line):
                continue
            cells = [c.strip() for c in line.strip("|").split("|")]
            rows.append(cells)
        return rows

    def generate_pdf_bytes(report_text):
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=letter,
            rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40
        )

        styles = getSampleStyleSheet()
        normal_style = ParagraphStyle(
            'ReportNormal', parent=styles['Normal'],
            fontSize=10, leading=14, textColor=colors.HexColor("#222222")
        )
        h1_style = ParagraphStyle(
            'ReportH1', parent=styles['Heading1'],
            fontSize=16, leading=20, textColor=colors.HexColor("#1A365D"),
            spaceBefore=14, spaceAfter=8
        )
        h2_style = ParagraphStyle(
            'ReportH2', parent=styles['Heading2'],
            fontSize=13, leading=16, textColor=colors.HexColor("#1A365D"),
            spaceBefore=10, spaceAfter=6
        )
        code_style = ParagraphStyle(
            'ReportCode', parent=styles['Code'],
            fontSize=8.5, leading=11, backColor=colors.HexColor("#f0f0f0"),
            borderPadding=6
        )

        def clean_inline(text):
            text = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
            text = re.sub(r'\*(.*?)\*', r'<i>\1</i>', text)
            return text

        story = [
            Paragraph(f"{APP_NAME} — Audit Report", h1_style),
            HRFlowable(width="100%", color=colors.HexColor("#cccccc")),
            Spacer(1, 10)
        ]

        lines = report_text.split("\n")
        i = 0
        in_code_block = False
        code_buffer = []

        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            if stripped.startswith("```"):
                if not in_code_block:
                    in_code_block = True
                    code_buffer = []
                else:
                    in_code_block = False
                    code_text = "\n".join(code_buffer)
                    safe_code = code_text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                    safe_code = safe_code.replace('\n', '<br/>')
                    story.append(Paragraph(safe_code, code_style))
                    story.append(Spacer(1, 8))
                i += 1
                continue

            if in_code_block:
                code_buffer.append(line)
                i += 1
                continue

            if stripped.startswith("|"):
                table_lines = []
                while i < len(lines) and lines[i].strip().startswith("|"):
                    table_lines.append(lines[i])
                    i += 1
                table_data = markdown_table_to_data("\n".join(table_lines))
                if table_data:
                    tbl = Table(table_data, hAlign="LEFT", repeatRows=1)
                    tbl.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1A365D")),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('FONTSIZE', (0, 0), (-1, -1), 8.5),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f7f7")]),
                        ('LEFTPADDING', (0, 0), (-1, -1), 5),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
                    ]))
                    story.append(tbl)
                    story.append(Spacer(1, 10))
                continue

            if stripped.startswith("### "):
                story.append(Paragraph(clean_inline(stripped[4:]), h2_style))
            elif stripped.startswith("## "):
                story.append(Paragraph(clean_inline(stripped[3:]), h2_style))
            elif stripped.startswith("# "):
                story.append(Paragraph(clean_inline(stripped[2:]), h1_style))
            elif stripped == "":
                story.append(Spacer(1, 6))
            else:
                story.append(Paragraph(clean_inline(stripped), normal_style))
                story.append(Spacer(1, 3))

            i += 1

        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()

    pdf_data = generate_pdf_bytes(report_text)

    st.download_button(
        label="📄 Download PDF Audit Report",
        data=pdf_data,
        file_name="security_audit_report.pdf",
        mime="application/pdf",
        type="secondary",
        use_container_width=True
    )