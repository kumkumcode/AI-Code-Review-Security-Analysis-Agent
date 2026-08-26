"""
helpers.py — Parsing, scoring, and formatting utilities for CodeReview.AI
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
from utils.theme import SEV_ICON

# ── Text cleaning ─────────────────────────────────────────────────────────────
def clean(text: str) -> str:
    """Strip markdown bold/italic markers and extra whitespace."""
    return re.sub(r'\*+', '', text or '').strip()


def field(pattern: str, text: str, default: str = "N/A") -> str:
    """Extract a single captured group from text via regex."""
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(1).strip() if m else default


# ── Markdown table parser ────────────────────────────────────────────────────
def find_table(text: str) -> list:
    """Find and parse the first markdown table in the report text."""
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        if lines[i].strip().startswith("|"):
            tbl = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                tbl.append(lines[i])
                i += 1
            rows = []
            for ln in tbl:
                ln = ln.strip()
                if re.match(r"^\|[\s\-:|]+\|$", ln):
                    continue
                rows.append([c.strip() for c in ln.strip("|").split("|")])
            if rows:
                return rows
        i += 1
    return []


def build_findings(rows: list) -> list:
    """Convert raw table rows into structured finding dicts."""
    if not rows or len(rows) < 2:
        return []

    header = [clean(h).lower() for h in rows[0]]

    def col(*keywords):
        for idx, h in enumerate(header):
            if any(k in h for k in keywords):
                return idx
        return None

    ip   = col("problem")
    il   = col("line")
    isev = col("severity")
    icat = col("category")

    findings = []
    for row in rows[1:]:
        def g(i, d="-"):
            return clean(row[i]) if i is not None and i < len(row) else d

        raw   = g(ip, "Issue")
        cwe_m = re.search(r"\(CWE-\d+\)", raw)
        cwe   = cwe_m.group(0) if cwe_m else ""
        prob  = re.sub(r"\s*\(CWE-\d+\)", "", raw).strip()
        sev   = g(isev, "Medium").strip().capitalize()
        if sev not in SEV_ICON:
            sev = "Medium"

        findings.append({
            "problem":   prob,
            "cwe":       cwe,
            "line":      g(il),
            "severity":  sev,
            "category":  g(icat, "General"),
        })
    return findings


# ── Plain-English finding explanations ───────────────────────────────────────
_EXPLAIN_MAP = [
    (["sql injection", "sql"],
     "Attackers can manipulate database queries to steal or modify data."),
    (["xss", "cross-site scripting"],
     "Attackers can inject scripts that run inside other users' browsers."),
    (["hardcoded secret", "hardcoded password", "hardcoded key", "cryptographic"],
     "A credential is stored in plain code — anyone with code access can read it."),
    (["csrf"],
     "Attackers could trick a logged-in user into taking unintended actions."),
    (["deserialization"],
     "Loading untrusted data this way could allow attackers to execute code."),
    (["input validation"],
     "The code does not verify incoming data is safe before using it."),
    (["access control", "authorization"],
     "Users may reach data or actions beyond their permitted access level."),
    (["duplication"],
     "Repeated logic means a bug fixed in one place may remain in duplicates."),
    (["type", "runtime"],
     "Unexpected input types are not guarded against — the app could crash."),
    (["resource", "leak"],
     "A file, connection, or resource is not properly closed after use."),
    (["exposure", "stack trace", "logging"],
     "Sensitive internal details could leak to logs or end users."),
]


def explain(problem: str, category: str) -> str:
    """Return a plain-English explanation for a finding."""
    combined = (problem + " " + category).lower()
    for keywords, msg in _EXPLAIN_MAP:
        if any(k in combined for k in keywords):
            return msg
    return "Flagged as a potential risk — see the full report for technical detail."


# ── Scoring and grading ───────────────────────────────────────────────────────
def risk_score(findings: list) -> int:
    """Calculate 0–100 health score from a list of findings."""
    deductions = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Informational": 1}
    return max(0, 100 - sum(deductions.get(f["severity"], 5) for f in findings))


def grade(score: int) -> tuple:
    """Return (letter, word) grade for a health score."""
    if score >= 90: return "A", "Excellent"
    if score >= 75: return "B", "Good"
    if score >= 60: return "C", "Needs Attention"
    if score >= 40: return "D", "High Risk"
    return "F", "Critical Risk"


def grade_color(score: int) -> str:
    """Return hex colour corresponding to a health score."""
    if score >= 90: return "#22c55e"
    if score >= 75: return "#3b82f6"
    if score >= 60: return "#eab308"
    if score >= 40: return "#f97316"
    return "#ef4444"


# ── Code helpers ─────────────────────────────────────────────────────────────
def guess_lang(text: str) -> str:
    """Heuristically detect whether a code block is Java or Python."""
    t = text.lower()
    return "java" if ("public class" in t or "system.out" in t) else "python"


def strip_code_fences(text: str) -> str:
    """Replace fenced code blocks with a pointer to the Refactored Code section."""
    return re.sub(
        r"```(?:\w+)?\n.*?```",
        "*(see Refactored Code section below)*",
        text, flags=re.DOTALL
    )


def render_chat_markdown(text: str) -> str:
    """
    Convert assistant response markdown into safe inline HTML for st.markdown.
    Keeps output clean and readable — no raw ** or ## showing through.
    """
    # Escape HTML special chars first
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # Bold
    text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
    # Inline code
    text = re.sub(
        r'`([^`]+)`',
        r'<code style="background:rgba(99,102,241,0.15);padding:1px 5px;'
        r'border-radius:4px;font-family:monospace;font-size:0.82rem;">\1</code>',
        text
    )
    # Numbered list items
    text = re.sub(r'(?m)^(\d+)\.\s+', r'<br><b>\1.</b> ', text)
    # Bullet list items
    text = re.sub(r'(?m)^[\-\*]\s+', r'<br>• ', text)
    # Headers → bold accent line
    text = re.sub(
        r'(?m)^#{1,3}\s+(.+)',
        r'<br><b style="color:#818cf8;">\1</b>',
        text
    )
    # Newlines → <br>
    text = text.replace('\n', '<br>')
    # Remove leading <br> tags
    text = re.sub(r'^(<br>\s*)+', '', text)
    return text
