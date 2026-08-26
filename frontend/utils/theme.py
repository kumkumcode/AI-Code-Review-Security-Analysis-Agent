"""
theme.py — Colour palette, constants, and global CSS for CodeReview.AI
"""

# ── Colour palette (Kiro-inspired dark theme) ─────────────────────────────
ACCENT   = "#6366f1"
ACCENT2  = "#818cf8"
BG_DARK  = "#0d0d14"
BG_PANEL = "#13131f"
BG_CARD  = "#1a1a2e"
BORDER   = "#2a2a45"
TXT_PRI  = "#f1f5f9"
TXT_SEC  = "#94a3b8"
TXT_MUT  = "#475569"

SEV_COLOR = {
    "Critical":      "#ef4444",
    "High":          "#f97316",
    "Medium":        "#eab308",
    "Low":           "#22c55e",
    "Informational": "#3b82f6",
}

SEV_ICON = {
    "Critical":      "🔴",
    "High":          "🟠",
    "Medium":        "🟡",
    "Low":           "🟢",
    "Informational": "🔵",
}

TIPS = [
    "Never build SQL queries with string concatenation — always use parameterised queries.",
    "Store secrets in environment variables, never directly in source code.",
    "Validate and sanitise all user input before using it in DB or system calls.",
    "Use bcrypt, scrypt, or Argon2 for passwords — never MD5 or SHA-1.",
    "Keep dependencies updated — outdated libraries are a top attack surface.",
    "Enforce access control server-side, never just by hiding a button or URL.",
    "Avoid deserialising untrusted data — prefer JSON over pickle.",
    "Log authentication failures, but never log passwords or tokens.",
    "Disable debug mode and verbose errors before going to production.",
    "Rate-limit login endpoints to stop brute-force attacks.",
]


def get_global_css() -> str:
    """Returns the full CSS block injected once by dashboard.py."""
    return f"""
<style>
/* ── Global App Background & Container Resets ── */
.stApp {{
    background: {BG_DARK} !important;
}}

.main, .block-container, [data-testid="stMainBlockContainer"] {{
    padding: 1rem 1.5rem !important;
    max-width: 100% !important;
    width: 100% !important;
    margin: 0 !important;
}}

/* ── Hide Streamlit chrome ── */
[data-testid="stHeader"],
[data-testid="stToolbar"],
[data-testid="stSidebar"],
footer, #MainMenu {{ display:none !important; }}

/* ── Top bar ── */
.topbar {{
    display:flex; align-items:center; justify-content:space-between;
    background:linear-gradient(90deg,#17132a 0%,#100f1c 100%);
    border-bottom:1px solid rgba(167,139,250,.32);
    padding:14px 24px; position:sticky; top:0; z-index:999;
    min-height:78px; box-shadow: 0 1px 8px rgba(0,0,0,0.4);
    margin: -1rem -1.5rem 1.5rem -1.5rem;
}}
.tb-brand {{ display:flex; align-items:center; gap:10px; }}
.tb-icon {{
    width:38px; height:38px; border-radius:9px; background:linear-gradient(135deg,#8b5cf6,#6366f1);
    display:flex; align-items:center; justify-content:center; font-size:16px;
    box-shadow:0 7px 18px rgba(124,58,237,.28);
}}
.tb-name {{ font-size:1.1rem; font-weight:700; color:{TXT_PRI}; }}
.tb-sub  {{ font-size:0.72rem; color:#b9b0df; letter-spacing:0.05em; }}
.tb-badge {{
    background:rgba(99,102,241,0.15); border:1px solid rgba(99,102,241,0.3);
    color:{ACCENT2}; font-size:0.7rem; padding:3px 10px;
    border-radius:20px; font-weight:600;
}}

/* ── Clean Panel Styling ── */
.plabel {{
    font-size:0.69rem; font-weight:700; color:#a78bfa;
    letter-spacing:0.08em; text-transform:uppercase;
    padding:10px 0 5px 0;
}}

.history-title {{
    color:#f8f7ff; font-size:1.04rem; font-weight:800;
    letter-spacing:.01em; padding:0 0 13px;
    border-bottom:1px solid rgba(167,139,250,.25); margin-bottom:8px;
}}

.hitem {{
    padding:10px 11px; border-radius:10px; margin-bottom:6px;
    background:#1a1728; border:1px solid rgba(167,139,250,.18);
}}
.hitem:hover {{
    background:#231d39;
    border-color:#8b5cf6;
}}
.hitem-title {{ font-size:0.82rem; font-weight:600; color:{TXT_PRI}; }}
.hitem-meta  {{ font-size:0.72rem; color:{TXT_SEC}; margin-top:3px; }}

.tip-box {{
    background:linear-gradient(145deg,rgba(124,58,237,.16),rgba(99,102,241,.07));
    border:1px solid rgba(167,139,250,.35);
    border-radius:8px; padding:10px 12px;
    font-size:0.76rem; color:#d7d1f3; line-height:1.5; margin-top:6px;
}}

.mc {{
    background:{BG_CARD}; border:1px solid {BORDER};
    border-radius:10px; padding:13px 15px; height:100%;
}}
.mc-label {{
    font-size:0.65rem; font-weight:700; color:{TXT_SEC};
    text-transform:uppercase; letter-spacing:0.06em; margin-bottom:6px;
}}
.mc-value {{ font-size:1.5rem; font-weight:800; color:{TXT_PRI}; line-height:1; }}
.mc-sub   {{ font-size:0.72rem; color:{TXT_SEC}; margin-top:4px; }}

.shdr {{
    font-size:0.72rem; font-weight:700; color:{TXT_SEC};
    letter-spacing:0.07em; text-transform:uppercase;
    display:flex; align-items:center; gap:8px;
    margin:20px 0 10px 0;
}}
.shdr-line {{ flex:1; height:1px; background:{BORDER}; }}

.exec-box {{
    background:rgba(99,102,241,0.08);
    border:1px solid rgba(99,102,241,0.2);
    border-radius:10px; padding:14px 18px;
    font-size:0.87rem; color:#e2e8f0; line-height:1.6; margin-bottom:16px;
}}

.fcard {{
    background:{BG_CARD}; border:1px solid {BORDER};
    border-radius:10px; padding:13px 15px; margin-bottom:8px;
    border-left:4px solid {ACCENT};
}}
.fcard-title  {{ font-size:0.9rem; font-weight:700; color:{TXT_PRI}; }}
.fcard-meta   {{ font-size:0.74rem; color:{TXT_SEC}; margin:4px 0 6px 0; }}
.fcard-explain{{ font-size:0.83rem; color:#cbd5e1; line-height:1.5; }}
.sev-pill {{
    display:inline-block; padding:2px 8px; border-radius:20px;
    font-size:0.68rem; font-weight:700; margin-left:6px;
}}

/* ── Chat Panel Styles ── */
.chat-hdr {{
    display:flex; align-items:center; gap:10px;
    padding:14px 16px; border-bottom:1px solid rgba(167,139,250,.28);
    background:linear-gradient(90deg,#18152a,#12111d);
    border-top-left-radius: 12px; border-top-right-radius: 12px;
}}
.cipher-av {{
    width:38px; height:38px; border-radius:50%;
    background:linear-gradient(135deg,#8b5cf6,#c084fc);
    display:flex; align-items:center; justify-content:center;
    font-size:14px; flex-shrink:0;
    box-shadow:0 6px 16px rgba(124,58,237,.32);
}}
.cipher-nm {{ font-size:1rem; font-weight:700; color:{TXT_PRI}; }}
.cipher-st {{ font-size:0.68rem; color:#56e891; }}
.dot {{
    display:inline-block; width:6px; height:6px;
    border-radius:50%; background:#56e891; margin-right:3px;
}}

.msg-u {{
    align-self:flex-end; background:rgba(124,58,237,.28);
    border:1px solid rgba(167,139,250,.45); color:{TXT_PRI};
    padding:8px 12px; border-radius:12px 12px 2px 12px;
    max-width:86%; font-size:0.84rem; line-height:1.5; word-wrap:break-word;
}}
.msg-b {{
    align-self:flex-start; background:#1b1829;
    border:1px solid rgba(167,139,250,.2); color:{TXT_PRI};
    padding:8px 12px; border-radius:2px 12px 12px 12px;
    max-width:92%; font-size:0.84rem; line-height:1.55; word-wrap:break-word;
}}
.msg-b-name {{
    font-size:0.67rem; font-weight:700; color:{ACCENT2}; margin-bottom:4px;
}}
.ctx-banner {{
    margin:13px 14px 4px;
    background:rgba(124,58,237,.1); border:1px solid rgba(167,139,250,.28);
    border-radius:6px; padding:5px 10px; font-size:0.71rem; color:#c4b5fd;
}}

/* ── Streamlit Element Tweaks ── */
textarea {{
    background:{BG_DARK} !important; color:{TXT_PRI} !important;
    border:1px solid {BORDER} !important; border-radius:8px !important;
    font-family:'Fira Code',monospace !important; font-size:0.84rem !important;
}}
.stButton>button {{
    background:linear-gradient(90deg,#7c3aed,#6366f1) !important; color:white !important;
    border:none !important; border-radius:8px !important;
    font-weight:600 !important; padding:9px 18px !important;
    box-shadow:0 7px 16px rgba(99,102,241,.25);
    width: 100%;
}}
.stButton>button:hover {{ background:#4f46e5 !important; }}
[data-testid="stFileUploader"] {{
    background:{BG_CARD} !important;
    border:1px dashed {BORDER} !important; border-radius:8px !important;
}}
[data-baseweb="tab"]   {{ color:{TXT_SEC} !important; font-size:0.82rem !important; }}
[aria-selected="true"] {{
    color:{TXT_PRI} !important; border-bottom:2px solid {ACCENT} !important;
}}
[data-testid="stExpander"] {{
    background:{BG_CARD} !important; border:1px solid {BORDER} !important;
    border-radius:10px !important; margin-bottom:6px !important;
}}

/* ── Lock CipHer Panel Inside Column Card Container ── */
div[data-testid="column"]:nth-of-type(3) {{
    display: flex;
    flex-direction: column;
    height: 100%;
}}
div[data-testid="column"]:nth-of-type(3) > div {{
    display: flex;
    flex-direction: column;
    height: 100%;
}}
div[data-testid="column"]:nth-of-type(3) [data-testid="stVerticalBlock"] {{
    gap: 0.4rem;
}}
</style>
"""