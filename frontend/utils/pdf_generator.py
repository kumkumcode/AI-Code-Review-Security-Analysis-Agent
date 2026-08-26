"""
pdf_generator.py — Professional AST-structured PDF audit report generator for CodeReview.AI
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import io
import re
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors as rl_colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, HRFlowable, KeepTogether,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from utils.helpers import explain


_SEV_RGB = {
    "Critical":      (220, 38,  38),
    "High":          (249, 115, 22),
    "Medium":        (234, 179,  8),
    "Low":           (34,  197, 94),
    "Informational": (59,  130, 246),
}


class ReportNode:
    """AST Node base for structured PDF generation."""
    def render(self, story, styles):
        raise NotImplementedError


class SectionNode(ReportNode):
    def __init__(self, title, children=None):
        self.title = title
        self.children = children or []

    def render(self, story, styles):
        story.append(Paragraph(self.title, styles["h2"]))
        story.append(HRFlowable(width="100%", color=rl_colors.HexColor("#e2e8f0")))
        story.append(Spacer(1, 6))
        for child in self.children:
            child.render(story, styles)


def _ci(text: str) -> str:
    text = (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
    text = re.sub(r'(?<!\*)\*(?!\*)(.*?)\*', r'<i>\1</i>', text)
    return text


def _make_styles():
    base = getSampleStyleSheet()
    return {
        "h1": ParagraphStyle("H1", parent=base["Heading1"], fontSize=20, leading=24, textColor=rl_colors.HexColor("#1e1b4b"), spaceAfter=10),
        "h2": ParagraphStyle("H2", parent=base["Heading2"], fontSize=13, leading=16, textColor=rl_colors.HexColor("#3730a3"), spaceBefore=14, spaceAfter=6),
        "h3": ParagraphStyle("H3", parent=base["Heading3"], fontSize=11, leading=14, textColor=rl_colors.HexColor("#4338ca"), spaceBefore=8, spaceAfter=4),
        "body": ParagraphStyle("Body", parent=base["Normal"], fontSize=9.5, leading=14, textColor=rl_colors.HexColor("#1e293b")),
        "code": ParagraphStyle("Code", parent=base["Code"], fontSize=8, leading=11, backColor=rl_colors.HexColor("#f1f5f9"), borderPadding=5, textColor=rl_colors.HexColor("#0f172a")),
        "meta": ParagraphStyle("Meta", parent=base["Normal"], fontSize=8.5, leading=12, textColor=rl_colors.HexColor("#64748b")),
    }


def generate_pdf(report_text: str, findings: list, lang: str,
                 score: int, grade_letter: str, grade_word: str,
                 quality: str, dup: str, sev: str) -> bytes:
    buf    = io.BytesIO()
    doc    = SimpleDocTemplate(buf, pagesize=A4, rightMargin=2*cm, leftMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
    styles = _make_styles()
    story  = []

    # Title & Metadata Cover Block
    story.append(Paragraph("CodeReview.AI", styles["h1"]))
    story.append(Paragraph("Security &amp; Code Quality Audit Report", styles["h2"]))
    story.append(HRFlowable(width="100%", color=rl_colors.HexColor("#6366f1"), thickness=2))
    story.append(Spacer(1, 10))

    by_sev = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    meta_rows = [
        ["Report Date",       datetime.now().strftime("%B %d, %Y  %H:%M")],
        ["Language",          lang],
        ["Quality Score",     quality],
        ["Duplication",       dup],
        ["Overall Severity",  sev],
        ["Health Score",      f"{score} / 100  (Grade {grade_letter} — {grade_word})"],
        ["Total Findings",    str(len(findings))],
        ["Critical / High",   f"{by_sev.get('Critical',0)} Critical  ·  {by_sev.get('High',0)} High"],
    ]
    mt = Table(meta_rows, colWidths=[4.5*cm, 12.5*cm])
    mt.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (0, -1), rl_colors.HexColor("#6366f1")),
        ("TEXTCOLOR", (1, 0), (1, -1), rl_colors.HexColor("#1e293b")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [rl_colors.white, rl_colors.HexColor("#f8fafc")]),
        ("BOX", (0, 0), (-1, -1), 0.4, rl_colors.HexColor("#e2e8f0")),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, rl_colors.HexColor("#e2e8f0")),
    ]))
    story.append(mt)
    story.append(Spacer(1, 16))

    # Executive Summary
    story.append(Paragraph("Executive Summary", styles["h2"]))
    story.append(HRFlowable(width="100%", color=rl_colors.HexColor("#e2e8f0")))
    story.append(Spacer(1, 6))
    total = len(findings)
    crit  = by_sev.get("Critical", 0)
    high  = by_sev.get("High",     0)
    exec_txt = f"The automated audit identified <b>{total} issue(s)</b> in the submitted {lang} code — <b>{crit} Critical</b>, <b>{high} High</b>. Overall health score: <b>{score}/100</b> (Grade <b>{grade_letter} — {grade_word}</b>)."
    story.append(Paragraph(exec_txt, styles["body"]))
    story.append(Spacer(1, 16))

    # Findings Summary Table
    if findings:
        story.append(Paragraph("Findings Summary", styles["h2"]))
        story.append(HRFlowable(width="100%", color=rl_colors.HexColor("#e2e8f0")))
        story.append(Spacer(1, 6))

        data = [["#", "Finding", "Severity", "Line", "Category"]]
        for i, f in enumerate(findings, 1):
            data.append([str(i), f["problem"], f["severity"], str(f["line"]), f["category"]])

        ft = Table(data, colWidths=[0.8*cm, 7.2*cm, 2.5*cm, 1.5*cm, 5*cm])
        ft.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), rl_colors.HexColor("#1e1b4b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), rl_colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
            ("TOPPADDING", (0, 0), (-1, 0), 6),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [rl_colors.white, rl_colors.HexColor("#f8fafc")]),
            ("BOX", (0, 0), (-1, -1), 0.4, rl_colors.HexColor("#e2e8f0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.4, rl_colors.HexColor("#e2e8f0")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(ft)
        story.append(Spacer(1, 16))

    doc.build(story)
    buf.seek(0)
    return buf.getvalue()