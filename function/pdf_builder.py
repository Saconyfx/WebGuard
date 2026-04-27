"""
PDF report generator.

Takes a ScanResponse and renders a multi-page PDF:
  - Cover page with metadata + severity summary
  - Severity bar chart
  - One card per finding with code snippet
"""

import io
import logging
from datetime import datetime, timezone
from typing import List

from reportlab.lib.pagesizes import LETTER
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, white, black, Color
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_RIGHT, TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, Flowable,
)

from models import ScanResponse, Finding

log = logging.getLogger("webguard.pdf")

# ─── Brand colors ─────────────────────────────────────────────
C_INK       = HexColor("#14161A")
C_CHARCOAL  = HexColor("#3A3F47")
C_SLATE     = HexColor("#5B6270")
C_STONE     = HexColor("#8B919C")
C_DUST      = HexColor("#B8BDC5")
C_MIST      = HexColor("#D9DCE1")
C_FOG       = HexColor("#E7E9ED")
C_PAPER     = HexColor("#F7F6F2")
C_WHITE     = white

C_CRIMSON_50  = HexColor("#FEF0EF")
C_CRIMSON_100 = HexColor("#FCD9D6")
C_CRIMSON_500 = HexColor("#B8251C")
C_CRIMSON_600 = HexColor("#9B1C1C")
C_CRIMSON_700 = HexColor("#7E1414")

# Severity → color
SEV_COLORS = {
    "critical": (HexColor("#9B1C1C"), C_WHITE,             HexColor("#7E1414")),  # bg, text, border
    "high":     (HexColor("#FEF0EF"), HexColor("#7E1414"), HexColor("#FCD9D6")),
    "med":      (HexColor("#FDF1DC"), HexColor("#A36A00"), HexColor("#F5D6A3")),
    "low":      (HexColor("#E4EDFB"), HexColor("#0B4AA8"), HexColor("#C1D5F4")),
    "info":     (HexColor("#F0F1F4"), HexColor("#3A3F47"), HexColor("#D9DCE1")),
    "clean":    (HexColor("#E6F4EC"), HexColor("#0D7A3F"), HexColor("#B4D9C0")),
}

SEV_LABEL = {
    "critical": "CRITICAL", "high": "HIGH", "med": "MEDIUM",
    "low": "LOW", "info": "INFO", "clean": "CLEAN",
}

SEV_ORDER = ["critical", "high", "med", "low", "info", "clean"]


# ─── Custom flowables ─────────────────────────────────────────
class SeverityBar(Flowable):
    """Stacked horizontal bar showing severity proportions."""
    def __init__(self, counts: dict, width=6.5*inch, height=0.45*inch):
        super().__init__()
        self.counts = counts
        self.width = width
        self.height = height

    def draw(self):
        c = self.canv
        total = sum(self.counts.values()) or 1
        x = 0
        for sev in SEV_ORDER:
            n = self.counts.get(sev, 0)
            if n == 0:
                continue
            w = (n / total) * self.width
            bg, _, _ = SEV_COLORS[sev]
            c.setFillColor(bg)
            c.rect(x, 0, w, self.height, fill=1, stroke=0)
            # Label inside bar if wide enough
            if w > 0.4 * inch:
                c.setFillColor(C_WHITE if sev == "critical" else C_INK)
                c.setFont("Helvetica-Bold", 9)
                c.drawCentredString(x + w/2, self.height/2 - 3, f"{n} {SEV_LABEL[sev]}")
            x += w
        # Border
        c.setStrokeColor(C_MIST)
        c.setLineWidth(0.5)
        c.rect(0, 0, self.width, self.height, fill=0, stroke=1)


class HRule(Flowable):
    """Horizontal rule line."""
    def __init__(self, color=C_FOG, width=6.5*inch, thickness=0.5):
        super().__init__()
        self.color = color
        self.width = width
        self.thickness = thickness
        self.height = thickness

    def draw(self):
        c = self.canv
        c.setStrokeColor(self.color)
        c.setLineWidth(self.thickness)
        c.line(0, 0, self.width, 0)


# ─── Page header / footer ─────────────────────────────────────
def _on_page(canvas, doc):
    """Footer on every page: page number + brand."""
    canvas.saveState()
    page_num = canvas.getPageNumber()
    width, height = LETTER

    # Footer line
    canvas.setStrokeColor(C_FOG)
    canvas.setLineWidth(0.5)
    canvas.line(0.75*inch, 0.55*inch, width - 0.75*inch, 0.55*inch)

    # Footer text
    canvas.setFillColor(C_STONE)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(0.75*inch, 0.4*inch, "WebGuard Security Report")
    canvas.drawRightString(width - 0.75*inch, 0.4*inch, f"Page {page_num}")

    # Crimson accent on header (every page after first)
    if page_num > 1:
        canvas.setFillColor(C_CRIMSON_600)
        canvas.rect(0, height - 0.2*inch, width, 0.05*inch, fill=1, stroke=0)

    canvas.restoreState()


# ─── Styles ───────────────────────────────────────────────────
def _build_styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title", parent=base["Title"],
            fontName="Helvetica-Bold", fontSize=28,
            textColor=C_INK, spaceAfter=8,
            leading=32, alignment=TA_LEFT,
        ),
        "subtitle": ParagraphStyle(
            "subtitle", parent=base["Normal"],
            fontName="Helvetica", fontSize=12,
            textColor=C_SLATE, spaceAfter=20, leading=18,
        ),
        "h2": ParagraphStyle(
            "h2", parent=base["Heading2"],
            fontName="Helvetica-Bold", fontSize=14,
            textColor=C_INK, spaceBefore=18, spaceAfter=10,
        ),
        "meta_label": ParagraphStyle(
            "meta_label", parent=base["Normal"],
            fontName="Helvetica", fontSize=9,
            textColor=C_STONE, leading=12,
        ),
        "meta_value": ParagraphStyle(
            "meta_value", parent=base["Normal"],
            fontName="Helvetica-Bold", fontSize=10.5,
            textColor=C_INK, leading=14, spaceAfter=4,
        ),
        "finding_title": ParagraphStyle(
            "finding_title", parent=base["Normal"],
            fontName="Helvetica-Bold", fontSize=11,
            textColor=C_INK, leading=14, spaceAfter=4,
        ),
        "finding_meta": ParagraphStyle(
            "finding_meta", parent=base["Normal"],
            fontName="Helvetica", fontSize=8.5,
            textColor=C_SLATE, leading=11, spaceAfter=4,
        ),
        "finding_body": ParagraphStyle(
            "finding_body", parent=base["Normal"],
            fontName="Helvetica", fontSize=10,
            textColor=C_CHARCOAL, leading=14, spaceAfter=6,
        ),
        "code": ParagraphStyle(
            "code", parent=base["Normal"],
            fontName="Courier", fontSize=8.5,
            textColor=C_INK, leading=11,
        ),
        "code_vuln": ParagraphStyle(
            "code_vuln", parent=base["Normal"],
            fontName="Courier-Bold", fontSize=8.5,
            textColor=C_CRIMSON_700, leading=11,
        ),
    }


# ─── Helpers ──────────────────────────────────────────────────
def _escape_for_paragraph(text: str) -> str:
    """Escape HTML-ish chars so ReportLab's Paragraph parser is happy."""
    return (text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;"))


def _severity_badge(sev: str) -> Table:
    """Small colored badge for severity."""
    bg, fg, border = SEV_COLORS.get(sev, SEV_COLORS["info"])
    label = SEV_LABEL.get(sev, sev.upper())
    t = Table([[label]], colWidths=[0.85*inch], rowHeights=[0.22*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), bg),
        ("TEXTCOLOR",  (0,0), (-1,-1), fg),
        ("BOX",        (0,0), (-1,-1), 0.5, border),
        ("FONTNAME",   (0,0), (-1,-1), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 8),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
    ]))
    return t


def _code_snippet_table(snip: dict, vuln_line: int) -> Table:
    """Render the snippet as a 2-column table: line numbers | code."""
    if not snip:
        return None
    rows = []
    styles = []
    for i, raw in enumerate(snip.get("lines", [])):
        line_no = snip["start_line"] + i
        is_vuln = line_no == vuln_line
        # Truncate ultra-long lines so they fit on the page
        display = raw if len(raw) <= 110 else raw[:107] + "..."
        rows.append([str(line_no), display.replace("\t", "  ")])
        if is_vuln:
            styles.append(("BACKGROUND", (0, i), (-1, i), C_CRIMSON_50))
            styles.append(("TEXTCOLOR", (1, i), (1, i), C_CRIMSON_700))
            styles.append(("FONTNAME", (1, i), (1, i), "Courier-Bold"))
            styles.append(("LINEBEFORE", (0, i), (0, i), 2, C_CRIMSON_600))

    if not rows:
        return None

    t = Table(rows, colWidths=[0.45*inch, 5.85*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (0,-1), C_FOG),
        ("TEXTCOLOR",   (0,0), (0,-1), C_STONE),
        ("FONTNAME",    (0,0), (-1,-1), "Courier"),
        ("FONTSIZE",    (0,0), (-1,-1), 8),
        ("ALIGN",       (0,0), (0,-1), "RIGHT"),
        ("VALIGN",      (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (0,-1), 6),
        ("RIGHTPADDING",(0,0), (0,-1), 8),
        ("LEFTPADDING", (1,0), (1,-1), 8),
        ("TOPPADDING",  (0,0), (-1,-1), 2),
        ("BOTTOMPADDING",(0,0),(-1,-1), 2),
        ("BOX",         (0,0), (-1,-1), 0.5, C_MIST),
    ] + styles))
    return t


def _finding_card(idx: int, f: Finding, styles: dict) -> KeepTogether:
    """One boxed card per finding."""
    sev = f.sev
    bg, _, border = SEV_COLORS.get(sev, SEV_COLORS["info"])

    # Header row: badge + title + line + code
    header_data = [[
        _severity_badge(sev),
        Paragraph(
            f"<b>#{idx:02d}</b> &nbsp;&nbsp; "
            f"<font color='#5B6270'>line</font> "
            f"<font color='#14161A'><b>{f.line or '—'}</b></font>",
            styles["finding_meta"]
        ),
        Paragraph(
            f"<font color='#5B6270'>{_escape_for_paragraph(f.code)}</font> · "
            f"<font color='#5B6270'>by {_escape_for_paragraph(f.tool or 'scanner')}</font>",
            styles["finding_meta"]
        ),
    ]]
    header = Table(header_data, colWidths=[0.95*inch, 1.5*inch, None])
    header.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("ALIGN",  (2,0), (2,0), "RIGHT"),
        ("LEFTPADDING", (0,0), (-1,-1), 0),
        ("RIGHTPADDING",(0,0),(-1,-1), 0),
        ("TOPPADDING",  (0,0), (-1,-1), 0),
        ("BOTTOMPADDING",(0,0),(-1,-1), 0),
    ]))

    parts = [
        header,
        Spacer(1, 6),
        Paragraph(
            f"<b>{_escape_for_paragraph(f.cat)}</b>",
            styles["finding_title"]
        ),
        Paragraph(_escape_for_paragraph(f.finding), styles["finding_body"]),
    ]

    # Snippet
    snip_dict = f.code_snippet.model_dump() if f.code_snippet else None
    if snip_dict and snip_dict.get("lines"):
        snippet_tbl = _code_snippet_table(snip_dict, f.line)
        if snippet_tbl:
            parts.append(snippet_tbl)

    # Wrap entire card with a left-color stripe
    inner = Table([[parts]], colWidths=[6.4*inch])
    inner.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C_PAPER),
        ("LEFTPADDING",  (0,0), (-1,-1), 14),
        ("RIGHTPADDING", (0,0), (-1,-1), 14),
        ("TOPPADDING",   (0,0), (-1,-1), 12),
        ("BOTTOMPADDING",(0,0), (-1,-1), 12),
        ("LINEBEFORE",   (0,0), (0,-1), 4, border),
        ("BOX",          (0,0), (-1,-1), 0.5, C_MIST),
    ]))

    return KeepTogether([inner, Spacer(1, 10)])


# ─── Public entrypoint ────────────────────────────────────────
def build_pdf(scan: ScanResponse) -> bytes:
    """Render the scan to a PDF and return raw bytes."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=LETTER,
        leftMargin=0.75*inch, rightMargin=0.75*inch,
        topMargin=0.75*inch, bottomMargin=0.75*inch,
        title="WebGuard Security Report",
        author="WebGuard",
    )
    styles = _build_styles()
    story = []

    # ── Cover ───────────────────────────────────────────────
    story.append(Paragraph("WebGuard", styles["title"]))
    story.append(Paragraph("Security Analysis Report", styles["subtitle"]))
    story.append(HRule(C_CRIMSON_600, thickness=2, width=2*inch))
    story.append(Spacer(1, 18))

    # Metadata table
    now = datetime.now(timezone.utc).strftime("%B %d, %Y · %H:%M UTC")
    meta_rows = [
        ["Source",       scan.source or "—"],
        ["Generated",    now],
        ["Scan duration",f"{scan.scan_seconds:.2f} seconds"],
        ["Tools used",   ", ".join(scan.tools_run) or "—"],
    ]
    if scan.tools_failed:
        meta_rows.append(["Tools failed", ", ".join(scan.tools_failed)])

    meta_tbl = Table(meta_rows, colWidths=[1.25*inch, 5.0*inch])
    meta_tbl.setStyle(TableStyle([
        ("FONTNAME",  (0,0), (0,-1), "Helvetica"),
        ("FONTNAME",  (1,0), (1,-1), "Helvetica-Bold"),
        ("FONTSIZE",  (0,0), (-1,-1), 10),
        ("TEXTCOLOR", (0,0), (0,-1), C_STONE),
        ("TEXTCOLOR", (1,0), (1,-1), C_INK),
        ("VALIGN",    (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING",(0,0),(-1,-1), 0),
        ("BOTTOMPADDING",(0,0),(-1,-1), 5),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 24))

    # Severity summary
    counts = {s: 0 for s in SEV_ORDER}
    for f in scan.findings:
        counts[f.sev] = counts.get(f.sev, 0) + 1
    total = sum(counts.values())

    story.append(Paragraph("Executive Summary", styles["h2"]))
    story.append(HRule())
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        f"<b>{total}</b> findings across <b>{len(scan.tools_run)}</b> scanner(s).",
        styles["finding_body"]
    ))
    story.append(Spacer(1, 8))
    story.append(SeverityBar(counts))
    story.append(Spacer(1, 20))

    # ── Findings ────────────────────────────────────────────
    if scan.findings:
        story.append(PageBreak())
        story.append(Paragraph("Findings Detail", styles["h2"]))
        story.append(HRule())
        story.append(Spacer(1, 12))
        for i, f in enumerate(scan.findings, 1):
            story.append(_finding_card(i, f, styles))
    else:
        story.append(Paragraph(
            "<b>No findings.</b> All scanners completed without flagging any issues.",
            styles["finding_body"]
        ))

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    pdf_bytes = buf.getvalue()
    buf.close()
    return pdf_bytes
