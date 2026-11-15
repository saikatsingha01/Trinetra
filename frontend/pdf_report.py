from __future__ import annotations

from io import BytesIO
from xml.sax.saxutils import escape
from typing import Any
from email import policy
from email.parser import Parser
import json
import re
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    LongTable,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


# ---------------------------------------------------------------------------
# Fonts: use a real Unicode font instead of PDF core Helvetica so characters
# from real-world Gmail messages are not silently dropped during generation.
# ---------------------------------------------------------------------------
_FONT_REG = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
_FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
_FONT_MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
_FONT_MONO_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"

try:
    if Path(_FONT_REG).exists():
        pdfmetrics.registerFont(TTFont("TRI-Sans", _FONT_REG))
        pdfmetrics.registerFont(TTFont("TRI-Sans-Bold", _FONT_BOLD))
        pdfmetrics.registerFont(TTFont("TRI-Mono", _FONT_MONO))
        pdfmetrics.registerFont(TTFont("TRI-Mono-Bold", _FONT_MONO_BOLD))
        FONT = "TRI-Sans"
        FONT_BOLD = "TRI-Sans-Bold"
        FONT_MONO = "TRI-Mono"
        FONT_MONO_BOLD = "TRI-Mono-Bold"
    else:
        FONT = FONT_BOLD = FONT_MONO = FONT_MONO_BOLD = "Helvetica"
except Exception:
    FONT = FONT_BOLD = FONT_MONO = FONT_MONO_BOLD = "Helvetica"


# TRINETRA website palette.
BG = colors.HexColor("#071016")
PANEL = colors.HexColor("#0d171d")
PANEL2 = colors.HexColor("#111e26")
PANEL3 = colors.HexColor("#15242c")
INK = colors.HexColor("#edf6f8")
MUTED = colors.HexColor("#8298a3")
CYAN = colors.HexColor("#79e3f2")
GREEN = colors.HexColor("#59d6a1")
AMBER = colors.HexColor("#f1c36d")
RED = colors.HexColor("#ff6b78")
PURPLE = colors.HexColor("#b89cff")
GRID = colors.HexColor("#24343d")


def _clean_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    # Remove control characters that ReportLab can mis-handle while keeping
    # normal newlines/tabs. Also normalize common typography characters to
    # ASCII-safe forms where possible.
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", text)
    replacements = {
        "\u2013": "-",
        "\u2014": "-",
        "\u2212": "-",
        "\u00a0": " ",
        "\u200b": "",
        "\u200c": "",
        "\u200d": "",
        "\ufeff": "",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


def _inline(text: Any) -> str:
    return escape(_clean_text(text), {'"': '&quot;'})


def _tone(verdict: str | None) -> colors.Color:
    v = _clean_text(verdict).upper()
    if v in {"CRITICAL", "MALICIOUS"}:
        return RED
    if v in {"HIGH", "SUSPICIOUS", "PHISHING"}:
        return AMBER
    if v in {"MEDIUM", "WARN", "WARNING"}:
        return PURPLE
    return GREEN


class DarkDoc(BaseDocTemplate):
    def __init__(self, buffer: BytesIO):
        super().__init__(
            buffer,
            pagesize=A4,
            leftMargin=14 * mm,
            rightMargin=14 * mm,
            topMargin=16 * mm,
            bottomMargin=17 * mm,
            title="TRINETRA Email Threat Assessment",
            author="TRINETRA",
            subject="Email threat analysis report",
        )
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="main")
        self.addPageTemplates([PageTemplate(id="dark", frames=[frame], onPage=self._draw_page)])

    @staticmethod
    def _draw_page(canvas, doc):
        canvas.saveState()
        w, h = A4
        canvas.setFillColor(BG)
        canvas.rect(0, 0, w, h, fill=1, stroke=0)
        canvas.setFillColor(colors.HexColor("#42545d"))
        canvas.setFont(FONT_MONO, 7.2)
        canvas.drawString(14 * mm, 8.5 * mm, "TRINETRA // EMAIL THREAT INTELLIGENCE")
        canvas.drawRightString(w - 14 * mm, 8.5 * mm, f"PAGE {doc.page}")
        canvas.restoreState()


def _style(name: str, **kwargs) -> ParagraphStyle:
    kwargs.setdefault("fontName", FONT)
    kwargs.setdefault("textColor", INK)
    return ParagraphStyle(name, **kwargs)


def _section_title(text: str, color=CYAN):
    return Paragraph(
        _inline(text),
        _style("section", fontName=FONT_BOLD, fontSize=15, leading=18, textColor=color, spaceBefore=10, spaceAfter=7, keepWithNext=True),
    )


def _subhead(text: str, color=PURPLE):
    return Paragraph(
        _inline(text),
        _style("subhead", fontName=FONT_BOLD, fontSize=10.5, leading=13, textColor=color, spaceBefore=6, spaceAfter=5, keepWithNext=True),
    )


def _kv_table(rows: list[tuple[Any, Any]], widths=(48 * mm, 130 * mm), font_size=9.2):
    if not rows:
        rows = [("STATUS", "No data returned")]
    left = _style("kv-left", fontName=FONT_BOLD, fontSize=7.9, leading=10.5, textColor=MUTED)
    right = _style("kv-right", fontName=FONT, fontSize=font_size, leading=13, textColor=INK, wordWrap="LTR")
    data = [[Paragraph(_inline(key).upper(), left), Paragraph(_inline(value).replace("\n", "<br/>"), right)] for key, value in rows]
    table = LongTable(data, colWidths=list(widths), hAlign="LEFT", repeatRows=0)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PANEL),
        ("BOX", (0, 0), (-1, -1), 0.45, GRID),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def _paragraph(text: Any, *, size=9.3, leading=13.2, color=INK, bold=False, back=None, border=None, padding=0, space_after=5):
    return Paragraph(
        _inline(text).replace("\n", "<br/>"),
        _style(
            f"p-{size}-{bold}-{bool(back)}",
            fontName=FONT_BOLD if bold else FONT,
            fontSize=size,
            leading=leading,
            textColor=color,
            backColor=back,
            borderColor=border,
            borderWidth=0.45 if border else 0,
            borderPadding=padding,
            spaceAfter=space_after,
        ),
    )


def _bullet_list(items: list[Any], *, size=9.3):
    out = []
    style = _style("bullet", fontName=FONT, fontSize=size, leading=size + 4, textColor=INK, leftIndent=10, firstLineIndent=-6, spaceAfter=4)
    for item in items:
        text = _clean_text(item)
        out.append(Paragraph("- " + _inline(text).replace("\n", "<br/>"), style))
    return out


def _html_to_text(html: str) -> str:
    text = re.sub(r"(?is)<(script|style|noscript|template)[^>]*>.*?</\1>", " ", html or "")
    text = re.sub(r"(?is)<br\s*/?>", "\n", text)
    text = re.sub(r"(?is)</(p|div|section|article|li|tr|h[1-6])\s*>", "\n", text)
    text = re.sub(r"(?is)<li[^>]*>", "- ", text)
    text = re.sub(r"(?is)<[^>]+>", " ", text)
    text = re.sub(r"&nbsp;", " ", text, flags=re.I)
    text = re.sub(r"&amp;", "&", text, flags=re.I)
    text = re.sub(r"&lt;", "<", text, flags=re.I)
    text = re.sub(r"&gt;", ">", text, flags=re.I)
    text = re.sub(r"\n{4,}", "\n\n", text)
    text = re.sub(r"[ \t]+", " ", text)
    return _clean_text(text).strip()


def _structured_email_from_eml(raw: str | None) -> dict[str, Any] | None:
    if not raw:
        return None
    try:
        msg = Parser(policy=policy.default).parsestr(str(raw))
    except Exception:
        return None
    plain = None
    html = None
    attachments: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        if disposition == "attachment" or filename:
            if filename:
                attachments.append(_clean_text(filename))
            continue
        ctype = (part.get_content_type() or "").lower()
        try:
            content = part.get_content()
        except Exception:
            try:
                payload = part.get_payload(decode=True)
                charset = part.get_content_charset() or "utf-8"
                content = (payload or b"").decode(charset, errors="replace")
            except Exception:
                content = ""
        if ctype == "text/html":
            html = str(content)
        elif ctype == "text/plain" and plain is None:
            plain = str(content)
    body = _html_to_text(html) if html else _clean_text(plain or "")
    return {
        "from": _clean_text(msg.get("From") or ""),
        "to": _clean_text(msg.get("To") or ""),
        "cc": _clean_text(msg.get("Cc") or ""),
        "reply_to": _clean_text(msg.get("Reply-To") or ""),
        "date": _clean_text(msg.get("Date") or ""),
        "subject": _clean_text(msg.get("Subject") or "(no subject)"),
        "body": body,
        "attachments": list(dict.fromkeys(attachments)),
    }


def _structured_email(report: dict[str, Any]) -> dict[str, Any]:
    supplied = report.get("provided_email")
    parsed = _structured_email_from_eml(supplied if isinstance(supplied, str) else None)
    if parsed:
        return parsed
    email_obj = report.get("email") if isinstance(report.get("email"), dict) else {}
    return {
        "from": _clean_text(email_obj.get("from") or email_obj.get("sender") or ""),
        "to": _clean_text(email_obj.get("to") or email_obj.get("recipient") or ""),
        "cc": _clean_text(email_obj.get("cc") or ""),
        "reply_to": _clean_text(email_obj.get("reply_to") or ""),
        "date": _clean_text(email_obj.get("date") or ""),
        "subject": _clean_text(email_obj.get("subject") or "(no subject)"),
        "body": _clean_text(email_obj.get("body") or ""),
        "attachments": [],
    }


def _email_story(email_data: dict[str, Any]) -> list[Any]:
    story: list[Any] = [_section_title("Provided Gmail", CYAN)]
    meta = [
        ("From", email_data.get("from")),
        ("To", email_data.get("to")),
        ("Cc", email_data.get("cc")),
        ("Reply-To", email_data.get("reply_to")),
        ("Date", email_data.get("date")),
        ("Subject", email_data.get("subject")),
    ]
    story.append(_kv_table(meta, widths=(40 * mm, 140 * mm), font_size=9.4))
    story.append(Spacer(1, 7))
    story.append(Paragraph("MESSAGE BODY", _style("msghead", fontName=FONT_BOLD, fontSize=8.5, leading=10, textColor=CYAN, spaceAfter=5)))
    body = _clean_text(email_data.get("body") or "").strip()
    if body:
        # Preserve paragraph boundaries, but let ReportLab wrap every line.
        msg_style = _style("msgbody", fontName=FONT, fontSize=9.5, leading=14.2, textColor=INK, backColor=PANEL, borderColor=GRID, borderWidth=0.45, borderPadding=9, spaceAfter=6)
        for block in re.split(r"\n{2,}", body):
            if block.strip():
                story.append(Paragraph(_inline(block.strip()).replace("\n", "<br/>"), msg_style))
    else:
        story.append(_paragraph("No readable message body was found in the supplied message.", color=MUTED))
    attachments = email_data.get("attachments") or []
    if attachments:
        story.append(Spacer(1, 4))
        story.append(Paragraph("ATTACHMENTS", _style("att", fontName=FONT_BOLD, fontSize=8.5, textColor=AMBER, spaceAfter=4)))
        story.extend(_bullet_list(attachments))
    story.append(Spacer(1, 8))
    return story


def _json_lines(value: Any) -> list[str]:
    try:
        rendered = json.dumps(value, indent=2, ensure_ascii=False, default=str)
    except Exception:
        rendered = str(value)
    rendered = _clean_text(rendered)
    return rendered.splitlines() or [""]


def _value_story(value: Any, *, max_table_rows: int = 0) -> list[Any]:
    """Render arbitrary JSON-like engine data without giant cells or clipping."""
    story: list[Any] = []
    if isinstance(value, dict):
        scalar_rows: list[tuple[str, Any]] = []
        complex_items: list[tuple[str, Any]] = []
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                complex_items.append((str(key), child))
            else:
                scalar_rows.append((str(key), child))
        if scalar_rows:
            story.append(_kv_table(scalar_rows, widths=(58 * mm, 122 * mm), font_size=8.8))
        for key, child in complex_items:
            story.append(_subhead(key, PURPLE))
            story.extend(_value_story(child))
    elif isinstance(value, list):
        if not value:
            story.append(_paragraph("No entries returned.", size=8.8, color=MUTED))
        elif all(not isinstance(item, (dict, list)) for item in value):
            story.extend(_bullet_list(value, size=8.9))
        else:
            for index, item in enumerate(value, start=1):
                story.append(_subhead(f"Entry {index}", PURPLE))
                story.extend(_value_story(item))
    else:
        story.append(_paragraph(value, size=8.8))
    return story


def _complete_engine_story(report: dict[str, Any]) -> list[Any]:
    story: list[Any] = [_section_title("Complete engine report", CYAN)]
    story.append(_paragraph(
        "Every returned analysis field is reproduced below. Raw EML bytes are intentionally excluded; the user-visible Gmail is reproduced in structured form at the beginning.",
        size=9,
        leading=13,
        color=MUTED,
    ))
    for key, value in report.items():
        if key == "provided_email":
            continue
        story.append(_subhead(str(key).replace("_", " ").title(), CYAN if key in {"security_analysis", "threat_intelligence", "ai_assessment"} else PURPLE))
        story.extend(_value_story(value))
        story.append(Spacer(1, 4))
    return story


def build_report_pdf(report: dict[str, Any]) -> bytes:
    buf = BytesIO()
    doc = DarkDoc(buf)

    title = _style("title", fontName=FONT_BOLD, fontSize=25, leading=29, textColor=INK, spaceAfter=6)
    subtitle = _style("subtitle", fontName=FONT, fontSize=9.5, leading=13, textColor=MUTED, spaceAfter=9)
    body = _style("body", fontName=FONT, fontSize=9.3, leading=13.4, textColor=INK, spaceAfter=5)

    score = int(max(0, min(100, float(report.get("risk_score") or 0))))
    verdict = _clean_text(report.get("verdict") or "UNKNOWN").upper()
    confidence = report.get("analysis_confidence") or {}
    confidence_score = confidence.get("score") if isinstance(confidence, dict) else None
    mode = _clean_text(report.get("analysis_mode") or "full")
    tone = _tone(verdict)

    story: list[Any] = []
    story.append(Paragraph("TRINETRA", _style("brand", fontName=FONT_BOLD, fontSize=9, leading=11, textColor=CYAN, spaceAfter=3)))
    story.append(Paragraph("CASE ID: " + _inline(report.get("case_id") or "UNKNOWN"), _style("case", fontName=FONT_BOLD, fontSize=11, leading=13, textColor=CYAN, spaceAfter=7)))

    # User-visible Gmail first, not the raw MIME source.
    story.extend(_email_story(_structured_email(report)))

    story.append(Paragraph("Email Threat Assessment", title))
    story.append(Paragraph(_inline((report.get("email") or {}).get("subject") or (report.get("source_file") or {}).get("filename") or "Analyzed email message"), subtitle))

    # Separate risk and confidence boxes, matching the website layout.
    risk_box = Table([
        [
            Paragraph("RISK SCORE", _style("risklabel", fontName=FONT_MONO_BOLD, fontSize=8, leading=10, textColor=MUTED, spaceAfter=3)),
        ],
        [
            Paragraph(f"<font size='40'><b>{score}</b></font> <font size='11'>/ 100</font>", _style("risknum", fontName=FONT_BOLD, fontSize=11, leading=36, textColor=INK, spaceAfter=2)),
        ],
        [
            Paragraph(_inline(f"Verdict: {verdict}"), _style("riskverdict", fontName=FONT_BOLD, fontSize=10.5, leading=13, textColor=tone, spaceAfter=3)),
        ],
        [
            Paragraph("Risk score measures the severity of detected security and threat signals. Higher values indicate stronger evidence of risk.", body),
        ],
    ], colWidths=[75 * mm])
    risk_box.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), PANEL),
        ("BOX", (0,0), (-1,-1), 0.7, tone),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (-1,-1), 10),
        ("RIGHTPADDING", (0,0), (-1,-1), 10),
        ("TOPPADDING", (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
    ]))

    confidence_text = (
        "Confidence tells you how strongly the available evidence supports the risk decision. It is not the probability that the email is safe or malicious. It reflects evidence coverage, agreement between independent signals, provider coverage, authentication consistency, grounding quality, verdict stability, and AI availability."
    )
    if mode == "subhom_only":
        confidence_text += " Ollama AI assessment failed after the configured attempts, so the independent AI signal could not be incorporated. Confidence is intentionally lower. Re-upload the email for a more precise result."

    conf_score_text = "-" if confidence_score is None else f"{confidence_score}%"
    confidence_box = Table([
        [Paragraph("ANALYSIS CONFIDENCE", _style("conflabel", fontName=FONT_MONO_BOLD, fontSize=8, leading=10, textColor=MUTED, spaceAfter=3))],
        [Paragraph(f"<font size='31'><b>{_inline(conf_score_text)}</b></font>", _style("confnum", fontName=FONT_BOLD, fontSize=9, leading=31, textColor=INK, spaceAfter=2))],
        [Paragraph(_inline(confidence.get("label") or "Not available").upper(), _style("conflab", fontName=FONT_MONO_BOLD, fontSize=8, leading=10, textColor=CYAN, spaceAfter=8))],
        [Paragraph("WHY THIS CONFIDENCE SCORE?", _style("why", fontName=FONT_BOLD, fontSize=10, leading=12, textColor=CYAN, spaceAfter=5))],
        [Paragraph(_inline(confidence_text), _style("confbody", fontName=FONT_BOLD, fontSize=10.8, leading=15.5, textColor=INK, spaceAfter=2))],
    ], colWidths=[105 * mm])
    confidence_box.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), PANEL),
        ("BOX", (0,0), (-1,-1), 0.7, PURPLE if mode == "full" else AMBER),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (-1,-1), 10),
        ("RIGHTPADDING", (0,0), (-1,-1), 10),
        ("TOPPADDING", (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
    ]))

    hero = Table([[risk_box, confidence_box]], colWidths=[77 * mm, 105 * mm], hAlign="LEFT")
    hero.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (-1,-1), 0),
        ("RIGHTPADDING", (0,0), (-1,-1), 5),
        ("TOPPADDING", (0,0), (-1,-1), 0),
        ("BOTTOMPADDING", (0,0), (-1,-1), 0),
    ]))
    story.append(hero)
    story.append(Spacer(1, 9))

    if mode == "subhom_only":
        story.append(KeepTogether([
            _paragraph(
                "AI ASSESSMENT UNAVAILABLE - Ollama failed after the configured attempts. TRINETRA still calculated the risk score from Subhom's security and threat signals. Confidence is intentionally lower because the independent AI signal is missing. Re-upload the email for a more precise report.",
                size=10,
                leading=14,
                color=AMBER,
                bold=True,
                back=colors.HexColor("#2b2110"),
                border=AMBER,
                padding=8,
                space_after=0,
            ),
            Spacer(1, 9),
        ]))

    story.append(_section_title("Confidence factors", CYAN))
    factor_defs = {
        "evidence_coverage": "How much of the expected email and security evidence was available.",
        "signal_agreement": "Whether independent signals support the same conclusion rather than contradicting each other.",
        "provider_coverage": "How much useful external reputation or enrichment evidence was available for indicators.",
        "authentication_consistency": "How consistently SPF, DKIM, DMARC and related authentication evidence agree.",
        "grounding_quality": "How well the AI assessment, when available, is tied back to collected evidence.",
        "verdict_stability": "How far the risk score is from a verdict boundary; near-boundary scores are less stable.",
        "ai_availability": "Whether the independent Ollama assessment was successfully incorporated.",
    }
    factor_rows = [("Factor", "Value", "Meaning")]
    if isinstance(confidence, dict):
        for key, value in (confidence.get("factors") or {}).items():
            factor_rows.append((str(key).replace("_", " ").title(), f"{value}%", factor_defs.get(key, "Evidence quality factor used by the confidence model.")))
    else:
        factor_rows.append(("Unavailable", "-", "The analysis confidence object was not returned."))
    factor_data = [[
        Paragraph(_inline(a).upper(), _style("fh1", fontName=FONT_BOLD, fontSize=7.5, leading=9.5, textColor=CYAN)),
        Paragraph(_inline(b).upper(), _style("fh2", fontName=FONT_BOLD, fontSize=7.5, leading=9.5, textColor=CYAN)),
        Paragraph(_inline(c), _style("fh3", fontName=FONT, fontSize=8.4, leading=11.5, textColor=INK)),
    ] for a,b,c in factor_rows]
    factor_table = LongTable(factor_data, colWidths=[45*mm, 23*mm, 112*mm], repeatRows=1)
    factor_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), PANEL),
        ("GRID", (0,0), (-1,-1), 0.25, GRID),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("TOPPADDING", (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
    ]))
    story.append(factor_table)

    if isinstance(confidence, dict) and confidence.get("rationale"):
        story.append(Spacer(1, 6))
        story.append(_subhead("Confidence rationale", CYAN))
        story.extend(_bullet_list(confidence.get("rationale") or [], size=9.2))

    # Core sections - rendered independently so no large rows merge together.
    story.append(_section_title("Security & threat signals", CYAN))
    security = report.get("security_analysis") or {}
    threat = report.get("threat_intelligence") or {}
    iocs = report.get("iocs") or {}
    if security:
        story.append(_subhead("Security analysis", PURPLE))
        story.extend(_value_story(security))
    if threat:
        story.append(_subhead("Threat intelligence", PURPLE))
        story.extend(_value_story(threat))
    if iocs:
        story.append(_subhead("IOC inventory", PURPLE))
        story.extend(_value_story(iocs))

    story.append(_section_title("AI assessment", CYAN))
    ai = report.get("ai_assessment") or {}
    if mode == "subhom_only":
        story.append(_paragraph("Ollama assessment unavailable. The missing AI signal is not treated as a zero-risk result.", size=9.6, leading=14, color=AMBER, bold=True, back=colors.HexColor("#2b2110"), border=AMBER, padding=8))
    elif ai:
        story.extend(_value_story(ai))
    else:
        story.append(_paragraph("No AI assessment payload was returned.", color=MUTED))

    story.append(_section_title("Why this verdict was returned", CYAN))
    reasons = report.get("reasons") or []
    story.extend(_bullet_list(reasons, size=9.3) if reasons else [_paragraph("No explicit detection reasons were returned by the analysis engine.", color=MUTED)])

    story.append(_section_title("Correlations", CYAN))
    correlations = report.get("correlations") or []
    story.extend(_bullet_list(correlations, size=9.2) if correlations else [_paragraph("No cross-signal correlations were returned.", color=MUTED)])

    story.append(_section_title("Triggered rules", CYAN))
    rules = report.get("triggered_rules") or []
    story.extend(_value_story(rules) if rules else [_paragraph("No triggered rules were returned.", color=MUTED)])

    story.append(_section_title("Score breakdown", CYAN))
    breakdown = report.get("score_breakdown") or {}
    story.extend(_value_story(breakdown) if breakdown else [_paragraph("No score breakdown was returned.", color=MUTED)])

    # Keep every returned field available to the user, in readable chunks.
    story.extend(_complete_engine_story(report))

    story.append(_section_title("Report metadata", CYAN))
    model_info = report.get("model_info") if isinstance(report.get("model_info"), dict) else {}
    story.append(_kv_table([
        ("Case ID", report.get("case_id") or ""),
        ("Analysis mode", mode),
        ("Analyzed at", report.get("analyzed_at") or ""),
        ("Processing time", report.get("processing_time_ms") or ""),
        ("Model", model_info.get("model") or ""),
    ], widths=(45 * mm, 135 * mm), font_size=9.1))

    doc.build(story)
    return buf.getvalue()
