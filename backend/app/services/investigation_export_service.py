from __future__ import annotations

from datetime import datetime
from html import escape
from pathlib import Path
import re
from typing import Any

from backend.app.bootstrap import ensure_project_root_on_path
from backend.app.security import ensure_within_directory, validate_export_name

ensure_project_root_on_path()

from log_manager import LOG_DIR  # noqa: E402

_SECTION_SPECS = [
    ("Quick Verdict", "verdictRows"),
    ("Network Path", "networkRows"),
    ("Transport & Protocol", "transportRows"),
    ("Process & Host Correlation", "processRows"),
    ("Flow & Session", "flowRows"),
    ("Stream Intelligence Summary", "streamRows"),
    ("Enrichment", "enrichmentRows"),
    ("Raw Metadata", "rawRows"),
]
_PATH_PATTERN = re.compile(r"(?i)(?:[a-z]:[\\/][^\s<>|]+|\\\\[^\s<>|]+)")


def _sanitize_text(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""

    def replace_path(match: re.Match[str]) -> str:
        raw = match.group(0)
        normalized = raw.replace("\\", "/").rstrip("/")
        name = Path(normalized).name or "redacted"
        return f"[redacted-path]/{name}"

    return _PATH_PATTERN.sub(replace_path, text)


def _sanitize_row(row: dict[str, Any]) -> dict[str, str]:
    return {
        "label": _sanitize_text(row.get("label")),
        "value": _sanitize_text(row.get("value")),
    }


def _sanitize_item(item: dict[str, Any]) -> dict[str, Any]:
    sections = []
    for section in item.get("sections") or []:
        title = _sanitize_text(section.get("title"))
        body = _sanitize_text(section.get("body"))
        if title or body:
            sections.append({"title": title or "Section", "body": body or "-"})
    return {
        "title": _sanitize_text(item.get("title")) or "Insight",
        "body": _sanitize_text(item.get("body")) or "-",
        "sections": sections,
    }


def _sanitize_group(group: dict[str, Any]) -> dict[str, Any]:
    items = [_sanitize_item(item) for item in (group.get("items") or []) if _sanitize_text(item.get("title")) or _sanitize_text(item.get("body"))]
    return {
        "title": _sanitize_text(group.get("title")) or "Section",
        "items": items,
    }


def _sanitize_payload_tab(tab: dict[str, Any]) -> dict[str, str]:
    return {
        "label": _sanitize_text(tab.get("label")) or "Payload",
        "value": _sanitize_text(tab.get("value")) or "-",
    }


def _render_rows_section(title: str, rows: list[dict[str, str]]) -> str:
    visible = [row for row in rows if row.get("label") and row.get("value") and row["value"] != "-"]
    if not visible:
        return ""
    items = "".join(
        f"<div class='metric'><dt>{escape(row['label'])}</dt><dd>{escape(row['value'])}</dd></div>"
        for row in visible
    )
    return f"<section class='report-section'><h2>{escape(title)}</h2><dl class='metric-grid'>{items}</dl></section>"


def _render_activity_groups(title: str, groups: list[dict[str, Any]]) -> str:
    visible = [group for group in groups if group.get("items")]
    if not visible:
        return ""
    group_html = []
    for group in visible:
        items_html = []
        for item in group["items"]:
            section_html = "".join(
                f"<div class='nested-item'><strong>{escape(section['title'])}</strong><p>{escape(section['body'])}</p></div>"
                for section in item.get("sections") or []
            )
            items_html.append(
                "<article class='activity-item'>"
                f"<strong>{escape(item['title'])}</strong>"
                f"<p>{escape(item['body'])}</p>"
                f"{section_html}"
                "</article>"
            )
        group_html.append(
            "<div class='report-subsection'>"
            f"<h3>{escape(group['title'])}</h3>"
            f"{''.join(items_html)}"
            "</div>"
        )
    return f"<section class='report-section'><h2>{escape(title)}</h2>{''.join(group_html)}</section>"


def _render_application_groups(groups: list[dict[str, Any]]) -> str:
    visible = []
    for group in groups:
        rows = [_sanitize_row(row) for row in (group.get("rows") or [])]
        rows = [row for row in rows if row.get("label") and row.get("value") and row["value"] != "-"]
        if rows:
            visible.append({"title": _sanitize_text(group.get("title")) or "Decode", "rows": rows})
    if not visible:
        return ""
    html_parts = []
    for group in visible:
        items = "".join(
            f"<div class='metric'><dt>{escape(row['label'])}</dt><dd>{escape(row['value'])}</dd></div>"
            for row in group["rows"]
        )
        html_parts.append(f"<div class='report-subsection'><h3>{escape(group['title'])}</h3><dl class='metric-grid'>{items}</dl></div>")
    return f"<section class='report-section'><h2>Application Decode</h2>{''.join(html_parts)}</section>"


def _render_payload(payload: dict[str, Any], rows: list[dict[str, str]]) -> str:
    sections = []
    row_html = _render_rows_section("Payload", rows)
    if row_html:
        sections.append(row_html)
    tabs = [_sanitize_payload_tab(tab) for tab in (payload.get("tabs") or [])]
    tabs = [tab for tab in tabs if tab.get("value") and tab["value"] != "-"]
    if tabs:
        tab_html = "".join(
            "<details class='payload-tab'>"
            f"<summary>{escape(tab['label'])}</summary>"
            f"<pre>{escape(tab['value'])}</pre>"
            "</details>"
            for tab in tabs
        )
        sections.append(f"<section class='report-section'><h2>Payload Views</h2>{tab_html}</section>")
    return "".join(sections)


def _render_risk(panel: dict[str, Any]) -> str:
    narrative = _sanitize_text(panel.get("narrative"))
    rows = [_sanitize_row(row) for row in (panel.get("rows") or [])]
    groups = [_sanitize_group(group) for group in (panel.get("groups") or [])]
    if not narrative and not any(row.get("value") and row["value"] != "-" for row in rows) and not any(group.get("items") for group in groups):
        return ""
    parts = ["<section class='report-section'><h2>Risk &amp; Explanation</h2>"]
    if narrative:
        parts.append(f"<p class='narrative'>{escape(narrative)}</p>")
    row_html = _render_rows_section("Risk Details", rows)
    if row_html:
        parts.append(row_html.replace("<section class='report-section'>", "<div class='embedded-section'>", 1).replace("</section>", "</div>", 1))
    if any(group.get("items") for group in groups):
        parts.append(_render_activity_groups("Risk Panels", groups).replace("<section class='report-section'>", "<div class='embedded-section'>", 1).replace("</section>", "</div>", 1))
    parts.append("</section>")
    return "".join(parts)


def _render_cards(cards: list[dict[str, Any]]) -> str:
    visible = []
    for card in cards:
        label = _sanitize_text(card.get("label"))
        value = _sanitize_text(card.get("value"))
        hint = _sanitize_text(card.get("hint"))
        if label or value or hint:
            visible.append({"label": label or "Summary", "value": value or "-", "hint": hint})
    if not visible:
        return ""
    items = "".join(
        "<article class='summary-card'>"
        f"<p class='eyebrow'>{escape(card['label'])}</p>"
        f"<strong>{escape(card['value'])}</strong>"
        f"<p>{escape(card['hint'])}</p>"
        "</article>"
        for card in visible
    )
    return f"<section class='report-section'><h2>Analyst Summary</h2><div class='summary-grid'>{items}</div></section>"


def _render_tabs(tabs: list[dict[str, Any]]) -> str:
    visible = [_sanitize_text(tab.get("label")) for tab in tabs if _sanitize_text(tab.get("label"))]
    if not visible:
        return ""
    chips = "".join(f"<span class='chip'>{escape(label)}</span>" for label in visible)
    return f"<section class='report-section'><h2>Investigation Views</h2><div class='chip-row'>{chips}</div></section>"


class InvestigationExportService:
    def export_report(self, payload: dict[str, Any]) -> dict[str, Any]:
        subject_kind = _sanitize_text(payload.get("kind") or payload.get("subject_kind")).lower()
        subject_id = _sanitize_text(payload.get("id") or payload.get("subject_id"))
        report_format = _sanitize_text(payload.get("format")).lower() or "html"
        model = payload.get("model") or {}
        if subject_kind not in {"packet", "alert"}:
            raise ValueError("Unsupported investigation kind")
        if not subject_id:
            raise ValueError("Missing investigation subject id")
        if report_format != "html":
            raise ValueError("Unsupported investigation export format")
        headline = _sanitize_text(payload.get("headline") or model.get("headline"))
        if not headline:
            raise ValueError("Missing investigation headline")

        analyst_cards = list(payload.get("analyst_cards") or payload.get("analystCards") or model.get("analystCards") or [])
        title = f"{subject_kind.title()} investigation | {headline}"
        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        filename = validate_export_name(f"investigation_{subject_kind}_{subject_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}", ".html")
        path = Path(ensure_within_directory(LOG_DIR, filename))

        html = self._render_html(
            title=title,
            generated_at=generated_at,
            subject_kind=subject_kind,
            subject_id=subject_id,
            headline=headline,
            summary_text=_sanitize_text(payload.get("summary_text") or payload.get("summaryText") or model.get("summaryText")),
            interpreted_summary=_sanitize_text(payload.get("interpreted_summary") or payload.get("interpretedSummary") or model.get("interpretedSummary")),
            analyst_cards=analyst_cards,
            model=model,
        )
        path.write_text(html, encoding="utf-8")
        return {"ok": True, "format": "html", "path": filename, "kind": subject_kind, "id": subject_id}

    def _render_html(
        self,
        *,
        title: str,
        generated_at: str,
        subject_kind: str,
        subject_id: str,
        headline: str,
        summary_text: str,
        interpreted_summary: str,
        analyst_cards: list[dict[str, Any]],
        model: dict[str, Any],
    ) -> str:
        sections: list[str] = []
        sections.append(_render_cards(analyst_cards))
        sections.append(_render_tabs(list(model.get("investigationTabs") or [])))
        if summary_text or interpreted_summary:
            narrative_html = f"<p class='narrative'>{escape(summary_text)}</p>" if summary_text else ""
            interpreted_html = f"<p>{escape(interpreted_summary)}</p>" if interpreted_summary and interpreted_summary != summary_text else ""
            sections.append(
                "<section class='report-section'>"
                "<h2>Inspection Narrative</h2>"
                f"{narrative_html}"
                f"{interpreted_html}"
                "</section>"
            )
        for title_label, key in _SECTION_SPECS:
            rows = [_sanitize_row(row) for row in (model.get(key) or [])]
            sections.append(_render_rows_section(title_label, rows))
        sections.append(_render_activity_groups("Stream Intelligence", [_sanitize_group(group) for group in (model.get("streamGroups") or [])]))
        sections.append(_render_activity_groups("Behavior Correlation", [_sanitize_group(group) for group in (model.get("correlationGroups") or [])]))
        sections.append(_render_activity_groups("Related Activity", [_sanitize_group(group) for group in (model.get("relatedGroups") or [])]))
        sections.append(_render_application_groups(list(model.get("applicationGroups") or [])))
        sections.append(_render_payload(model.get("payload") or {}, [_sanitize_row(row) for row in (model.get("payloadRows") or [])]))
        sections.append(_render_risk(model.get("riskExplanation") or {}))
        body = "".join(section for section in sections if section)
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{escape(title)}</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #08111f;
      --panel: #101d31;
      --panel-strong: #162742;
      --border: rgba(255,255,255,0.12);
      --text: #eef4ff;
      --muted: #a6b6d3;
      --accent: #7cb7ff;
      --success: #59f0c2;
      --warning: #ffd36b;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; padding: 32px; font-family: Segoe UI, Arial, sans-serif; background: radial-gradient(circle at top, rgba(124,183,255,0.14), transparent 30%), var(--bg); color: var(--text); }}
    main {{ max-width: 1180px; margin: 0 auto; display: grid; gap: 18px; }}
    .hero, .report-section, .embedded-section {{ background: var(--panel); border: 1px solid var(--border); border-radius: 20px; padding: 20px; }}
    .hero {{ background: linear-gradient(180deg, rgba(124,183,255,0.09), rgba(255,255,255,0.02)), var(--panel-strong); }}
    h1, h2, h3 {{ margin: 0 0 12px; }}
    h1 {{ font-size: 1.9rem; }}
    h2 {{ font-size: 1.05rem; }}
    h3 {{ font-size: 0.98rem; }}
    p {{ margin: 0; color: var(--muted); line-height: 1.55; }}
    .hero-meta, .chip-row {{ display: flex; flex-wrap: wrap; gap: 10px; margin-top: 14px; }}
    .chip {{ display: inline-flex; align-items: center; padding: 6px 10px; border-radius: 999px; background: rgba(124,183,255,0.1); color: var(--text); font-size: 0.88rem; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 12px; }}
    .summary-card {{ border: 1px solid var(--border); border-radius: 16px; padding: 14px; background: rgba(255,255,255,0.03); }}
    .summary-card strong {{ display: block; margin: 8px 0; font-size: 1.02rem; line-height: 1.4; }}
    .eyebrow {{ margin-bottom: 6px; color: var(--accent); text-transform: uppercase; letter-spacing: 0.08em; font-size: 0.72rem; }}
    .metric-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin: 0; }}
    .metric {{ border: 1px solid rgba(255,255,255,0.06); border-radius: 14px; padding: 12px; background: rgba(255,255,255,0.02); }}
    .metric dt {{ color: var(--muted); font-size: 0.82rem; margin-bottom: 6px; }}
    .metric dd {{ margin: 0; line-height: 1.5; word-break: break-word; }}
    .report-subsection + .report-subsection {{ margin-top: 14px; }}
    .activity-item {{ border: 1px solid rgba(255,255,255,0.06); border-radius: 14px; padding: 12px; background: rgba(255,255,255,0.02); }}
    .activity-item + .activity-item {{ margin-top: 10px; }}
    .activity-item strong {{ display: block; margin-bottom: 8px; }}
    .nested-item {{ margin-top: 10px; padding-top: 10px; border-top: 1px solid rgba(255,255,255,0.06); }}
    .nested-item p {{ margin-top: 4px; }}
    .payload-tab + .payload-tab {{ margin-top: 10px; }}
    .payload-tab summary {{ cursor: pointer; color: var(--warning); }}
    pre {{ margin: 10px 0 0; padding: 12px; border-radius: 14px; background: rgba(0,0,0,0.24); color: var(--text); white-space: pre-wrap; word-break: break-word; }}
    .narrative {{ color: var(--text); }}
    @media (max-width: 760px) {{
      body {{ padding: 16px; }}
      .metric-grid, .summary-grid {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <p class="eyebrow">{escape(subject_kind.title())} Investigation Export</p>
      <h1>{escape(headline)}</h1>
      <p class="narrative">{escape(interpreted_summary or summary_text or "Analyst-readable investigation export generated from the current inspection model.")}</p>
      <div class="hero-meta">
        <span class="chip">Subject ID: {escape(subject_id)}</span>
        <span class="chip">Generated: {escape(generated_at)}</span>
        <span class="chip">Format: HTML</span>
      </div>
    </section>
    {body}
  </main>
</body>
</html>"""


__all__ = ["InvestigationExportService"]
