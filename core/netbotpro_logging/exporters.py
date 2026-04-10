from __future__ import annotations

import html
import json
import os
import sys
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path

import pandas as pd

from .config import FPDF, LOG_DIR, get_conn, is_persist_enabled
from .privacy import alert_rows_to_df, packet_rows_to_df, traceroute_rows_to_df


def _svg_bar_chart(labels, values, width=520, height=180):
    if not labels or not values:
        return ""
    vmax = max(values) if values else 1
    vmax = vmax if vmax > 0 else 1
    pad = 28
    chart_w = max(10, width - pad * 2)
    chart_h = max(10, height - pad * 2)
    bar_w = chart_w / max(1, len(labels))
    parts = [f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img">']
    parts.append(f'<line x1="{pad}" y1="{height - pad}" x2="{width - pad}" y2="{height - pad}" stroke="#334155"/>')
    for i, (lab, val) in enumerate(zip(labels, values)):
        x = pad + i * bar_w + 6
        bw = max(6, bar_w - 12)
        bh = (float(val) / float(vmax)) * chart_h
        y = (height - pad) - bh
        parts.append(f'<rect x="{x:.2f}" y="{y:.2f}" width="{bw:.2f}" height="{bh:.2f}" rx="4" fill="#22c55e" opacity="0.9"><title>{html.escape(str(lab))}: {val}</title></rect>')
        lab_s = str(lab)
        if len(lab_s) > 10:
            lab_s = lab_s[:10] + "..."
        parts.append(f'<text x="{x + bw / 2:.2f}" y="{height - 10}" text-anchor="middle" font-size="10" fill="#94a3b8">{html.escape(lab_s)}</text>')
    parts.append("</svg>")
    return "".join(parts)


def _write_full_html(save_path: str, df_packets: pd.DataFrame, df_alerts: pd.DataFrame, df_tr: pd.DataFrame, source: str = "session") -> None:
    Path(save_path).parent.mkdir(parents=True, exist_ok=True)
    p_count = int(len(df_packets)) if df_packets is not None else 0
    a_count = int(len(df_alerts)) if df_alerts is not None else 0
    proto_counts = df_packets["proto"].fillna("OTHER").astype(str).str.upper().value_counts().head(10).to_dict() if df_packets is not None and not df_packets.empty and "proto" in df_packets.columns else {}
    top_src = df_packets["src"].fillna("-").astype(str).value_counts().head(8).to_dict() if df_packets is not None and not df_packets.empty and "src" in df_packets.columns else {}
    top_dst = df_packets["dst"].fillna("-").astype(str).value_counts().head(8).to_dict() if df_packets is not None and not df_packets.empty and "dst" in df_packets.columns else {}
    attack_counts = df_alerts["attack"].fillna("Alert").astype(str).value_counts().head(10).to_dict() if df_alerts is not None and not df_alerts.empty and "attack" in df_alerts.columns else {}
    now = datetime.now().isoformat(timespec="seconds")
    css = ":root{--bg:#0b1220;--panel:#0f172a;--muted:#94a3b8;--fg:#e2e8f0;--line:#1f2937;--accent:#22c55e;--danger:#ef4444;}body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial;background:var(--bg);color:var(--fg)}.wrap{max-width:1180px;margin:0 auto;padding:18px}.head{display:flex;align-items:flex-end;justify-content:space-between;gap:12px;flex-wrap:wrap}h1{margin:0;font-size:22px}.meta{color:var(--muted);font-size:12px}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:14px}.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:12px}.card .k{color:var(--muted);font-size:12px}.card .v{font-size:20px;font-weight:700;margin-top:6px}.charts{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px}.sec{margin-top:14px}.sec h2{font-size:15px;margin:0 0 8px 0;color:#cbd5e1}table{width:100%;border-collapse:collapse;font-size:12px}th,td{border-bottom:1px solid var(--line);padding:8px;vertical-align:top}th{position:sticky;top:0;background:rgba(15,23,42,.98);text-align:left;color:#cbd5e1}details{background:rgba(148,163,184,.04);border:1px solid var(--line);border-radius:12px;padding:10px;margin:8px 0}details>summary{cursor:pointer;color:#e2e8f0;font-weight:600}pre{white-space:pre-wrap;word-break:break-word;background:rgba(2,6,23,.5);border:1px solid var(--line);border-radius:10px;padding:10px;overflow:auto}@media (max-width:980px){.grid{grid-template-columns:1fr 1fr}.charts{grid-template-columns:1fr}}@media (max-width:560px){.grid{grid-template-columns:1fr}}"
    parts = ['<!doctype html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>NetBotPRO Report</title>', f"<style>{css}</style></head><body><div class=\"wrap\">"]
    parts.append(f'<div class="head"><div><h1>NetBotPRO - Full Report</h1><div class="meta">Generated: {html.escape(now)} | Source: {html.escape(source)}</div></div><div class="meta">{html.escape(os.path.basename(save_path))}</div></div>')
    parts.append('<div class="grid">')
    parts.append(f'<div class="card"><div class="k">Packets</div><div class="v">{p_count}</div></div>')
    parts.append(f'<div class="card"><div class="k">Alerts</div><div class="v" style="color:var(--danger)">{a_count}</div></div>')
    parts.append(f'<div class="card"><div class="k">Top proto</div><div class="v">{html.escape(next(iter(proto_counts.keys()), "-"))}</div></div>')
    parts.append(f'<div class="card"><div class="k">Top src / dst</div><div class="v" style="font-size:14px">{html.escape(next(iter(top_src.keys()), "-"))} -> {html.escape(next(iter(top_dst.keys()), "-"))}</div></div>')
    parts.append("</div>")
    parts.append('<div class="charts">')
    parts.append('<div class="card"><div class="k">Protocol distribution</div>' + (_svg_bar_chart(list(proto_counts.keys()), list(proto_counts.values())) or '<div class="meta">No data</div>') + "</div>")
    parts.append('<div class="card"><div class="k">Alerts by type</div>' + (_svg_bar_chart(list(attack_counts.keys()), [int(v) for v in attack_counts.values()]) or '<div class="meta">No alerts</div>') + "</div>")
    parts.append("</div>")
    if df_alerts is not None and not df_alerts.empty:
        cols = [c for c in ["ts", "src", "dst", "proto", "dport", "attack", "score", "engine"] if c in df_alerts.columns]
        parts.append('<div class="sec"><h2>Alerts</h2>' + df_alerts[cols].to_html(index=False, escape=True) + "</div>")
    if df_packets is not None and not df_packets.empty:
        main_cols = [c for c in ["ts", "src", "dst", "proto", "sport", "dport", "length", "process_name", "l7", "country", "org", "sni", "alpn", "ja3", "ja4", "summary"] if c in df_packets.columns]
        parts.append('<div class="sec"><h2>Packets</h2>' + df_packets[main_cols].to_html(index=False, escape=True) + "</div>")
    parts.append('<div class="meta" style="margin-top:18px">Generated by NetBotPRO logging exporters</div></div></body></html>')
    Path(save_path).write_text("".join(parts), encoding="utf-8")


def export_session_zip(save_path: str, packet_rows: list[dict] | None = None, alert_rows: list[dict] | None = None, traceroute_rows: list[dict] | None = None, include_html: bool = True) -> str:
    df_p = packet_rows_to_df(packet_rows or [])
    df_a = alert_rows_to_df(alert_rows or [])
    df_t = traceroute_rows_to_df(traceroute_rows or [])
    Path(save_path).parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        p_csv = Path(td) / "packets.csv"
        a_csv = Path(td) / "alerts.csv"
        t_csv = Path(td) / "traceroute.csv"
        df_p.to_csv(p_csv, index=False)
        df_a.to_csv(a_csv, index=False)
        df_t.to_csv(t_csv, index=False)
        html_path = Path(td) / "report.html"
        if include_html:
            _write_full_html(str(html_path), df_p, df_a, df_t, source="session")
        meta_path = Path(td) / "meta.json"
        meta_path.write_text(json.dumps({"generated_at": datetime.utcnow().isoformat() + "Z", "source": "session", "counts": {"packets": int(len(df_p)), "alerts": int(len(df_a)), "traceroute": int(len(df_t))}}, ensure_ascii=False, indent=2), encoding="utf-8")
        with zipfile.ZipFile(save_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(p_csv, arcname="packets.csv")
            zf.write(a_csv, arcname="alerts.csv")
            zf.write(t_csv, arcname="traceroute.csv")
            if include_html and html_path.exists():
                zf.write(html_path, arcname="report.html")
            zf.write(meta_path, arcname="meta.json")
    return save_path


def export_all_history_zip(save_path: str) -> str:
    if not is_persist_enabled():
        return ""
    conn = get_conn()
    if conn is None:
        return ""
    with tempfile.TemporaryDirectory() as td:
        df_p = pd.read_sql_query("SELECT ts, src, dst, proto, sport, dport, length, country, org, summary, is_alert FROM packets ORDER BY id", conn)
        df_a = pd.read_sql_query("SELECT ts, src, dst, proto, attack_type as attack, score, detail FROM alerts ORDER BY id", conn)
        p_csv = Path(td) / "packets_all.csv"
        a_csv = Path(td) / "alerts_all.csv"
        html_path = Path(td) / "report_all.html"
        meta_path = Path(td) / "meta.json"
        df_p.to_csv(p_csv, index=False)
        df_a.to_csv(a_csv, index=False)
        _write_full_html(str(html_path), df_p, df_a, pd.DataFrame(), source="db_all")
        meta_path.write_text(json.dumps({"generated_at": datetime.utcnow().isoformat() + "Z", "source": "db_all", "counts": {"packets": int(len(df_p)), "alerts": int(len(df_a))}}, ensure_ascii=False, indent=2), encoding="utf-8")
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(save_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(p_csv, arcname="packets_all.csv")
            zf.write(a_csv, arcname="alerts_all.csv")
            zf.write(html_path, arcname="report_all.html")
            zf.write(meta_path, arcname="meta.json")
    return save_path


def export_packets_csv(save_path: str = "", packet_rows: list[dict] | None = None) -> str:
    path = save_path or str(LOG_DIR / f"packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    if packet_rows is not None:
        packet_rows_to_df(packet_rows).to_csv(path, index=False)
        return path
    if not is_persist_enabled():
        return ""
    conn = get_conn()
    if conn is None:
        return ""
    df = pd.read_sql_query("SELECT id, ts, src, dst, proto, sport, dport, length, country, org, summary, is_alert FROM packets ORDER BY id", conn)
    if df.empty:
        return ""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)
    return path


def export_packets_excel(save_path: str = "", packet_rows: list[dict] | None = None) -> str:
    path = save_path or str(LOG_DIR / f"packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx")
    if packet_rows is not None:
        packet_rows_to_df(packet_rows).to_excel(path, index=False)
        return path
    if not is_persist_enabled():
        return ""
    conn = get_conn()
    if conn is None:
        return ""
    df = pd.read_sql_query("SELECT id, ts, src, dst, proto, sport, dport, length, country, org, summary, is_alert FROM packets ORDER BY id", conn)
    if df.empty:
        return ""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    df.to_excel(path, index=False)
    return path


def export_alerts_pdf(save_path: str = "", alert_rows: list[dict] | None = None) -> str:
    if FPDF is None:
        return ""
    path = save_path or str(LOG_DIR / f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
    df = alert_rows_to_df(alert_rows or []) if alert_rows is not None else None
    if df is None:
        if not is_persist_enabled():
            return ""
        conn = get_conn()
        if conn is None:
            return ""
        df = pd.read_sql_query("SELECT id, ts, src, dst, proto, attack_type as attack, score, detail FROM alerts ORDER BY id", conn)
    if df.empty:
        return ""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    pdf = FPDF(format="A4")
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=12)
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "NetBotPRO - Alerts Report", ln=True)
    pdf.set_font("Arial", "", 10)
    pdf.cell(0, 6, f"Generated: {datetime.now().isoformat(timespec='seconds')}", ln=True)
    pdf.ln(3)
    cols = ["ts", "src", "dst", "proto", "attack", "score"]
    col_w = [28, 36, 36, 12, 62, 12]
    pdf.set_font("Arial", "B", 9)
    for i, col in enumerate(cols):
        pdf.cell(col_w[i], 7, col.upper(), border=1)
    pdf.ln()
    pdf.set_font("Arial", "", 8)
    for _, row in df.iterrows():
        vals = [str(row.get(col, "")) for col in cols]
        vals[4] = (vals[4][:45] + "...") if len(vals[4]) > 48 else vals[4]
        for i, value in enumerate(vals):
            pdf.cell(col_w[i], 6, value, border=1)
        pdf.ln()
    pdf.output(path)
    return path


def export_full_html_report(save_path: str = "", packet_rows: list[dict] | None = None, alert_rows: list[dict] | None = None, traceroute_rows: list[dict] | None = None) -> str:
    path = save_path or str(LOG_DIR / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    if packet_rows is not None or alert_rows is not None or traceroute_rows is not None:
        _write_full_html(path, packet_rows_to_df(packet_rows or []), alert_rows_to_df(alert_rows or []), traceroute_rows_to_df(traceroute_rows or []), source="session")
        return path
    if not is_persist_enabled():
        return ""
    conn = get_conn()
    if conn is None:
        return ""
    df_p = pd.read_sql_query("SELECT ts, src, dst, proto, sport, dport, length, summary FROM packets ORDER BY id", conn)
    df_a = pd.read_sql_query("SELECT ts, src, dst, proto, attack_type as attack, score, detail FROM alerts ORDER BY id", conn)
    _write_full_html(path, df_p, df_a, pd.DataFrame(), source="db")
    return path


def open_logs_folder() -> None:
    path = str(LOG_DIR)
    if os.name == "nt":
        os.startfile(path)  # type: ignore[arg-type]
        return
    try:
        import subprocess
        if sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception:
        pass
