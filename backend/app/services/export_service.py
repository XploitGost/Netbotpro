from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from backend.app.bootstrap import ensure_project_root_on_path
from backend.app.security import ensure_within_directory, validate_export_name

ensure_project_root_on_path()

from log_manager import (  # noqa: E402
    LOG_DIR,
    export_alerts_pdf,
    export_full_html_report,
    export_packets_csv,
    export_packets_excel,
    export_session_zip,
)


class ExportService:
    def export_session(self, kind: str, packet_rows: list[dict[str, Any]], alert_rows: list[dict[str, Any]], traceroute_rows: list[dict[str, Any]]) -> dict[str, Any]:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        normalized = kind.lower().strip()
        if normalized == "csv":
            filename = validate_export_name(f"packets_{ts}", ".csv")
            path = ensure_within_directory(LOG_DIR, filename)
            export_packets_csv(path, packet_rows=packet_rows)
        elif normalized == "xlsx":
            filename = validate_export_name(f"packets_{ts}", ".xlsx")
            path = ensure_within_directory(LOG_DIR, filename)
            export_packets_excel(path, packet_rows=packet_rows)
        elif normalized == "pdf":
            filename = validate_export_name(f"alerts_{ts}", ".pdf")
            path = ensure_within_directory(LOG_DIR, filename)
            export_alerts_pdf(path, alert_rows=alert_rows)
        elif normalized == "html":
            filename = validate_export_name(f"report_{ts}", ".html")
            path = ensure_within_directory(LOG_DIR, filename)
            export_full_html_report(path, packet_rows=packet_rows, alert_rows=alert_rows, traceroute_rows=traceroute_rows)
        elif normalized == "zip":
            filename = validate_export_name(f"session_{ts}", ".zip")
            path = ensure_within_directory(LOG_DIR, filename)
            export_session_zip(path, packet_rows=packet_rows, alert_rows=alert_rows, traceroute_rows=traceroute_rows)
        else:
            raise ValueError("Unsupported export format")
        if not Path(path).exists():
            raise ValueError(f"Export failed for format: {normalized}")
        return {"ok": True, "format": normalized, "path": path}
