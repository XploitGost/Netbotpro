# log_manager.py
# -*- coding: utf-8 -*-
"""
Backward-compatible logging facade for NetBotPRO.

The implementation now lives in `core.netbotpro_logging` so storage,
exporters, retention, and row normalization stay separated while the old
import path keeps working.
"""

from __future__ import annotations

from core.netbotpro_logging.config import DB_PATH, FPDF, LOG_DIR, get_conn as _get_conn, init_storage, is_persist_enabled, set_persist
from core.netbotpro_logging.exporters import (
    export_alerts_pdf,
    export_all_history_zip,
    export_full_html_report,
    export_packets_csv,
    export_packets_excel,
    export_session_zip,
    open_logs_folder,
)
from core.netbotpro_logging.privacy import alert_rows_to_df as _df_from_alert_rows
from core.netbotpro_logging.privacy import packet_rows_to_df as _df_from_packet_rows
from core.netbotpro_logging.privacy import traceroute_rows_to_df as _df_from_traceroute_rows
from core.netbotpro_logging.storage import cleanup_retention, insert_alert, insert_batch, insert_packet

__all__ = [
    "DB_PATH",
    "FPDF",
    "LOG_DIR",
    "_get_conn",
    "_df_from_alert_rows",
    "_df_from_packet_rows",
    "_df_from_traceroute_rows",
    "cleanup_retention",
    "export_alerts_pdf",
    "export_all_history_zip",
    "export_full_html_report",
    "export_packets_csv",
    "export_packets_excel",
    "export_session_zip",
    "init_storage",
    "insert_alert",
    "insert_batch",
    "insert_packet",
    "is_persist_enabled",
    "open_logs_folder",
    "set_persist",
]
