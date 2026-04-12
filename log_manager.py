# log_manager.py
# -*- coding: utf-8 -*-
"""
Backward-compatible logging facade for NetBotPRO.

Heavy export/dataframe dependencies are imported lazily so the desktop
backend can boot and package without pulling optional reporting stacks
into the startup import graph.
"""

from __future__ import annotations

import importlib
from typing import Any

from core.netbotpro_logging.config import DB_PATH, FPDF, LOG_DIR, get_conn as _get_conn, init_storage, is_persist_enabled, set_persist
from core.netbotpro_logging.storage import cleanup_retention, insert_alert, insert_batch, insert_packet


def _import_exporters():
    return importlib.import_module("core.netbotpro_logging.exporters")


def _import_privacy():
    return importlib.import_module("core.netbotpro_logging.privacy")


def export_alerts_pdf(*args, **kwargs):
    return _import_exporters().export_alerts_pdf(*args, **kwargs)


def export_all_history_zip(*args, **kwargs):
    return _import_exporters().export_all_history_zip(*args, **kwargs)


def export_full_html_report(*args, **kwargs):
    return _import_exporters().export_full_html_report(*args, **kwargs)


def export_packets_csv(*args, **kwargs):
    return _import_exporters().export_packets_csv(*args, **kwargs)


def export_packets_excel(*args, **kwargs):
    return _import_exporters().export_packets_excel(*args, **kwargs)


def export_session_zip(*args, **kwargs):
    return _import_exporters().export_session_zip(*args, **kwargs)


def open_logs_folder(*args, **kwargs):
    return _import_exporters().open_logs_folder(*args, **kwargs)


def _df_from_alert_rows(*args, **kwargs):
    return _import_privacy().alert_rows_to_df(*args, **kwargs)


def _df_from_packet_rows(*args, **kwargs):
    return _import_privacy().packet_rows_to_df(*args, **kwargs)


def _df_from_traceroute_rows(*args, **kwargs):
    return _import_privacy().traceroute_rows_to_df(*args, **kwargs)


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
