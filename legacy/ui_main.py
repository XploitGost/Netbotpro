# ui_kali.py - NetBotPRO Kali Edition UI (Scapy-optimized + auto-follow)

from __future__ import annotations

import os
import queue
import threading
import sqlite3
import platform
import subprocess
from collections import Counter
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Callable

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from config.settings_manager import load_settings, save_settings
from core.core_sniffer import NetSniffer
from core.firewall_tools import block_ip
from core.ids_ml import MLIDS
from core.ids_rules_engine import RuleEngine
from core.ids_signature import SignatureIDS
from core.incident_engine import IncidentCorrelator
from core.score_engine import AlertScorer
from core.traceroute_tools import run_traceroute
from legacy.charts import StatsChart
from legacy.filter_engine import make_packet_filter
from legacy.themes import apply_theme
from log_manager import (
    DB_PATH,
    export_packets_csv,
    export_packets_excel,
    export_alerts_pdf,
    export_full_html_report,
    open_logs_folder,
    init_storage,
    insert_packet,
    insert_alert,
)

# i18n fallback
try:
    from legacy.i18n import tr
except Exception:  # pragma: no cover
    def tr(key: str, lang: str = "fa") -> str:
        return key


LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# تعداد ردیف‌های زنده روی Sniffer (بیشتر از این تو VM لَگ می‌آره)
MAX_SNIFFER_ROWS = 2500
MAX_ALERT_ROWS = 4000

ALERT_SOUND_FILE = os.path.join(os.path.dirname(__file__), "alert.wav")

try:
    import winsound  # type: ignore
except Exception:
    winsound = None  # type: ignore


def get_font(size: int = 10, bold: bool = False):
    return ("Segoe UI", size, "bold" if bold else "normal")


class NetBotKaliGUI(tk.Tk):
    def __init__(self) -> None:
        super().__init__()

        # --- DB init ---
        try:
            init_storage()
        except Exception as e:
            print("[init_storage] warning:", e)

        # --- Settings ---
        try:
            self.settings: Dict[str, Any] = load_settings() or {}
        except Exception:
            self.settings = {}

        self.language = self.settings.get("language", "fa")
        self.theme_name = self.settings.get("theme", "dark")

        theme = apply_theme(self, self.theme_name)
        self.theme = theme
        self.bg_main = theme.get("bg", "#101419")
        self.fg_main = theme.get("fg", "#f9fafb")
        self.accent = theme.get("accent", "#22c55e")
        self.danger = theme.get("danger", "#ef4444")

        self.title("NetBotPRO - Kali Edition")
        self.geometry("1400x800")
        self.configure(bg=self.bg_main)

        # Settings flags
        self.autostart_sniffer = bool(self.settings.get("autostart_sniffer", False))
        self.auto_block = bool(self.settings.get("auto_block", False))
        self.whitelist_ips = self.settings.get(
            "whitelist_ips", "127.0.0.1, 192.168.1.1"
        )

        self.ids_signature_enabled = bool(
            self.settings.get("ids_signature_enabled", True)
        )
        self.ids_ml_enabled = bool(self.settings.get("ids_ml_enabled", True))
        self.ids_ml_threshold = float(self.settings.get("ids_ml_threshold", 0.25))
        self.ids_ml_contamination = float(
            self.settings.get("ids_ml_contamination", 0.06)
        )

        self.alert_sound_enabled = bool(self.settings.get("alert_sound_enabled", True))
        self.right_log_enabled = bool(self.settings.get("right_log_enabled", True))

        # --- Sniffer / IDS state ---
        self.sniffer_engine: Optional[NetSniffer] = None
        self.sniffer_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=8000)
        self.sniffer_running = False

        self.sniffer_filter_expr = tk.StringVar(value="")
        self.sniffer_filter_func: Callable[[Dict[str, Any]], bool] = make_packet_filter(
            ""
        )

        self.total_packets = 0
        self.total_alerts = 0

        self.ids_sig = SignatureIDS()
        self.ids_ml = MLIDS(
            contamination=self.ids_ml_contamination,
            sample_rate=5,
            min_train_size=200,
            max_buffer=8000,
        )
        self.rule_engine = RuleEngine()
        # Pro scoring / correlation (Balanced mode)
        self.alert_scorer = AlertScorer()
        self.incident_engine = IncidentCorrelator(window_sec=120)

        self.sniffer_rows: List[str] = []
        self.sniffer_meta_by_item: Dict[str, Dict[str, Any]] = {}
        self.alert_rows: List[str] = []

        self.counter_src: Counter[str] = Counter()
        self.counter_dst: Counter[str] = Counter()
        self.counter_proto: Counter[str] = Counter()

        self.ml_samples_seen = 0
        self.ml_last_score = 0.0

        self.dashboard_total_packets = tk.StringVar(value="0")
        self.dashboard_total_alerts = tk.StringVar(value="0")
        self.dashboard_top_src = tk.StringVar(value="-")
        self.dashboard_top_dst = tk.StringVar(value="-")
        self.dashboard_top_proto = tk.StringVar(value="-")

        self.ml_status_label = tk.StringVar(value="Idle")
        self.ml_samples_label = tk.StringVar(value="0")
        self.ml_lastscore_label = tk.StringVar(value="0.000")

        self._alerts_tab_starred = False

        # برای کم کردن فشار گراف
        self._chart_every_n_packets = 10
        self._chart_packet_counter = 0

        # Auto-follow آخرین پکت (مثل tail -f) – پیش‌فرض روشن
        self.auto_follow_tail = tk.BooleanVar(value=True)

        # DB worker queue (تا UI روی sqlite قفل نشه)
        self.db_queue: "queue.Queue[Tuple[Dict[str, Any], List[Dict[str, Any]]]]" = (
            queue.Queue(maxsize=10000)
        )
        threading.Thread(target=self._db_worker, daemon=True).start()

        # --- UI layout ---
        self._build_layout()

        try:
            self.state("zoomed")
        except Exception:
            pass

        # Autostart sniffer
        if self.autostart_sniffer:
            self.after(800, self.start_sniffer_ui)

        # Poll sniffer queue
        self.after(150, self._poll_sniffer_queue)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _style_text(self, txt: tk.Text) -> None:
        try:
            txt.configure(
                bg=self.theme.get("panel_bg", "#111827"),
                fg=self.theme.get("fg", "#f9fafb"),
                insertbackground=self.theme.get("fg", "#f9fafb"),
                relief="flat",
                borderwidth=1,
                highlightthickness=0,
            )
        except Exception:
            pass

    def _copy_from_text(self, event) -> str:
        widget: tk.Text = event.widget
        try:
            data = widget.get("sel.first", "sel.last")
        except Exception:
            return "break"
        if not data:
            return "break"
        self.clipboard_clear()
        self.clipboard_append(data)
        return "break"

    def _copy_from_tree(self, event) -> str:
        tv: ttk.Treeview = event.widget
        sel = tv.selection()
        if not sel:
            return "break"
        lines = []
        for item in sel:
            vals = tv.item(item, "values")
            lines.append("\t".join(str(v) for v in vals))
        text = "\n".join(lines)
        self.clipboard_clear()
        self.clipboard_append(text)
        return "break"

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def _build_layout(self) -> None:
        root = ttk.Frame(self)
        root.pack(fill="both", expand=True)

        # Status bar
        topbar = ttk.Frame(root)
        topbar.pack(side="top", fill="x")

        self.status_var = tk.StringVar(value="Ready")
        self.status_packets = tk.StringVar(value="Packets: 0")
        self.status_alerts = tk.StringVar(value="Alerts: 0")

        ttk.Label(topbar, textvariable=self.status_var).pack(side="left", padx=6)
        ttk.Label(topbar, textvariable=self.status_packets).pack(side="right", padx=6)
        ttk.Label(topbar, textvariable=self.status_alerts).pack(side="right", padx=6)

        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=True, padx=4, pady=4)
        self.nb = nb
        self.nb.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        self.tab_dashboard = ttk.Frame(nb)
        self.tab_sniffer = ttk.Frame(nb)
        self.tab_alerts = ttk.Frame(nb)
        self.tab_stats = ttk.Frame(nb)
        self.tab_tr = ttk.Frame(nb)
        self.tab_offline = ttk.Frame(nb)
        self.tab_logs = ttk.Frame(nb)
        self.tab_rules = ttk.Frame(nb)
        self.tab_settings = ttk.Frame(nb)
        self.tab_about = ttk.Frame(nb)

        nb.add(self.tab_dashboard, text=tr("tab.dashboard", self.language))
        nb.add(self.tab_sniffer, text=tr("tab.sniffer", self.language))
        nb.add(self.tab_alerts, text=tr("tab.alerts", self.language))
        nb.add(self.tab_stats, text=tr("tab.stats", self.language))
        nb.add(self.tab_tr, text=tr("tab.traceroute", self.language))
        nb.add(self.tab_offline, text=tr("tab.offline", self.language))
        nb.add(self.tab_logs, text=tr("tab.logs", self.language))
        nb.add(self.tab_rules, text=tr("tab.rules", self.language))
        nb.add(self.tab_settings, text=tr("tab.settings", self.language))
        nb.add(self.tab_about, text=tr("tab.about", self.language))

        self._build_dashboard()
        self._build_sniffer()
        self._build_alerts()
        self._build_stats()
        self._build_traceroute()
        self._build_offline()
        self._build_logs()
        self._build_rules()
        self._build_settings()
        self._build_about()

    # ---------------- Dashboard ----------------
    def _build_dashboard(self) -> None:
        f = self.tab_dashboard
        ttk.Label(
            f,
            text=tr("tab.dashboard", self.language),
            font=get_font(14, True),
            foreground=self.accent,
        ).pack(anchor="w", padx=10, pady=10)

        row = ttk.Frame(f)
        row.pack(fill="x", padx=10)

        def card(parent, title, var):
            frame = ttk.Labelframe(parent, text=title)
            frame.pack(side="left", fill="x", expand=True, padx=5)
            ttk.Label(frame, textvariable=var, font=get_font(18, True)).pack(
                padx=8, pady=8
            )

        card(row, "Packets", self.dashboard_total_packets)
        card(row, "Alerts", self.dashboard_total_alerts)
        card(row, "Top src", self.dashboard_top_src)
        card(row, "Top dst", self.dashboard_top_dst)
        card(row, "Top proto", self.dashboard_top_proto)

    # ---------------- Sniffer ----------------
    def _build_sniffer(self) -> None:
        frame = self.tab_sniffer

        bar = ttk.Frame(frame)
        bar.pack(fill="x", padx=6, pady=4)
        ttk.Label(
            bar,
            text=tr("sniffer.heading", self.language),
            font=get_font(12, True),
            foreground=self.accent,
        ).pack(side="left")

        btns = ttk.Frame(bar)
        btns.pack(side="right")
        ttk.Button(btns, text="Start", command=self.start_sniffer_ui).pack(
            side="left", padx=2
        )
        ttk.Button(btns, text="Stop", command=self.stop_sniffer_ui).pack(
            side="left", padx=2
        )
        ttk.Button(btns, text="Clear", command=self.clear_sniffer_table).pack(
            side="left", padx=2
        )
        ttk.Button(btns, text="Export HTML", command=self._export_html_report).pack(
            side="left", padx=2
        )

        filt = ttk.Frame(frame)
        filt.pack(fill="x", padx=6, pady=4)
        ttk.Label(filt, text="Filter expression:").pack(side="left")
        entry = ttk.Entry(filt, textvariable=self.sniffer_filter_expr)
        entry.pack(side="left", fill="x", expand=True, padx=4)
        ttk.Button(
            filt,
            text="Apply",
            command=lambda: self._apply_filter_expr(self.sniffer_filter_expr.get()),
        ).pack(side="left", padx=2)
        ttk.Button(filt, text="Reset", command=self._reset_filter).pack(
            side="left", padx=2
        )
        ttk.Button(
            filt, text="Follow selected", command=self._follow_selected_sniffer
        ).pack(side="left", padx=8)
        ttk.Button(filt, text="Stop follow", command=self._reset_filter).pack(
            side="left", padx=2
        )

        # چک‌باکس Auto-follow آخرین پکت
        ttk.Checkbutton(
            filt,
            text="Auto follow last packet",
            variable=self.auto_follow_tail,
        ).pack(side="left", padx=8)

        main = ttk.Frame(frame)
        main.pack(fill="both", expand=True, padx=6, pady=4)

        left = ttk.Frame(main)
        left.pack(side="left", fill="both", expand=True)

        right = ttk.Frame(main)
        right.pack(side="left", fill="both", expand=False, padx=(6, 0))

        cols = (
            "#",
            "time",
            "src",
            "dst",
            "proto",
            "sport",
            "dport",
            "country",
            "len",
            "proc",
            "alert",
        )
        self.sniffer_table = ttk.Treeview(
            left, columns=cols, show="headings", selectmode="browse"
        )
        widths = (55, 80, 150, 150, 70, 70, 70, 80, 70, 120, 60)
        for c, w in zip(cols, widths):
            self.sniffer_table.heading(c, text=c.upper())
            self.sniffer_table.column(c, width=w, anchor="w")

        vsb = ttk.Scrollbar(left, orient="vertical", command=self.sniffer_table.yview)
        self.sniffer_table.configure(yscrollcommand=vsb.set)
        self.sniffer_table.pack(side="left", fill="both", expand=True)
        vsb.pack(side="left", fill="y")

        self.sniffer_table.bind("<<TreeviewSelect>>", self._on_sniffer_row_select)
        self.sniffer_table.bind("<Button-3>", self._on_sniffer_right_click)
        self.sniffer_table.bind("<Control-c>", self._copy_from_tree, add="+")
        # هر اسکرول = کاربر می‌خواد خودش کنترل اسکرول رو بگیره → auto-follow خاموش
        self.sniffer_table.bind("<MouseWheel>", self._on_sniffer_scroll, add="+")
        # برای لینوکس
        self.sniffer_table.bind("<Button-4>", self._on_sniffer_scroll, add="+")
        self.sniffer_table.bind("<Button-5>", self._on_sniffer_scroll, add="+")

        # context menu
        self._sniffer_ctx_menu = tk.Menu(self, tearoff=0)
        self._sniffer_ctx_menu.add_command(
            label="Filter by src IP", command=lambda: self._follow_ip("src")
        )
        self._sniffer_ctx_menu.add_command(
            label="Filter by dst IP", command=lambda: self._follow_ip("dst")
        )
        self._sniffer_ctx_menu.add_command(
            label="Follow 5-tuple", command=self._follow_5tuple
        )
        self._sniffer_ctx_menu.add_separator()
        self._sniffer_ctx_menu.add_command(
            label="Reset filter", command=self._reset_filter
        )

        # details
        top_right = ttk.Labelframe(right, text="Packet details")
        top_right.pack(fill="both", expand=True)

        self.packet_details_text = tk.Text(top_right, height=18, wrap="word")
        self.packet_details_text.pack(fill="both", expand=True, padx=4, pady=4)
        self._style_text(self.packet_details_text)
        self.packet_details_text.bind("<Control-c>", self._copy_from_text, add="+")

        bottom_right = ttk.Labelframe(right, text="Live log")
        bottom_right.pack(fill="both", expand=True, pady=(6, 0))

        self.sniffer_log_text = tk.Text(bottom_right, height=10, wrap="none")
        self.sniffer_log_text.pack(fill="both", expand=True, padx=4, pady=4)
        self._style_text(self.sniffer_log_text)
        self.sniffer_log_text.bind("<Control-c>", self._copy_from_text, add="+")

    # ---------------- Alerts ----------------
    def _build_alerts(self) -> None:
        frame = self.tab_alerts
        bar = ttk.Frame(frame)
        bar.pack(fill="x", padx=6, pady=4)
        ttk.Label(
            bar,
            text=tr("alerts.heading", self.language),
            font=get_font(12, True),
            foreground=self.danger,
        ).pack(side="left")

        btns = ttk.Frame(bar)
        btns.pack(side="right")
        ttk.Button(
            btns, text="Follow selected", command=self._follow_selected_alert
        ).pack(side="left", padx=2)
        ttk.Button(btns, text="Stop follow", command=self._reset_filter).pack(
            side="left", padx=2
        )
        ttk.Button(btns, text="Clear", command=self.clear_alerts).pack(
            side="left", padx=2
        )

        box = ttk.Labelframe(frame, text="Alerts")
        box.pack(fill="both", expand=True, padx=6, pady=4)

        cols = ("time", "src", "dst", "proto", "dport", "attack", "score", "engine")
        self.alerts_table = ttk.Treeview(box, columns=cols, show="headings")
        widths = (80, 150, 150, 70, 70, 260, 80, 80)
        for c, w in zip(cols, widths):
            self.alerts_table.heading(c, text=c.upper())
            self.alerts_table.column(c, width=w, anchor="w")
        self.alerts_table.pack(fill="both", expand=True)
        self.alerts_table.bind("<Double-1>", self._on_alert_double_click)
        self.alerts_table.bind("<Control-c>", self._copy_from_tree, add="+")

    # ---------------- Stats / Graph ----------------
    def _build_stats(self) -> None:
        frame = self.tab_stats
        ttk.Label(
            frame,
            text=tr("stats.heading", self.language),
            font=get_font(12, True),
            foreground=self.accent,
        ).pack(anchor="w", padx=6, pady=4)
        self.stats_chart = StatsChart(frame)

        ml = ttk.Labelframe(frame, text="ML IDS")
        ml.pack(fill="x", padx=6, pady=4)
        ttk.Label(ml, text="Samples:").pack(side="left")
        ttk.Label(ml, textvariable=self.ml_samples_label).pack(side="left", padx=2)
        ttk.Label(ml, text="Last score:").pack(side="left", padx=(20, 2))
        ttk.Label(ml, textvariable=self.ml_lastscore_label).pack(side="left", padx=2)
        ttk.Label(ml, text="Status:").pack(side="left", padx=(20, 2))
        ttk.Label(ml, textvariable=self.ml_status_label).pack(side="left", padx=2)

    # ---------------- TraceRoute ----------------
    def _build_traceroute(self) -> None:
        frame = self.tab_tr
        top = ttk.Frame(frame)
        top.pack(fill="x", padx=6, pady=4)
        ttk.Label(
            top,
            text=tr("tr.heading", self.language),
            font=get_font(12, True),
            foreground=self.accent,
        ).pack(side="left")

        row = ttk.Frame(frame)
        row.pack(fill="x", padx=6, pady=4)
        self.tr_target = tk.StringVar(value="")
        ttk.Label(row, text=tr("tr.target", self.language)).pack(side="left")
        ttk.Entry(row, textvariable=self.tr_target).pack(
            side="left", fill="x", expand=True
        )
        ttk.Button(
            row, text=tr("tr.run", self.language), command=self.run_traceroute_ui
        ).pack(side="left", padx=4)

        main = ttk.Frame(frame)
        main.pack(fill="both", expand=True, padx=6, pady=4)

        left = ttk.Frame(main)
        left.pack(side="left", fill="both", expand=True)
        right = ttk.Labelframe(main, text="Hop details")
        right.pack(side="left", fill="both", expand=False, padx=(6, 0))

        cols = ("hop", "ip", "rtt", "country", "city", "org", "asn", "route")
        self.tr_table = ttk.Treeview(left, columns=cols, show="headings")
        widths = (50, 140, 70, 80, 100, 150, 80, 200)
        for c, w in zip(cols, widths):
            self.tr_table.heading(c, text=c.upper())
            self.tr_table.column(c, width=w, anchor="w")
        vsb = ttk.Scrollbar(left, orient="vertical", command=self.tr_table.yview)
        self.tr_table.configure(yscrollcommand=vsb.set)
        self.tr_table.pack(side="left", fill="both", expand=True)
        vsb.pack(side="left", fill="y")

        self.tr_table.bind("<<TreeviewSelect>>", self._on_tr_row_select)
        self.tr_table.bind("<Control-c>", self._copy_from_tree, add="+")

        self.tr_details = tk.Text(right, height=20, wrap="word")
        self.tr_details.pack(fill="both", expand=True, padx=4, pady=4)
        self._style_text(self.tr_details)
        self.tr_details.bind("<Control-c>", self._copy_from_text, add="+")

    # ---------------- Offline Analyzer (placeholder) ----------------
    def _build_offline(self) -> None:
        frame = self.tab_offline
        bar = ttk.Frame(frame)
        bar.pack(fill="x", padx=6, pady=4)
        ttk.Label(
            bar,
            text=tr("off.heading", self.language),
            font=get_font(12, True),
            foreground=self.accent,
        ).pack(side="left")

        row = ttk.Frame(frame)
        row.pack(fill="x", padx=6, pady=4)
        self.offline_path = tk.StringVar(value="")
        ttk.Entry(row, textvariable=self.offline_path).pack(
            side="left", fill="x", expand=True
        )
        ttk.Button(row, text="Browse", command=self._browse_pcap).pack(
            side="left", padx=4
        )
        ttk.Button(
            row, text="Analyze (soon)", command=self._run_offline_analyzer
        ).pack(side="left", padx=4)

        box = ttk.Labelframe(frame, text="Offline alerts")
        box.pack(fill="both", expand=True, padx=6, pady=4)
        cols = ("time", "src", "dst", "proto", "dport", "attack", "score")
        self.offline_alerts_table = ttk.Treeview(box, columns=cols, show="headings")
        for c in cols:
            self.offline_alerts_table.heading(c, text=c.upper())
            self.offline_alerts_table.column(c, width=100, anchor="w")
        self.offline_alerts_table.pack(fill="both", expand=True)
        self.offline_alerts_table.bind("<Control-c>", self._copy_from_tree, add="+")

    # ---------------- Logs / History ----------------
    def _build_logs(self) -> None:
        frame = self.tab_logs

        bar = ttk.Frame(frame)
        bar.pack(fill="x", padx=6, pady=4)
        ttk.Label(
            bar,
            text=tr("logs.heading", self.language),
            font=get_font(12, True),
            foreground=self.accent,
        ).pack(side="left")

        btns = ttk.Frame(bar)
        btns.pack(side="right")
        ttk.Button(btns, text="Refresh", command=self._refresh_logs_ui).pack(
            side="left", padx=2
        )
        ttk.Button(btns, text="Open folder", command=open_logs_folder).pack(
            side="left", padx=2
        )
        ttk.Button(btns, text="Export CSV", command=self._export_csv).pack(
            side="left", padx=2
        )
        ttk.Button(btns, text="Export Excel", command=self._export_xlsx).pack(
            side="left", padx=2
        )
        ttk.Button(btns, text="Export PDF", command=self._export_pdf).pack(
            side="left", padx=2
        )
        ttk.Button(btns, text="Export HTML", command=self._export_full_html).pack(
            side="left", padx=2
        )

        main = ttk.Frame(frame)
        main.pack(fill="both", expand=True, padx=6, pady=4)

        upper = ttk.Labelframe(main, text="Packet log")
        upper.pack(fill="both", expand=True)
        lower = ttk.Labelframe(main, text="Alert log")
        lower.pack(fill="both", expand=True, pady=(6, 0))

        cols_p = ("id", "ts", "src", "dst", "proto", "sport", "dport", "length")
        self.logs_packets = ttk.Treeview(upper, columns=cols_p, show="headings")
        for c in cols_p:
            self.logs_packets.heading(c, text=c.upper())
            self.logs_packets.column(c, width=100, anchor="w")
        self.logs_packets.pack(fill="both", expand=True)
        self.logs_packets.bind("<Control-c>", self._copy_from_tree, add="+")

        cols_a = ("id", "ts", "src", "dst", "proto", "attack", "score")
        self.logs_alerts = ttk.Treeview(lower, columns=cols_a, show="headings")
        for c in cols_a:
            self.logs_alerts.heading(c, text=c.upper())
            self.logs_alerts.column(c, width=100, anchor="w")
        self.logs_alerts.pack(fill="both", expand=True)
        self.logs_alerts.bind("<Control-c>", self._copy_from_tree, add="+")

        self._refresh_logs_ui()

    # ---------------- IDS Rules ----------------
    def _build_rules(self) -> None:
        frame = self.tab_rules
        ttk.Label(
            frame,
            text=tr("rules.heading", self.language),
            font=get_font(12, True),
            foreground=self.accent,
        ).pack(anchor="w", padx=6, pady=4)

        btns = ttk.Frame(frame)
        btns.pack(fill="x", padx=6, pady=4)
        ttk.Button(
            btns, text="Reload from file", command=self._rules_load_from_file
        ).pack(side="left", padx=2)
        ttk.Button(btns, text="Save", command=self._rules_save_to_file).pack(
            side="left", padx=2
        )

        self.rules_text = tk.Text(frame, wrap="none")
        self.rules_text.pack(fill="both", expand=True, padx=6, pady=4)
        self._style_text(self.rules_text)
        self.rules_text.bind("<Control-c>", self._copy_from_text, add="+")

        self._rules_load_from_file(initial=True)

    # ---------------- Settings ----------------
    def _build_settings(self) -> None:
        frame = self.tab_settings
        top = ttk.Frame(frame)
        top.pack(fill="x", padx=6, pady=4)
        ttk.Label(
            top,
            text=tr("settings.heading", self.language),
            font=get_font(12, True),
            foreground=self.accent,
        ).pack(side="left")

        gen = ttk.Labelframe(frame, text="General")
        gen.pack(fill="x", padx=6, pady=4)

        self.var_iface = tk.StringVar(value=self.settings.get("iface", "iface=default"))
        self.var_autostart = tk.BooleanVar(value=self.autostart_sniffer)
        self.var_auto_block = tk.BooleanVar(value=self.auto_block)
        self.var_whitelist = tk.StringVar(value=self.whitelist_ips)

        row1 = ttk.Frame(gen)
        row1.pack(fill="x", pady=2)
        ttk.Label(row1, text="Sniffer interface:").pack(side="left")
        ttk.Entry(row1, textvariable=self.var_iface, width=24).pack(side="left", padx=4)

        row2 = ttk.Frame(gen)
        row2.pack(fill="x", pady=2)
        ttk.Checkbutton(
            row2, text="Autostart sniffer on launch", variable=self.var_autostart
        ).pack(side="left")

        row3 = ttk.Frame(gen)
        row3.pack(fill="x", pady=2)
        ttk.Checkbutton(
            row3, text="Auto-block high risk IPs", variable=self.var_auto_block
        ).pack(side="left")

        row4 = ttk.Frame(gen)
        row4.pack(fill="x", pady=2)
        ttk.Label(row4, text="Whitelist IPs (comma):").pack(side="left")
        ttk.Entry(row4, textvariable=self.var_whitelist, width=50).pack(
            side="left", padx=4
        )

        ids = ttk.Labelframe(frame, text="IDS / ML")
        ids.pack(fill="x", padx=6, pady=4)

        self.var_ml_threshold = tk.DoubleVar(value=self.ids_ml_threshold)
        self.var_ml_contamination = tk.DoubleVar(value=self.ids_ml_contamination)
        self.var_ids_sig_enabled = tk.BooleanVar(value=self.ids_signature_enabled)
        self.var_ids_ml_enabled = tk.BooleanVar(value=self.ids_ml_enabled)

        row5 = ttk.Frame(ids)
        row5.pack(fill="x", pady=2)
        ttk.Label(row5, text="ML threshold:").pack(side="left")
        ttk.Entry(row5, textvariable=self.var_ml_threshold, width=8).pack(
            side="left", padx=4
        )

        row6 = ttk.Frame(ids)
        row6.pack(fill="x", pady=2)
        ttk.Label(row6, text="ML contamination:").pack(side="left")
        ttk.Entry(row6, textvariable=self.var_ml_contamination, width=8).pack(
            side="left", padx=4
        )

        row7 = ttk.Frame(ids)
        row7.pack(fill="x", pady=2)
        ttk.Checkbutton(
            row7, text="Enable signature IDS", variable=self.var_ids_sig_enabled
        ).pack(side="left")
        ttk.Checkbutton(
            row7, text="Enable ML IDS", variable=self.var_ids_ml_enabled
        ).pack(side="left", padx=20)

        ui_box = ttk.Labelframe(frame, text="UI")
        ui_box.pack(fill="x", padx=6, pady=4)

        self.var_language = tk.StringVar(value=self.language)
        self.var_theme = tk.StringVar(value=self.theme_name)
        self.var_alert_sound_enabled = tk.BooleanVar(value=self.alert_sound_enabled)
        self.var_right_log_enabled = tk.BooleanVar(value=self.right_log_enabled)

        row8 = ttk.Frame(ui_box)
        row8.pack(fill="x", pady=2)
        ttk.Label(row8, text="Language:").pack(side="left")
        ttk.Combobox(
            row8,
            textvariable=self.var_language,
            values=("fa", "en"),
            width=6,
            state="readonly",
        ).pack(side="left", padx=4)
        ttk.Label(row8, text="Theme:").pack(side="left", padx=(20, 2))
        ttk.Combobox(
            row8,
            textvariable=self.var_theme,
            values=("dark", "light"),
            width=8,
            state="readonly",
        ).pack(side="left", padx=4)

        row9 = ttk.Frame(ui_box)
        row9.pack(fill="x", pady=2)
        ttk.Checkbutton(
            row9, text="Play sound on alert", variable=self.var_alert_sound_enabled
        ).pack(side="left")
        ttk.Checkbutton(
            row9, text="Show right-side sniffer log", variable=self.var_right_log_enabled
        ).pack(side="left", padx=20)

        bottom = ttk.Frame(frame)
        bottom.pack(fill="x", padx=6, pady=8)
        ttk.Button(bottom, text="Save settings", command=self._save_settings).pack(
            side="right"
        )

    # ---------------- About ----------------
    def _build_about(self) -> None:
        frame = self.tab_about
        ttk.Label(
            frame,
            text=tr("about.text", self.language),
            font=get_font(11, False),
            justify="left",
        ).pack(anchor="nw", padx=10, pady=10)

    # =================================================================
    # Sniffer / IDS core
    # =================================================================
    def start_sniffer_ui(self) -> None:
        if self.sniffer_engine is not None:
            return
        iface = self.settings.get("iface", "iface=default")
        try:
            self.sniffer_engine = NetSniffer(self._on_sniffer_packet)
            self.sniffer_engine.start(iface=iface)
            self.sniffer_running = True
            self.status_var.set(f"Sniffer running on {iface}")
        except Exception as e:
            self.sniffer_engine = None
            self.sniffer_running = False
            messagebox.showerror("Sniffer", f"Failed to start sniffer:\n{e}")

    def stop_sniffer_ui(self) -> None:
        eng = self.sniffer_engine
        self.sniffer_engine = None
        self.sniffer_running = False
        if eng is not None:
            try:
                eng.stop()
            except Exception:
                pass
        self.status_var.set("Sniffer stopped")

    def clear_sniffer_table(self) -> None:
        tv = self.sniffer_table
        for item in tv.get_children():
            tv.delete(item)
        self.sniffer_rows.clear()
        self.sniffer_meta_by_item.clear()
        self.total_packets = 0
        self.dashboard_total_packets.set("0")
        self.status_packets.set("Packets: 0")
        self.packet_details_text.delete("1.0", "end")
        self.sniffer_log_text.delete("1.0", "end")

    def _apply_filter_expr(self, expr: str) -> None:
        expr = (expr or "").strip()
        if not expr:
            self._reset_filter()
            return
        try:
            self.sniffer_filter_func = make_packet_filter(expr)
            self.sniffer_filter_expr.set(expr)
            self.status_var.set(f"Filter: {expr}")
        except Exception as e:
            self.sniffer_filter_func = make_packet_filter("")
            messagebox.showerror("Filter", f"Invalid filter:\n{e}")

    def _reset_filter(self) -> None:
        self.sniffer_filter_expr.set("")
        self.sniffer_filter_func = make_packet_filter("")
        self.status_var.set("Filter: (none)")

    def _on_sniffer_packet(self, meta: Dict[str, Any]) -> None:
        try:
            self.sniffer_queue.put_nowait(meta)
        except queue.Full:
            # صف پر شد، ترجیح می‌دیم UI زنده بماند تا این‌که همه‌چیز را log کنیم
            pass

    def _poll_sniffer_queue(self) -> None:
        """
        هر ~150ms تعداد محدودی پکت را پردازش می‌کنیم.
        اگر صف ترکید، پکت‌های خیلی قدیمی Drop می‌شوند تا UI زنده بماند.
        """
        # اگر صف خیلی پر شد، قدیمی‌ها را دور بریزیم
        qsize = self.sniffer_queue.qsize()
        if qsize > 4000:
            drop_n = qsize - 3000
            for _ in range(drop_n):
                try:
                    self.sniffer_queue.get_nowait()
                except queue.Empty:
                    break

        processed = 0
        max_per_tick = 40  # سبک‌تر از نسخه‌های قبلی
        while processed < max_per_tick:
            try:
                meta = self.sniffer_queue.get_nowait()
            except queue.Empty:
                break
            self._handle_packet(meta)
            processed += 1

        self.after(150, self._poll_sniffer_queue)

    def _handle_packet(self, meta: Dict[str, Any]) -> None:
        # Counters
        self.total_packets += 1
        self.status_packets.set(f"Packets: {self.total_packets}")
        self.dashboard_total_packets.set(str(self.total_packets))

        src = meta.get("src") or "-"
        dst = meta.get("dst") or "-"
        proto = (meta.get("proto") or "OTHER").upper()
        self.counter_src[src] += 1
        self.counter_dst[dst] += 1
        self.counter_proto[proto] += 1

        self._update_dashboard_top()

        alerts: List[Dict[str, Any]] = []

        # Signature IDS
        try:
            if self.ids_signature_enabled:
                a1 = self.ids_sig.analyze_packet(meta)
                if a1:
                    a1["engine"] = "SIG"
                    try:
                        self.alert_scorer.enrich_alert(meta, a1, sig_engine=self.ids_sig)
                        self.incident_engine.enrich_alert(meta, a1)
                    except Exception:
                        pass
                    alerts.append(a1)
        except Exception:
            pass

        # Rule engine
        try:
            a2 = self.rule_engine.analyze(meta)
            if a2:
                a2["engine"] = "RULE"
                try:
                    self.alert_scorer.enrich_alert(meta, a2, sig_engine=self.ids_sig)
                    self.incident_engine.enrich_alert(meta, a2)
                except Exception:
                    pass
                alerts.append(a2)
        except Exception:
            pass

        # ML IDS
        try:
            if self.ids_ml_enabled:
                self.ml_samples_seen += 1
                a3 = self.ids_ml.analyze_packet(meta, threshold=self.ids_ml_threshold)
                self.ml_status_label.set("Training / Active")
                if a3:
                    a3["engine"] = "ML"
                    try:
                        self.alert_scorer.enrich_alert(meta, a3, sig_engine=self.ids_sig)
                        self.incident_engine.enrich_alert(meta, a3)
                    except Exception:
                        pass
                    alerts.append(a3)
                    try:
                        self.ml_last_score = float(a3.get("score", 0.0))
                    except Exception:
                        pass
        except Exception:
            pass

        self.ml_samples_label.set(str(self.ml_samples_seen))
        self.ml_lastscore_label.set(f"{self.ml_last_score:.3f}")

        # Log to DB (آسنکرون)
        self._log_packet_and_alerts(meta, alerts)

        # Update charts (هر N پکت یک‌بار)
        try:
            self._chart_packet_counter += 1
            if self._chart_packet_counter >= self._chart_every_n_packets:
                self.stats_chart.update_with_packet(
                    meta, self.total_packets, self.total_alerts
                )
                self._chart_packet_counter = 0
        except Exception:
            pass

        # Filter برای UI
        try:
            if self.sniffer_filter_func and not self.sniffer_filter_func(meta):
                return
        except Exception:
            pass

        # اضافه کردن به جدول Sniffer
        self._append_sniffer_row(meta, has_alert=bool(alerts))

        # اضافه کردن Alerts به تب Alert
        for a in alerts:
            self._add_alert(meta, a)

    def _log_packet_and_alerts(
        self, meta: Dict[str, Any], alerts: List[Dict[str, Any]]
    ) -> None:
        """ساخت ردیف‌های DB و ارسال به صف بک‌گراند؛ خود UI مستقیم sqlite را صدا نمی‌زند."""
        row_p = {
            "ts": meta.get("ts"),
            "src": meta.get("src"),
            "dst": meta.get("dst"),
            "proto": meta.get("proto"),
            "sport": meta.get("sport"),
            "dport": meta.get("dport"),
            "length": meta.get("length"),
            "country": meta.get("country") or meta.get("country_code"),
            "org": meta.get("org"),
            "summary": meta.get("summary"),
            "is_alert": bool(alerts),
        }

        alert_rows: List[Dict[str, Any]] = []
        for a in alerts:
            row_a = {
                "ts": meta.get("ts"),
                "src": meta.get("src"),
                "dst": meta.get("dst"),
                "proto": meta.get("proto"),
                "attack_type": a.get("attack_type") or a.get("attack") or "Alert",
                "score": float(a.get("score", 0.0)),
                "detail": a.get("detail") or meta.get("summary"),
            }
            alert_rows.append(row_a)

        try:
            self.db_queue.put_nowait((row_p, alert_rows))
        except queue.Full:
            # ترجیح می‌دیم UI فریز نشه، حتی اگر چند ردیف Log از دست بره
            pass

    def _db_worker(self) -> None:
        """تمام insertهای sqlite در این Thread انجام می‌شود تا Tk قفل نشود."""
        while True:
            try:
                packet_row, alert_rows = self.db_queue.get()
            except Exception:
                continue
            try:
                insert_packet(packet_row)
                for r in alert_rows:
                    insert_alert(r)
            except Exception as e:
                print("[db_worker] error:", e)

    def _update_dashboard_top(self) -> None:
        if self.counter_src:
            self.dashboard_top_src.set(self.counter_src.most_common(1)[0][0])
        if self.counter_dst:
            self.dashboard_top_dst.set(self.counter_dst.most_common(1)[0][0])
        if self.counter_proto:
            self.dashboard_top_proto.set(self.counter_proto.most_common(1)[0][0])

    def _append_sniffer_row(self, meta: Dict[str, Any], has_alert: bool) -> None:
        tv = self.sniffer_table
        row_id = str(self.total_packets)
        values = (
            row_id,
            meta.get("ts"),
            meta.get("src"),
            meta.get("dst"),
            meta.get("proto"),
            meta.get("sport"),
            meta.get("dport"),
            meta.get("country"),
            meta.get("length"),
            meta.get("process_name"),
            "YES" if has_alert else "",
        )
        item_id = tv.insert("", "end", values=values)
        self.sniffer_rows.append(item_id)
        self.sniffer_meta_by_item[item_id] = dict(meta)

        # Auto-follow: اگر فعال بود، به آخرین ردیف برو
        try:
            if self.auto_follow_tail.get():
                self.sniffer_table.see(item_id)
        except Exception:
            pass

        if len(self.sniffer_rows) > MAX_SNIFFER_ROWS:
            old = self.sniffer_rows.pop(0)
            try:
                tv.delete(old)
            except Exception:
                pass
            self.sniffer_meta_by_item.pop(old, None)

        try:
            if self.right_log_enabled:
                l7 = meta.get("l7")
                extra = f" - {l7}" if l7 else ""
                self.sniffer_log_text.insert(
                    "end",
                    f"[{meta.get('ts')}] {meta.get('src')} -> {meta.get('dst')} "
                    f"{meta.get('proto')} len={meta.get('length')}{extra}\n",
                )
                self.sniffer_log_text.see("end")
        except Exception:
            pass

    def _on_sniffer_row_select(self, event=None) -> None:
        tv = self.sniffer_table
        sel = tv.selection()
        if not sel:
            return
        item_id = sel[0]
        meta = self.sniffer_meta_by_item.get(item_id)
        if not meta:
            return
        text = self._format_packet_details(meta)
        self.packet_details_text.delete("1.0", "end")
        self.packet_details_text.insert("1.0", text)

    def _format_packet_details(self, meta: Dict[str, Any]) -> str:
        def val(x, default="Unknown"):
            if x is None:
                return default
            s = str(x)
            if not s or s.lower() == "none":
                return default
            return s

        lines: List[str] = []
        lines.append(f"Timestamp: {val(meta.get('ts'))}")
        lines.append(f"Direction: {val(meta.get('direction'))}")
        lines.append(f"Summary: {val(meta.get('summary'))}")
        l7 = meta.get("l7")
        if l7:
            lines.append(f"L7: {l7}")
        lines.append("")
        lines.append("[Local Process]")
        lines.append(f"PID: {val(meta.get('pid'), 'N/A')}")
        lines.append(f"Process: {val(meta.get('process_name'), 'N/A')}")
        lines.append("")
        lines.append("[L2 Ethernet]")
        lines.append(f"MAC Src: {val(meta.get('src_mac'), 'N/A')}")
        lines.append(f"MAC Dst: {val(meta.get('dst_mac'), 'N/A')}")
        lines.append(f"Vendor Src: {val(meta.get('vendor_src'), 'Unknown vendor')}")
        lines.append(f"Vendor Dst: {val(meta.get('vendor_dst'), 'Unknown vendor')}")
        lines.append("")
        lines.append("[L3 IPv4]")
        lines.append(f"IP Src: {val(meta.get('src'), 'N/A')}")
        lines.append(f"IP Dst: {val(meta.get('dst'), 'N/A')}")
        country_name = meta.get("country_name") or meta.get("country")
        country_code = meta.get("country") or meta.get("country_code")
        lines.append(
            f"Country: {val(country_name, 'Unknown')} ({val(country_code, '-')})"
        )
        lines.append(
            f"City/Org: {val(meta.get('city'), 'Unknown')} / {val(meta.get('org'), 'Unknown')}"
        )
        lines.append(f"ASN: {val(meta.get('asn'), 'N/A')}")
        lines.append(f"Inside/Outside: {val(meta.get('inside_outside'), 'Unknown')}")
        lines.append("")
        lines.append("[L4 Transport]")
        lines.append(f"Proto: {val(meta.get('proto'))}")
        lines.append(f"Sport: {val(meta.get('sport'), 'N/A')}")
        lines.append(f"Dport: {val(meta.get('dport'), 'N/A')}")
        lines.append(f"Length: {val(meta.get('length'), 'N/A')}")
        lines.append("")
        return "\n".join(lines)

    # ---------------- Sniffer context / follow ----------------
    def _on_sniffer_right_click(self, event) -> None:
        row_id = self.sniffer_table.identify_row(event.y)
        if not row_id:
            return
        self.sniffer_table.selection_set(row_id)
        try:
            self._sniffer_ctx_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._sniffer_ctx_menu.grab_release()

    def _get_selected_sniffer_meta(self) -> Optional[Dict[str, Any]]:
        sel = self.sniffer_table.selection()
        if not sel:
            return None
        return self.sniffer_meta_by_item.get(sel[0])

    def _follow_ip(self, which: str) -> None:
        meta = self._get_selected_sniffer_meta()
        if not meta:
            return
        ip = meta.get(which)
        if not ip:
            return
        expr = f"{which}={ip}"
        self._apply_filter_expr(expr)

    def _follow_5tuple(self) -> None:
        meta = self._get_selected_sniffer_meta()
        if not meta:
            return
        src = meta.get("src")
        dst = meta.get("dst")
        proto = meta.get("proto")
        sport = meta.get("sport")
        dport = meta.get("dport")
        parts = []
        if src:
            parts.append(f"src={src}")
        if dst:
            parts.append(f"dst={dst}")
        if proto:
            parts.append(f"proto={proto}")
        if sport is not None:
            parts.append(f"sport={sport}")
        if dport is not None:
            parts.append(f"dport={dport}")
        if not parts:
            return
        expr = " and ".join(parts)
        self._apply_filter_expr(expr)

    def _follow_selected_sniffer(self) -> None:
        self._follow_5tuple()

    def _follow_selected_alert(self) -> None:
        tv = self.alerts_table
        sel = tv.selection()
        if not sel:
            return
        item_id = sel[0]
        vals = tv.item(item_id, "values")
        if not vals:
            return
        _, src, dst, proto, dport, *_ = vals
        parts = []
        if src:
            parts.append(f"src={src}")
        if dst:
            parts.append(f"dst={dst}")
        if proto:
            parts.append(f"proto={proto}")
        if dport:
            parts.append(f"dport={dport}")
        if not parts:
            return
        expr = " and ".join(parts)
        self._apply_filter_expr(expr)
        self.nb.select(self.tab_sniffer)

    def _on_alert_double_click(self, event) -> None:
        self._follow_selected_alert()

    def _on_sniffer_scroll(self, event=None) -> None:
        """
        هر بار که کاربر تو جدول اسکرول می‌کند، auto-follow خاموش می‌شود
        تا بتواند پکت‌های قدیمی را بررسی کند.
        """
        try:
            self.auto_follow_tail.set(False)
        except Exception:
            pass
        return None

    # =================================================================
    # Alerts table / notifications
    # =================================================================
    def clear_alerts(self) -> None:
        for item in self.alerts_table.get_children():
            self.alerts_table.delete(item)
        self.alert_rows.clear()
        self.total_alerts = 0
        self.status_alerts.set("Alerts: 0")
        self.dashboard_total_alerts.set("0")

    def _add_alert(self, meta: Dict[str, Any], alert: Dict[str, Any]) -> None:
        self.total_alerts += 1
        self.status_alerts.set(f"Alerts: {self.total_alerts}")
        self.dashboard_total_alerts.set(str(self.total_alerts))

        vals = (
            meta.get("ts"),
            meta.get("src"),
            meta.get("dst"),
            meta.get("proto"),
            meta.get("dport"),
            alert.get("attack_type") or alert.get("attack") or "Alert",
            "%.3f" % float(alert.get("score", 0.0)),
            alert.get("engine") or "IDS",
        )
        item_id = self.alerts_table.insert("", "end", values=vals)
        self.alert_rows.append(item_id)
        if len(self.alert_rows) > MAX_ALERT_ROWS:
            old = self.alert_rows.pop(0)
            try:
                self.alerts_table.delete(old)
            except Exception:
                pass

        self._notify_alert(meta, alert)

        # Auto-block ساده
        try:
            if self.auto_block and float(alert.get("score", 0.0)) >= 0.7:
                ip = meta.get("remote_ip") or meta.get("src")
                if ip:
                    wl = [x.strip() for x in self.whitelist_ips.split(",") if x.strip()]
                    if ip not in wl:
                        if not block_ip(ip):
                            self.status_var.set(f"Block failed: {ip}")
        except Exception:
            pass

    def _notify_alert(self, meta: Dict[str, Any], alert: Dict[str, Any]) -> None:
        src = meta.get("src")
        dst = meta.get("dst")
        proto = meta.get("proto")
        attack = alert.get("attack_type") or alert.get("attack") or "Alert"
        score = float(alert.get("score", 0.0))
        self.status_var.set(
            f"New alert: {src} -> {dst} ({proto}) {attack} score={score:.3f}"
        )

        if not self._alerts_tab_starred:
            self._alerts_tab_starred = True
            self.nb.tab(self.tab_alerts, text="* " + tr("tab.alerts", self.language))

        if self.alert_sound_enabled:
            self._play_alert_sound()

    def _play_alert_sound(self) -> None:
        try:
            if os.path.exists(ALERT_SOUND_FILE):
                if platform.system().lower().startswith("win") and winsound is not None:
                    winsound.PlaySound(  # type: ignore
                        ALERT_SOUND_FILE, winsound.SND_FILENAME | winsound.SND_ASYNC
                    )
                    return
                try:
                    subprocess.Popen(["paplay", ALERT_SOUND_FILE])
                    return
                except Exception:
                    try:
                        subprocess.Popen(["aplay", ALERT_SOUND_FILE])
                        return
                    except Exception:
                        pass
            self.bell()
        except Exception:
            try:
                self.bell()
            except Exception:
                pass

    # =================================================================
    # TraceRoute handlers
    # =================================================================
    def run_traceroute_ui(self) -> None:
        target = self.tr_target.get().strip()
        if not target:
            messagebox.showwarning("TraceRoute", "Please enter host or IP.")
            return

        for item in self.tr_table.get_children():
            self.tr_table.delete(item)
        self.tr_details.delete("1.0", "end")
        self.status_var.set(f"Traceroute to {target} ...")

        def worker():
            hops = run_traceroute(target)
            self.after(0, lambda: self._traceroute_done(target, hops))

        threading.Thread(target=worker, daemon=True).start()

    def _traceroute_done(self, target: str, hops: List[Dict[str, Any]]) -> None:
        for hop in hops:
            self.tr_table.insert(
                "",
                "end",
                values=(
                    hop.get("hop"),
                    hop.get("ip"),
                    hop.get("rtt_ms"),
                    hop.get("country_name") or hop.get("country_code"),
                    hop.get("city"),
                    hop.get("org") or hop.get("isp"),
                    hop.get("asn"),
                    hop.get("route"),
                ),
            )
        self.status_var.set(f"Traceroute finished: {target}")
        children = self.tr_table.get_children()
        if children:
            self.tr_table.selection_set(children[-1])
            self._on_tr_row_select()

    def _on_tr_row_select(self, event=None) -> None:
        sel = self.tr_table.selection()
        if not sel:
            return
        item_id = sel[0]
        vals = self.tr_table.item(item_id, "values")
        if not vals:
            return
        hop, ip, rtt, country, city, org, asn, route = vals
        lines = [
            f"Hop: {hop}",
            f"IP: {ip}",
            f"RTT: {rtt} ms",
            f"Country: {country}",
            f"City: {city}",
            f"Org/ISP: {org}",
            f"ASN: {asn}",
            f"Route: {route}",
        ]
        self.tr_details.delete("1.0", "end")
        self.tr_details.insert("1.0", "\n".join(lines))

    # =================================================================
    # Offline placeholder
    # =================================================================
    def _browse_pcap(self) -> None:
        path = filedialog.askopenfilename(
            title="Select PCAP file",
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")],
        )
        if path:
            self.offline_path.set(path)

    def _run_offline_analyzer(self) -> None:
        path = self.offline_path.get().strip()
        if not path:
            messagebox.showinfo("Offline", "Select a PCAP file first.")
            return
        for item in self.offline_alerts_table.get_children():
            self.offline_alerts_table.delete(item)
        self.status_var.set(f"Offline analyzer not implemented yet ({path})")

    # =================================================================
    # Logs
    # =================================================================
    def _refresh_logs_ui(self) -> None:
        for tv in (self.logs_packets, self.logs_alerts):
            for item in tv.get_children():
                tv.delete(item)
        conn = None
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute(
                "SELECT id, ts, src, dst, proto, sport, dport, length "
                "FROM packets ORDER BY id DESC LIMIT 500"
            )
            for row in cur.fetchall():
                self.logs_packets.insert("", "end", values=row)

            cur.execute(
                "SELECT id, ts, src, dst, proto, attack_type, score "
                "FROM alerts ORDER BY id DESC LIMIT 300"
            )
            for row in cur.fetchall():
                self.logs_alerts.insert("", "end", values=row)
        except sqlite3.OperationalError as e:
            if "no such table" in str(e).lower():
                try:
                    init_storage()
                except Exception as e2:
                    print("[refresh_logs] init_storage error:", e2)
                else:
                    self._refresh_logs_ui()
            else:
                print("[refresh_logs] sqlite error:", e)
        except Exception as e:
            print("[refresh_logs] error:", e)
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def _export_csv(self) -> None:
        path = export_packets_csv()
        self.status_var.set(f"CSV exported: {path}")

    def _export_xlsx(self) -> None:
        path = export_packets_excel()
        self.status_var.set(f"Excel exported: {path}")

    def _export_pdf(self) -> None:
        path = export_alerts_pdf()
        self.status_var.set(f"PDF exported: {path}")

    def _export_full_html(self) -> None:
        path = export_full_html_report()
        self.status_var.set(f"HTML exported: {path}")

    def _export_html_report(self) -> None:
        path = export_full_html_report()
        self.status_var.set(f"HTML exported: {path}")

    # =================================================================
    # Rules
    # =================================================================
    def _rules_load_from_file(self, initial: bool = False) -> None:
        try:
            rules_path = self.rule_engine.rules_path  # type: ignore[attr-defined]
        except Exception:
            rules_path = os.path.join(os.path.dirname(__file__), "rules.json")
        if not os.path.exists(rules_path):
            txt = "[]"
        else:
            try:
                with open(rules_path, "r", encoding="utf-8") as f:
                    txt = f.read()
            except Exception:
                txt = "[]"
        self.rules_text.delete("1.0", "end")
        self.rules_text.insert("1.0", txt)
        if not initial:
            self.status_var.set(f"Rules loaded from {rules_path}")

    def _rules_save_to_file(self) -> None:
        try:
            rules_path = self.rule_engine.rules_path  # type: ignore[attr-defined]
        except Exception:
            rules_path = os.path.join(os.path.dirname(__file__), "rules.json")
        txt = self.rules_text.get("1.0", "end").strip()
        if not txt:
            txt = "[]"
        import json

        try:
            data = json.loads(txt)
        except Exception as e:
            messagebox.showerror("Rules", f"JSON error:\n{e}")
            return
        try:
            with open(rules_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            messagebox.showerror("Rules", f"Failed to save:\n{e}")
            return
        try:
            self.rule_engine.reload()
        except Exception:
            pass
        self.status_var.set(f"Rules saved to {rules_path}")

    # =================================================================
    # Settings save
    # =================================================================
    def _save_settings(self) -> None:
        self.settings["iface"] = self.var_iface.get().strip() or "iface=default"
        self.settings["autostart_sniffer"] = bool(self.var_autostart.get())
        self.settings["auto_block"] = bool(self.var_auto_block.get())
        self.settings["whitelist_ips"] = self.var_whitelist.get().strip()

        self.settings["ids_ml_threshold"] = float(self.var_ml_threshold.get() or 0.25)
        self.settings["ids_ml_contamination"] = float(
            self.var_ml_contamination.get() or 0.06
        )
        self.settings["ids_signature_enabled"] = bool(
            self.var_ids_sig_enabled.get()
        )
        self.settings["ids_ml_enabled"] = bool(self.var_ids_ml_enabled.get())

        self.settings["language"] = self.var_language.get()
        self.settings["theme"] = self.var_theme.get()
        self.settings["alert_sound_enabled"] = bool(
            self.var_alert_sound_enabled.get()
        )
        self.settings["right_log_enabled"] = bool(self.var_right_log_enabled.get())

        try:
            save_settings(self.settings)
        except Exception as e:
            messagebox.showerror("Settings", f"Failed to save:\n{e}")
            return

        messagebox.showinfo("Settings", "Settings saved. Restart app for theme change.")

    # =================================================================
    # Misc
    # =================================================================
    def _on_tab_changed(self, event=None) -> None:
        cur = self.nb.select()
        if cur == str(self.tab_alerts) and self._alerts_tab_starred:
            self._alerts_tab_starred = False
            self.nb.tab(self.tab_alerts, text=tr("tab.alerts", self.language))


if __name__ == "__main__":
    init_storage()
    app = NetBotKaliGUI()
    app.mainloop()
