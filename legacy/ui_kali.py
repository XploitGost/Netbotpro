# ui_kali.py - NetBotPRO Kali Edition UI (Sniffer + IDS + Graphs)
from __future__ import annotations

import os
import json
import queue
import threading
import sqlite3
import platform
import subprocess
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple, Callable

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from config.settings_manager import load_settings, save_settings
from core.core_sniffer import NetSniffer
from core.firewall_tools import block_ip
from core.ids_ml import MLIDS
from core.ids_rules_engine import RuleEngine
from core.ids_signature import SignatureIDS
from core.offline_analyzer import analyze_pcap_file
from core.traceroute_tools import run_traceroute
from legacy.charts import StatsChart
from legacy.filter_engine import make_packet_filter
from legacy.themes import apply_theme
from log_manager import (
    export_session_zip,
    DB_PATH,
    export_packets_csv,
    export_packets_excel,
    export_alerts_pdf,
    export_full_html_report,
    export_all_history_zip,
    open_logs_folder,
    init_storage,
    insert_packet,
    insert_alert,
    set_persist,
    cleanup_retention,
    is_persist_enabled,
)

try:
    from legacy.i18n import tr
except Exception:  # fallback if i18n not available
    def tr(key: str, lang: str = "fa") -> str:
        return key


LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# Live table row limits
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
    """
    Main Kali Edition UI.

    - Sniffer + Pause/Resume/Stop
    - Auto-follow last packet
    - Alerts tab + optional grouping + optional auto-block
    - Stats / Graph
    - TraceRoute
    - Offline PCAP analyzer
    - Logs/History
    - IDS Rules
    - Settings / Profiles
    """

    def __init__(self) -> None:
        super().__init__()

        # --- Settings ---
        try:
            self.settings: Dict[str, Any] = load_settings() or {}
        except Exception:
            self.settings = {}

        # --- Privacy / Storage (default: no persistent traces) ---
        self.persist_logs = bool(self.settings.get("persist_logs", False))
        try:
            self.retention_minutes = int(self.settings.get("retention_minutes", 0) or 0)
        except Exception:
            self.retention_minutes = 0
        self.mask_ip_logs = bool(self.settings.get("mask_ip_logs", False))

        # Apply persistence toggle globally (log_manager)
        try:
            set_persist(self.persist_logs)
        except Exception:
            pass

        # --- DB init (ONLY if persistence is enabled) ---
        if self.persist_logs:
            try:
                init_storage()
                if self.retention_minutes > 0:
                    cleanup_retention(self.retention_minutes)
            except Exception as e:
                print("[init_storage] warning:", e)


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

        # Generic settings flags
        self.autostart_sniffer = bool(self.settings.get("autostart_sniffer", False))
        self.auto_block = bool(self.settings.get("auto_block", False))
        self.whitelist_ips = self.settings.get("whitelist_ips", "127.0.0.1, 192.168.1.1")

        self.ids_signature_enabled = bool(self.settings.get("ids_signature_enabled", True))
        self.ids_ml_enabled = bool(self.settings.get("ids_ml_enabled", True))
        self.ids_ml_threshold = float(self.settings.get("ids_ml_threshold", 0.25))
        self.ids_ml_contamination = float(self.settings.get("ids_ml_contamination", 0.06))

        self.alert_sound_enabled = bool(self.settings.get("alert_sound_enabled", True))
        self.right_log_enabled = bool(self.settings.get("right_log_enabled", True))

        # --- UI vars (must exist before building tabs) ---
        self.group_alerts_var = tk.BooleanVar(value=bool(self.settings.get("group_alerts", True)))
        self.safe_mode_var = tk.BooleanVar(value=bool(self.settings.get("safe_mode", True)))

        # --- Sniffer / IDS state ---
        self.sniffer_engine: Optional[NetSniffer] = None
        self.sniffer_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=8000)
        self.sniffer_running = False
        self.sniffer_paused = False
        self.sniffer_iface_current: Optional[str] = None

        self.sniffer_filter_expr = tk.StringVar(value="")
        self.sniffer_filter_func: Callable[[Dict[str, Any]], bool] = make_packet_filter("")

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

        # Live table storage
        self.sniffer_rows: List[str] = []
        self.sniffer_meta_by_item: Dict[str, Dict[str, Any]] = {}
        self._session_traceroute_rows: list[dict] = []  # last traceroute result (in-memory)

        self.alert_rows: List[str] = []
        self.alert_meta_by_item: Dict[str, Dict[str, Any]] = {}  # <--- REQUIRED

        # Grouping state
        self.alert_group_index: Dict[tuple, str] = {}
        self.alert_group_count: Dict[tuple, int] = {}

        # Simple counts for dashboard
        self.counter_src: Counter[str] = Counter()
        self.counter_dst: Counter[str] = Counter()
        self.counter_proto: Counter[str] = Counter()

        # ML status
        self.ml_samples_seen = 0
        self.ml_last_score = 0.0

        # Dashboard labels
        self.dashboard_total_packets = tk.StringVar(value="0")
        self.dashboard_total_alerts = tk.StringVar(value="0")
        self.dashboard_top_src = tk.StringVar(value="-")
        self.dashboard_top_dst = tk.StringVar(value="-")
        self.dashboard_top_proto = tk.StringVar(value="-")

        # ML labels
        self.ml_status_label = tk.StringVar(value="Idle")
        self.ml_samples_label = tk.StringVar(value="0")
        self.ml_lastscore_label = tk.StringVar(value="0.000")

        self._alerts_tab_starred = False

        # Graph throttling
        self._chart_every_n_packets = 10
        self._chart_packet_counter = 0

        # Auto-follow last packet (Treeview)
        self.auto_follow_tail = tk.BooleanVar(value=True)

        # TraceRoute control
        self._tr_cancel_event = threading.Event()
        self._tr_running = False

        # DB worker queue (ONLY if persistence is enabled)
        self.db_queue: Optional["queue.Queue[Tuple[Dict[str, Any], List[Dict[str, Any]]]]"] = None
        if self.persist_logs:
            self.db_queue = queue.Queue(maxsize=10000)
            threading.Thread(target=self._db_worker, daemon=True).start()

        # Retention cleanup ticker (optional)
        if self.persist_logs and self.retention_minutes > 0:
            self.after(60_000, self._retention_tick)

        # --- Build UI ---
        self._build_layout()

        # Context menus (lazy init in handlers)
        self._sniffer_ctx_menu = None
        self._alert_menu = None

        try:
            self.state("zoomed")
        except Exception:
            pass

        # Autostart sniffer if desired
        if self.autostart_sniffer:
            self.after(800, self.start_sniffer_ui)

        # Poll sniffer queue forever
        self.after(150, self._poll_sniffer_queue)

    # ------------------------------------------------------------------
    # Helper widgets
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
            ttk.Label(frame, textvariable=var, font=get_font(18, True)).pack(padx=8, pady=8)

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
        ttk.Button(btns, text="Start", command=self.start_sniffer_ui).pack(side="left", padx=2)
        ttk.Button(btns, text="Pause", command=self.pause_sniffer_ui).pack(side="left", padx=2)
        ttk.Button(btns, text="Resume", command=self.resume_sniffer_ui).pack(side="left", padx=2)
        ttk.Button(btns, text="Stop", command=self.stop_sniffer_ui).pack(side="left", padx=2)
        ttk.Button(btns, text="Clear", command=self.clear_sniffer_table).pack(side="left", padx=2)
        ttk.Button(btns, text="Export HTML", command=self._export_html_report).pack(side="left", padx=2)

        # Filter row
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
        ttk.Button(filt, text="Reset", command=self._reset_filter).pack(side="left", padx=2)
        ttk.Button(filt, text="Follow selected", command=self._follow_selected_sniffer).pack(side="left", padx=8)
        ttk.Button(filt, text="Stop follow", command=self._stop_follow).pack(side="left", padx=2)

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

        cols = ("#", "time", "src", "dst", "proto", "sport", "dport", "country", "len", "proc", "alert")
        self.sniffer_table = ttk.Treeview(left, columns=cols, show="headings", selectmode="browse")
        widths = (55, 80, 150, 150, 70, 70, 70, 80, 70, 120, 60)
        for c, w in zip(cols, widths):
            self.sniffer_table.heading(c, text=c.upper())
            self.sniffer_table.column(c, width=w, anchor="w")

        try:
            self.sniffer_table.tag_configure("proto_TCP", foreground="#38bdf8")
            self.sniffer_table.tag_configure("proto_UDP", foreground="#a855f7")
            self.sniffer_table.tag_configure("proto_ICMP", foreground="#22c55e")
            self.sniffer_table.tag_configure("alert_row", background="#3b0d0d", foreground="#fee2e2")
        except Exception:
            pass

        vsb = ttk.Scrollbar(left, orient="vertical", command=self.sniffer_table.yview)
        self.sniffer_table.configure(yscrollcommand=vsb.set)
        self.sniffer_table.pack(side="left", fill="both", expand=True)
        vsb.pack(side="left", fill="y")

        self.sniffer_table.bind("<<TreeviewSelect>>", self._on_sniffer_row_select)
        self.sniffer_table.bind("<Button-3>", self._on_sniffer_right_click)
        self.sniffer_table.bind("<Control-c>", self._copy_from_tree, add="+")
        self.sniffer_table.bind("<MouseWheel>", self._on_sniffer_scroll, add="+")
        self.sniffer_table.bind("<Button-4>", self._on_sniffer_scroll, add="+")
        self.sniffer_table.bind("<Button-5>", self._on_sniffer_scroll, add="+")

        # Right panel
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
        ttk.Button(btns, text="Follow selected", command=self._follow_selected_alert).pack(side="left", padx=2)
        ttk.Button(btns, text="Stop follow", command=self._stop_follow).pack(side="left", padx=2)
        ttk.Checkbutton(btns, text="Group alerts", variable=self.group_alerts_var).pack(side="left", padx=10)
        ttk.Button(btns, text="Clear", command=self.clear_alerts).pack(side="left", padx=2)

        box = ttk.Labelframe(frame, text="Alerts")
        box.pack(fill="both", expand=True, padx=6, pady=4)

        cols = ("time", "src", "dst", "proto", "dport", "attack", "score", "engine")
        self.alerts_table = ttk.Treeview(box, columns=cols, show="headings")
        widths = (80, 150, 150, 70, 70, 260, 120, 80)
        for c, w in zip(cols, widths):
            self.alerts_table.heading(c, text=c.upper())
            self.alerts_table.column(c, width=w, anchor="w")
        self.alerts_table.pack(fill="both", expand=True)
        self.alerts_table.bind("<Double-1>", self._on_alert_double_click)
        self.alerts_table.bind("<<TreeviewSelect>>", lambda e: self._update_alert_details(self.alerts_table.selection()[0]) if self.alerts_table.selection() else None)
        self.alerts_table.bind("<Control-c>", self._copy_from_tree, add="+")
        self.alerts_table.bind("<Button-3>", self._on_alert_right_click)

        details = ttk.Labelframe(frame, text="Alert details")
        details.pack(fill="x", padx=6, pady=(0, 6))
        self.alert_details_var = tk.StringVar(value="")
        ttk.Label(details, textvariable=self.alert_details_var, wraplength=1100, justify="left").pack(anchor="w", padx=6, pady=6)

    def _update_alert_details(self, item_id: str) -> None:
        data = self.alert_meta_by_item.get(item_id) or {}
        meta = data.get("meta") or {}
        alert = data.get("alert") or {}
        if not meta and not alert:
            self.alert_details_var.set("")
            return
        lines = []
        atk = alert.get("attack_type") or alert.get("attack") or "Alert"
        lines.append(f"Attack: {atk}")
        lines.append(f"Engine: {alert.get('engine') or 'IDS'}")
        try:
            lines.append(f"Score: {float(alert.get('score', 0.0)):.3f}")
        except Exception:
            lines.append(f"Score: {alert.get('score')}")
        lines.append(f"Flow: {meta.get('src')} -> {meta.get('dst')} ({meta.get('proto')}) dport={meta.get('dport')}")
        det = alert.get("detail") or meta.get("summary")
        if det:
            lines.append("")
            lines.append(str(det))
        self.alert_details_var.set("\n".join(lines))

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
        self.tr_mode_var = tk.StringVar(value=str(self.settings.get("tr_mode", "UDP")))
        self.tr_timeout_var = tk.StringVar(value=str(self.settings.get("tr_timeout", 1.5)))
        self.tr_maxhops_var = tk.StringVar(value=str(self.settings.get("tr_max_hops", 30)))
        self.tr_queries_var = tk.StringVar(value=str(self.settings.get("tr_queries", 1)))
        self.tr_port_var = tk.StringVar(value=str(self.settings.get("tr_port", 443)))

        ttk.Label(row, text=tr("tr.target", self.language)).pack(side="left")
        ttk.Entry(row, textvariable=self.tr_target).pack(side="left", fill="x", expand=True)

        ttk.Label(row, text="  Mode:").pack(side="left", padx=(10, 2))
        ttk.Combobox(row, textvariable=self.tr_mode_var, values=("ICMP", "UDP", "TCP"), width=6, state="readonly").pack(side="left")

        ttk.Label(row, text="  Timeout(s):").pack(side="left", padx=(10, 2))
        ttk.Entry(row, textvariable=self.tr_timeout_var, width=6).pack(side="left")

        ttk.Label(row, text="  MaxHops:").pack(side="left", padx=(10, 2))
        ttk.Entry(row, textvariable=self.tr_maxhops_var, width=4).pack(side="left")

        ttk.Label(row, text="  Queries:").pack(side="left", padx=(10, 2))
        ttk.Entry(row, textvariable=self.tr_queries_var, width=3).pack(side="left")

        ttk.Label(row, text="  Port:").pack(side="left", padx=(10, 2))
        ttk.Entry(row, textvariable=self.tr_port_var, width=6).pack(side="left")

        self.btn_tr_run = ttk.Button(row, text=tr("tr.run", self.language), command=self.run_traceroute_ui)
        self.btn_tr_run.pack(side="left", padx=6)
        self.btn_tr_stop = ttk.Button(row, text="Stop", command=self.stop_traceroute_ui, state="disabled")
        self.btn_tr_stop.pack(side="left", padx=2)

        self.tr_progress = ttk.Progressbar(frame, mode="indeterminate")
        self.tr_progress.pack(fill="x", padx=6, pady=(0, 4))

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

    # ---------------- Offline Analyzer ----------------
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
        ttk.Entry(row, textvariable=self.offline_path).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Browse", command=self._browse_pcap).pack(side="left", padx=4)
        ttk.Button(row, text="Analyze", command=self._run_offline_analyzer).pack(side="left", padx=4)

        box = ttk.Labelframe(frame, text="Offline alerts")
        box.pack(fill="both", expand=True, padx=6, pady=4)
        cols = ("time", "src", "dst", "proto", "dport", "attack", "score")
        self.offline_alerts_table = ttk.Treeview(box, columns=cols, show="headings")
        for c in cols:
            self.offline_alerts_table.heading(c, text=c.upper())
            self.offline_alerts_table.column(c, width=120, anchor="w")
        self.offline_alerts_table.pack(fill="both", expand=True)
        self.offline_alerts_table.bind("<Control-c>", self._copy_from_tree, add="+")

        summary = ttk.Labelframe(frame, text="Offline summary")
        summary.pack(fill="x", padx=6, pady=(0, 6))
        left = ttk.Frame(summary); left.pack(side="left", fill="x", expand=True, padx=4, pady=4)
        right = ttk.Frame(summary); right.pack(side="left", fill="x", expand=True, padx=4, pady=4)

        ttk.Label(left, text="Top IPs").pack(anchor="w")
        self.offline_top_ips = ttk.Treeview(left, columns=("ip", "count"), show="headings", height=5)
        self.offline_top_ips.heading("ip", text="IP"); self.offline_top_ips.heading("count", text="COUNT")
        self.offline_top_ips.column("ip", width=220, anchor="w"); self.offline_top_ips.column("count", width=80, anchor="w")
        self.offline_top_ips.pack(fill="x", expand=True)

        ttk.Label(right, text="Timeline (minute → alerts)").pack(anchor="w")
        self.offline_timeline = ttk.Treeview(right, columns=("time", "count"), show="headings", height=5)
        self.offline_timeline.heading("time", text="TIME"); self.offline_timeline.heading("count", text="COUNT")
        self.offline_timeline.column("time", width=120, anchor="w"); self.offline_timeline.column("count", width=80, anchor="w")
        self.offline_timeline.pack(fill="x", expand=True)

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
        ttk.Button(btns, text="Refresh", command=self._refresh_logs_ui).pack(side="left", padx=2)
        ttk.Button(btns, text="Open folder", command=open_logs_folder).pack(side="left", padx=2)
        ttk.Button(btns, text="Export CSV", command=self._export_csv).pack(side="left", padx=2)
        ttk.Button(btns, text="Export Excel", command=self._export_xlsx).pack(side="left", padx=2)
        ttk.Button(btns, text="Export PDF", command=self._export_pdf).pack(side="left", padx=2)
        ttk.Button(btns, text="Export HTML", command=self._export_full_html).pack(side="left", padx=2)
        ttk.Button(btns, text="Export ZIP", command=self._export_zip).pack(side="left", padx=2)
        ttk.Button(btns, text="Export ALL ZIP", command=self._export_all_history_zip).pack(side="left", padx=8)

        # Privacy: if persistence is disabled, disable logs/export UI (no traces).
        if not getattr(self, 'persist_logs', False):
            ttk.Label(
                frame,
                text="Persistence is disabled (no DB traces). Enable it in Settings → Privacy/Storage to view/export logs.",
                foreground=self.danger,
            ).pack(anchor="w", padx=6, pady=(6, 2))
            try:
                for w in btns.winfo_children():
                    w.configure(state="disabled")
            except Exception:
                pass


        filt = ttk.Frame(frame)
        filt.pack(fill="x", padx=6, pady=(0, 4))
        ttk.Label(filt, text="Logs filter:").pack(side="left")
        self.logs_src_var = tk.StringVar(value="")
        self.logs_dst_var = tk.StringVar(value="")
        self.logs_attack_var = tk.StringVar(value="")
        self.logs_min_score_var = tk.StringVar(value="")
        ttk.Label(filt, text="src").pack(side="left", padx=(8, 2))
        ttk.Entry(filt, textvariable=self.logs_src_var, width=14).pack(side="left")
        ttk.Label(filt, text="dst").pack(side="left", padx=(8, 2))
        ttk.Entry(filt, textvariable=self.logs_dst_var, width=14).pack(side="left")
        ttk.Label(filt, text="attack").pack(side="left", padx=(8, 2))
        ttk.Entry(filt, textvariable=self.logs_attack_var, width=16).pack(side="left")
        ttk.Label(filt, text="min_score").pack(side="left", padx=(8, 2))
        ttk.Entry(filt, textvariable=self.logs_min_score_var, width=6).pack(side="left")
        ttk.Button(filt, text="Apply", command=self._refresh_logs_ui).pack(side="left", padx=8)
        ttk.Button(filt, text="Clear", command=self._clear_logs_filters).pack(side="left")

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
            self.logs_alerts.column(c, width=120, anchor="w")
        self.logs_alerts.pack(fill="both", expand=True)
        self.logs_alerts.bind("<Control-c>", self._copy_from_tree, add="+")

        # Do not auto-load historical logs on startup.
        # This avoids showing old DB content before the user explicitly asks for it.
        if getattr(self, 'persist_logs', False):
            ttk.Label(
                frame,
                text="Tip: Click Refresh to load saved history from SQLite.",
                foreground="#A0A0A0",
            ).pack(anchor="w", padx=10, pady=(0, 6))

    def _clear_logs_filters(self) -> None:
        self.logs_src_var.set("")
        self.logs_dst_var.set("")
        self.logs_attack_var.set("")
        self.logs_min_score_var.set("")
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
        ttk.Button(btns, text="Reload from file", command=self._rules_load_from_file).pack(side="left", padx=2)
        ttk.Button(btns, text="Save", command=self._rules_save_to_file).pack(side="left", padx=2)
        ttk.Button(btns, text="Validate JSON", command=self._lint_rules_text).pack(side="left", padx=10)

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
        ttk.Checkbutton(row2, text="Autostart sniffer on launch", variable=self.var_autostart).pack(side="left")
        ttk.Label(row2, text="  Profile:").pack(side="left", padx=(14, 2))
        self.var_profile = tk.StringVar(value=self.settings.get("profile", "Safe"))
        ttk.Combobox(row2, textvariable=self.var_profile, values=("Safe", "Home", "Office", "Pentest"), width=8, state="readonly").pack(side="left")
        ttk.Button(row2, text="Apply", command=lambda: self._apply_profile(self.var_profile.get())).pack(side="left", padx=6)

        row3 = ttk.Frame(gen)
        row3.pack(fill="x", pady=2)
        ttk.Checkbutton(row3, text="Auto-block high risk IPs", variable=self.var_auto_block).pack(side="left")
        ttk.Checkbutton(row3, text="Safe mode (prefer temp-block)", variable=self.safe_mode_var).pack(side="left", padx=18)

        row4 = ttk.Frame(gen)
        row4.pack(fill="x", pady=2)
        ttk.Label(row4, text="Whitelist IPs (comma):").pack(side="left")
        ttk.Entry(row4, textvariable=self.var_whitelist, width=50).pack(side="left", padx=4)

        ids = ttk.Labelframe(frame, text="IDS / ML")
        ids.pack(fill="x", padx=6, pady=4)

        self.var_ml_threshold = tk.DoubleVar(value=self.ids_ml_threshold)
        self.var_ml_contamination = tk.DoubleVar(value=self.ids_ml_contamination)
        self.var_ids_sig_enabled = tk.BooleanVar(value=self.ids_signature_enabled)
        self.var_ids_ml_enabled = tk.BooleanVar(value=self.ids_ml_enabled)

        row5 = ttk.Frame(ids)
        row5.pack(fill="x", pady=2)
        ttk.Label(row5, text="ML threshold:").pack(side="left")
        ttk.Entry(row5, textvariable=self.var_ml_threshold, width=8).pack(side="left", padx=4)

        row6 = ttk.Frame(ids)
        row6.pack(fill="x", pady=2)
        ttk.Label(row6, text="ML contamination:").pack(side="left")
        ttk.Entry(row6, textvariable=self.var_ml_contamination, width=8).pack(side="left", padx=4)

        row7 = ttk.Frame(ids)
        row7.pack(fill="x", pady=2)
        ttk.Checkbutton(row7, text="Enable signature IDS", variable=self.var_ids_sig_enabled).pack(side="left")
        ttk.Checkbutton(row7, text="Enable ML IDS", variable=self.var_ids_ml_enabled).pack(side="left", padx=20)

        ui_box = ttk.Labelframe(frame, text="UI")
        ui_box.pack(fill="x", padx=6, pady=4)

        self.var_language = tk.StringVar(value=self.language)
        self.var_theme = tk.StringVar(value=self.theme_name)
        self.var_alert_sound_enabled = tk.BooleanVar(value=self.alert_sound_enabled)
        self.var_right_log_enabled = tk.BooleanVar(value=self.right_log_enabled)

        row8 = ttk.Frame(ui_box)
        row8.pack(fill="x", pady=2)
        ttk.Label(row8, text="Language:").pack(side="left")
        ttk.Combobox(row8, textvariable=self.var_language, values=("fa", "en"), width=6, state="readonly").pack(side="left", padx=4)
        ttk.Label(row8, text="Theme:").pack(side="left", padx=(20, 2))
        ttk.Combobox(row8, textvariable=self.var_theme, values=("dark", "light"), width=8, state="readonly").pack(side="left", padx=4)

        row9 = ttk.Frame(ui_box)
        row9.pack(fill="x", pady=2)
        ttk.Checkbutton(row9, text="Play sound on alert", variable=self.var_alert_sound_enabled).pack(side="left")
        ttk.Checkbutton(row9, text="Show right-side sniffer log", variable=self.var_right_log_enabled).pack(side="left", padx=20)

        # ---------------- Privacy / Storage ----------------
        privacy = ttk.Labelframe(frame, text="Privacy / Storage")
        privacy.pack(fill="x", padx=6, pady=4)

        self.var_persist_logs = tk.BooleanVar(value=bool(getattr(self, 'persist_logs', False)))
        try:
            _rm = int(getattr(self, 'retention_minutes', 0) or 0)
        except Exception:
            _rm = 0
        self.var_retention_minutes = tk.IntVar(value=_rm)
        self.var_mask_ip_logs = tk.BooleanVar(value=bool(getattr(self, 'mask_ip_logs', False)))

        rowp = ttk.Frame(privacy)
        rowp.pack(fill="x", pady=2)
        ttk.Checkbutton(rowp, text="Enable persistent logs (SQLite)", variable=self.var_persist_logs).pack(side="left")
        ttk.Label(rowp, text="Retention (minutes):").pack(side="left", padx=(18, 2))
        ttk.Entry(rowp, textvariable=self.var_retention_minutes, width=6).pack(side="left")
        ttk.Checkbutton(rowp, text="Mask IPs in DB (x.x.x.0)", variable=self.var_mask_ip_logs).pack(side="left", padx=18)
        ttk.Label(
            privacy,
            text="Tip: keep persistence OFF for no traces. Logs/exports require persistence ON.",
        ).pack(anchor="w", padx=6, pady=(2, 4))

        bottom = ttk.Frame(frame)
        bottom.pack(fill="x", padx=6, pady=8)
        ttk.Button(bottom, text="Save settings", command=self._save_settings).pack(side="right")

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
        self.sniffer_iface_current = iface
        try:
            self.sniffer_engine = NetSniffer(self._on_sniffer_packet)
            self.sniffer_engine.start(iface=iface)
            self.sniffer_running = True
            self.sniffer_paused = False
            self.status_var.set(f"Sniffer running on {iface}")
        except Exception as e:
            self.sniffer_engine = None
            self.sniffer_running = False
            self.sniffer_paused = False
            messagebox.showerror("Sniffer", f"Failed to start sniffer:\n{e}")

    def pause_sniffer_ui(self) -> None:
        if not self.sniffer_running or self.sniffer_paused:
            return
        self.sniffer_paused = True
        self.status_var.set("Sniffer paused")

    def resume_sniffer_ui(self) -> None:
        if not self.sniffer_running or not self.sniffer_paused:
            return
        self.sniffer_paused = False
        iface = self.sniffer_iface_current or self.settings.get("iface", "iface=default")
        self.status_var.set(f"Sniffer resumed on {iface}")

    def stop_sniffer_ui(self) -> None:
        eng = self.sniffer_engine
        self.sniffer_engine = None
        self.sniffer_running = False
        self.sniffer_paused = False
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
        if self.sniffer_paused:
            try:
                self.sniffer_queue.get_nowait()
            except queue.Empty:
                pass
            return
        try:
            self.sniffer_queue.put_nowait(meta)
        except queue.Full:
            try:
                self.sniffer_queue.get_nowait()
            except queue.Empty:
                pass

    def _poll_sniffer_queue(self) -> None:
        if self.sniffer_paused:
            try:
                for _ in range(50):
                    self.sniffer_queue.get_nowait()
            except queue.Empty:
                pass
            self.after(150, self._poll_sniffer_queue)
            return

        qsize = self.sniffer_queue.qsize()
        if qsize > 4000:
            drop_n = qsize - 3000
            for _ in range(drop_n):
                try:
                    self.sniffer_queue.get_nowait()
                except queue.Empty:
                    break

        processed = 0
        max_per_tick = 40
        while processed < max_per_tick:
            try:
                meta = self.sniffer_queue.get_nowait()
            except queue.Empty:
                break
            self._handle_packet(meta)
            processed += 1

        self.after(150, self._poll_sniffer_queue)

    def _handle_packet(self, meta: Dict[str, Any]) -> None:
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

        try:
            if self.ids_signature_enabled:
                a1 = self.ids_sig.analyze_packet(meta)
                if a1:
                    a1["engine"] = "SIG"
                    alerts.append(a1)
        except Exception:
            pass

        try:
            a2 = self.rule_engine.analyze(meta)
            if a2:
                a2["engine"] = "RULE"
                alerts.append(a2)
        except Exception:
            pass

        try:
            if self.ids_ml_enabled:
                self.ml_samples_seen += 1
                a3 = self.ids_ml.analyze_packet(meta, threshold=self.ids_ml_threshold)
                self.ml_status_label.set("Training / Active")
                if a3:
                    a3["engine"] = "ML"
                    alerts.append(a3)
                    try:
                        self.ml_last_score = float(a3.get("score", 0.0))
                    except Exception:
                        pass
        except Exception:
            pass

        self.ml_samples_label.set(str(self.ml_samples_seen))
        self.ml_lastscore_label.set(f"{self.ml_last_score:.3f}")

        has_alert = bool(alerts)

        self._log_packet_and_alerts(meta, alerts)

        try:
            self._chart_packet_counter += 1
            if self._chart_packet_counter >= self._chart_every_n_packets:
                self.stats_chart.update_with_packet(meta, self.total_packets, self.total_alerts, has_alert=has_alert)
                self._chart_packet_counter = 0
        except Exception:
            pass

        try:
            if self.sniffer_filter_func and not self.sniffer_filter_func(meta):
                return
        except Exception:
            pass

        self._append_sniffer_row(meta, has_alert=has_alert)

        for a in alerts:
            self._add_alert(meta, a)

    def _log_packet_and_alerts(self, meta: Dict[str, Any], alerts: List[Dict[str, Any]]) -> None:
        if (not getattr(self, 'persist_logs', False)) or (self.db_queue is None):
            return

        def _mask_ip(ip: Any) -> Any:
            if not getattr(self, 'mask_ip_logs', False):
                return ip
            if not ip or not isinstance(ip, str):
                return ip
            if ':' in ip:  # IPv6: keep as-is (or implement masking later)
                return ip
            parts = ip.split('.')
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                return '.'.join(parts[:3] + ['0'])
            return ip

        src = _mask_ip(meta.get('src'))
        dst = _mask_ip(meta.get('dst'))

        row_p = {
            "ts": meta.get("ts"),
            "src": src,
            "dst": dst,
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
                "src": src,
                "dst": dst,
                "proto": meta.get("proto"),
                "attack_type": a.get("attack_type") or a.get("attack") or "Alert",
                "score": float(a.get("score", 0.0)),
                "detail": a.get("detail") or meta.get("summary"),
            }
            alert_rows.append(row_a)

        try:
            self.db_queue.put_nowait((row_p, alert_rows))
        except queue.Full:
            pass

    def _db_worker(self) -> None:
        if self.db_queue is None:
            return
        q = self.db_queue

        while True:
            try:
                packet_row, alert_rows = q.get()
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

        tags: List[str] = []
        proto_tag = (meta.get("proto") or "").upper()
        if proto_tag in ("TCP", "UDP", "ICMP"):
            tags.append(f"proto_{proto_tag}")
        if has_alert:
            tags.append("alert_row")

        kwargs: Dict[str, Any] = {"values": values}
        if tags:
            kwargs["tags"] = tuple(tags)

        item_id = tv.insert("", "end", **kwargs)
        self.sniffer_rows.append(item_id)
        self.sniffer_meta_by_item[item_id] = dict(meta)

        try:
            if self.auto_follow_tail.get():
                tv.see(item_id)
                tv.yview_moveto(1.0)
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
                    f"[{meta.get('ts')}] {meta.get('src')} -> {meta.get('dst')} {meta.get('proto')} len={meta.get('length')}{extra}\n",
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
        lines.append(f"Country: {val(country_name, 'Unknown')} ({val(country_code, '-')})")
        lines.append(f"City/Org: {val(meta.get('city'), 'Unknown')} / {val(meta.get('org'), 'Unknown')}")
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

    # ---------------- Context / follow ----------------
    def _ensure_sniffer_context_menu(self) -> None:
        if self._sniffer_ctx_menu is not None:
            return
        m = tk.Menu(self, tearoff=0)
        m.add_command(label="Follow SRC", command=lambda: self._follow_ip("src"))
        m.add_command(label="Follow DST", command=lambda: self._follow_ip("dst"))
        m.add_command(label="Follow 5-tuple", command=self._follow_5tuple)
        m.add_separator()
        m.add_command(label="Stop follow", command=self._stop_follow)
        self._sniffer_ctx_menu = m

    def _on_sniffer_right_click(self, event) -> None:
        row_id = self.sniffer_table.identify_row(event.y)
        if not row_id:
            return
        self.sniffer_table.selection_set(row_id)
        self._ensure_sniffer_context_menu()
        try:
            self._sniffer_ctx_menu.tk_popup(event.x_root, event.y_root)  # type: ignore
        finally:
            try:
                self._sniffer_ctx_menu.grab_release()  # type: ignore
            except Exception:
                pass

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
        self._apply_filter_expr(" and ".join(parts))

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
        self._apply_filter_expr(" and ".join(parts))
        self.nb.select(self.tab_sniffer)

    def _on_alert_double_click(self, event) -> None:
        self._follow_selected_alert()

    def _on_sniffer_scroll(self, event=None) -> None:
        try:
            self.auto_follow_tail.set(False)
        except Exception:
            pass
        return None

    def _stop_follow(self) -> None:
        # Stop tail-follow only; keep user's filter intact
        try:
            self.auto_follow_tail.set(False)
        except Exception:
            pass
        self.status_var.set("Follow stopped.")

    # =================================================================
    # Alerts table / notifications
    # =================================================================
    def clear_alerts(self) -> None:
        for item in self.alerts_table.get_children():
            self.alerts_table.delete(item)
        self.alert_rows.clear()
        self.alert_meta_by_item.clear()
        self.alert_group_index.clear()
        self.alert_group_count.clear()
        self.total_alerts = 0
        self.status_alerts.set("Alerts: 0")
        self.dashboard_total_alerts.set("0")

    def _format_conf_bar(self, score: float, width: int = 10) -> str:
        s = max(0.0, min(1.0, float(score)))
        filled = int(round(s * width))
        return f"{s:.3f} " + ("█" * filled) + ("░" * (width - filled))

    def _alert_key(self, meta: Dict[str, Any], alert: Dict[str, Any]) -> tuple:
        return (
            meta.get("src"),
            alert.get("attack_type") or alert.get("attack") or "Alert",
            meta.get("dport"),
            alert.get("engine") or "IDS",
        )

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
            self._format_conf_bar(float(alert.get("score", 0.0))),
            alert.get("engine") or "IDS",
        )

        key = self._alert_key(meta, alert)
        if self.group_alerts_var.get():
            if key in self.alert_group_index:
                item_id = self.alert_group_index[key]
                self.alert_group_count[key] = self.alert_group_count.get(key, 1) + 1
                cnt = self.alert_group_count[key]
                cur = list(self.alerts_table.item(item_id).get("values", vals))
                cur[5] = f"[{cnt}] " + str(cur[5]).split("] ", 1)[-1]
                self.alerts_table.item(item_id, values=cur)
            else:
                item_id = self.alerts_table.insert("", "end", values=vals)
                self.alert_group_index[key] = item_id
                self.alert_group_count[key] = 1
        else:
            item_id = self.alerts_table.insert("", "end", values=vals)

        self.alert_meta_by_item[item_id] = {"meta": meta, "alert": alert}
        self.alert_rows.append(item_id)

        if len(self.alert_rows) > MAX_ALERT_ROWS:
            old = self.alert_rows.pop(0)
            try:
                self.alerts_table.delete(old)
            except Exception:
                pass
            self.alert_meta_by_item.pop(old, None)

        self._notify_alert(meta, alert)

        # Auto-block (high score)
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
        self.status_var.set(f"New alert: {src} -> {dst} ({proto}) {attack} score={score:.3f}")

        if not self._alerts_tab_starred:
            self._alerts_tab_starred = True
            self.nb.tab(self.tab_alerts, text="* " + tr("tab.alerts", self.language))

        if self.alert_sound_enabled:
            self._play_alert_sound()

    def _play_alert_sound(self) -> None:
        try:
            if os.path.exists(ALERT_SOUND_FILE):
                if platform.system().lower().startswith("win") and winsound is not None:
                    winsound.PlaySound(ALERT_SOUND_FILE, winsound.SND_FILENAME | winsound.SND_ASYNC)  # type: ignore
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

    # ---------------- Alert context menu ----------------
    def _ensure_alert_context_menu(self) -> None:
        if self._alert_menu is not None:
            return
        m = tk.Menu(self, tearoff=0)
        m.add_command(label="Block IP", command=self._ctx_block_selected_alert_ip)
        m.add_command(label="Add to whitelist", command=self._ctx_whitelist_selected_alert_ip)
        m.add_command(label="Trace this IP", command=self._ctx_trace_selected_alert_ip)
        m.add_separator()
        m.add_command(label="Copy as JSON", command=self._ctx_copy_selected_alert_json)
        self._alert_menu = m

    def _ctx_get_selected_alert(self):
        sel = self.alerts_table.selection()
        if not sel:
            return None, None, None
        item_id = sel[0]
        data = self.alert_meta_by_item.get(item_id) or {}
        meta = data.get("meta") or {}
        alert = data.get("alert") or {}
        return item_id, meta, alert

    def _ctx_block_selected_alert_ip(self) -> None:
        _, meta, _ = self._ctx_get_selected_alert()
        if not meta:
            return
        ip = meta.get("src")
        if not ip:
            return
        if messagebox.askyesno("Block IP", f"Block {ip}?"):
            try:
                if block_ip(ip):
                    self.status_var.set(f"Blocked: {ip}")
                else:
                    messagebox.showerror("Block IP", f"Failed to block {ip}")
            except Exception as e:
                messagebox.showerror("Block IP", str(e))

    def _ctx_whitelist_selected_alert_ip(self) -> None:
        _, meta, _ = self._ctx_get_selected_alert()
        if not meta:
            return
        ip = meta.get("src")
        if not ip:
            return
        raw = (self.var_whitelist.get() if hasattr(self, "var_whitelist") else "") or ""
        items = [p.strip() for p in raw.split(",") if p.strip()]
        if ip not in items:
            items.append(ip)
        new_val = ", ".join(items)
        try:
            self.var_whitelist.set(new_val)
        except Exception:
            self.whitelist_ips = new_val
        self.status_var.set(f"Whitelisted: {ip}")

    def _ctx_trace_selected_alert_ip(self) -> None:
        _, meta, _ = self._ctx_get_selected_alert()
        if not meta:
            return
        ip = meta.get("src")
        if not ip:
            return
        try:
            self.tr_target.set(ip)
        except Exception:
            pass
        try:
            self.nb.select(self.tab_tr)
        except Exception:
            pass
        try:
            self.run_traceroute_ui()
        except Exception:
            pass

    def _ctx_copy_selected_alert_json(self) -> None:
        item_id, meta, alert = self._ctx_get_selected_alert()
        if not item_id:
            return
        payload = {"meta": meta, "alert": alert}
        text = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
        self.clipboard_clear()
        self.clipboard_append(text)
        self.status_var.set("Alert JSON copied.")

    def _on_alert_right_click(self, event) -> None:
        self._ensure_alert_context_menu()
        row = self.alerts_table.identify_row(event.y)
        if row:
            self.alerts_table.selection_set(row)
            try:
                self._alert_menu.tk_popup(event.x_root, event.y_root)  # type: ignore
            finally:
                try:
                    self._alert_menu.grab_release()  # type: ignore
                except Exception:
                    pass

    # =================================================================
    # TraceRoute handlers
    # =================================================================
    def stop_traceroute_ui(self) -> None:
        """Request traceroute stop (best-effort)."""
        try:
            self._tr_cancel_event.set()
        except Exception:
            pass
        try:
            self.status_var.set("Traceroute: stop requested ...")
        except Exception:
            pass

    def run_traceroute_ui(self) -> None:
        target = self.tr_target.get().strip()
        if not target:
            messagebox.showwarning("TraceRoute", "Please enter host or IP.")
            return

        # Basic input hardening: avoid whitespace / path-like inputs
        if any(ch.isspace() for ch in target) or "/" in target or "\\" in target:
            messagebox.showerror("TraceRoute", "Invalid target. Use a host/IP without spaces or slashes.")
            return

        # Parse UI params (best-effort)
        try:
            mode = (self.tr_mode_var.get() or "UDP").strip().upper()
        except Exception:
            mode = "UDP"
        try:
            timeout = float(self.tr_timeout_var.get() or 1.5)
        except Exception:
            timeout = 1.5
        try:
            max_hops = int(self.tr_maxhops_var.get() or 30)
        except Exception:
            max_hops = 30
        try:
            queries = int(self.tr_queries_var.get() or 1)
        except Exception:
            queries = 1
        try:
            port = int(self.tr_port_var.get() or 443)
        except Exception:
            port = 443

        # reset UI
        for item in self.tr_table.get_children():
            self.tr_table.delete(item)
        self.tr_details.delete("1.0", "end")

        # start traceroute
        try:
            self._tr_cancel_event.clear()
        except Exception:
            pass
        self._tr_running = True
        try:
            self.btn_tr_run.configure(state="disabled")
            self.btn_tr_stop.configure(state="normal")
        except Exception:
            pass
        try:
            self.tr_progress.start(10)
        except Exception:
            pass

        self.status_var.set(f"Traceroute to {target} ({mode}) ...")

        def worker():
            hops = run_traceroute(
                target,
                mode=mode,
                timeout=timeout,
                max_hops=max_hops,
                queries=queries,
                port=port,
                cancel_event=self._tr_cancel_event,
            )
            self.after(0, lambda: self._traceroute_done(target, hops))

        threading.Thread(target=worker, daemon=True).start()

    def _traceroute_done(self, target: str, hops: List[Dict[str, Any]]) -> None:
        # stop progress / restore buttons
        cancelled = False
        try:
            cancelled = bool(self._tr_cancel_event.is_set())
        except Exception:
            cancelled = False
        try:
            self._tr_running = False
        except Exception:
            pass
        try:
            self.tr_progress.stop()
        except Exception:
            pass
        try:
            self.btn_tr_run.configure(state="normal")
            self.btn_tr_stop.configure(state="disabled")
        except Exception:
            pass

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
        if cancelled:
            self.status_var.set(f"Traceroute cancelled: {target}")
        else:
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
    # Offline analyzer
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
        if not os.path.isfile(path):
            messagebox.showerror("Offline", f"File not found: {path}")
            return

        for item in self.offline_alerts_table.get_children():
            self.offline_alerts_table.delete(item)
        for item in self.offline_top_ips.get_children():
            self.offline_top_ips.delete(item)
        for item in self.offline_timeline.get_children():
            self.offline_timeline.delete(item)

        self.status_var.set("Analyzing PCAP (offline) ...")

        def worker():
            try:
                result = analyze_pcap_file(path, ml_threshold=float(self.ids_ml_threshold))
            except Exception as e:
                def _err():
                    self.status_var.set("Offline analysis failed.")
                    messagebox.showerror("Offline", str(e))
                self.after(0, _err)
                return

            alerts = result.get("alerts") or []
            top_ips = result.get("top_ips") or []
            timeline = result.get("timeline") or []

            def _ui():
                for a in alerts:
                    self.offline_alerts_table.insert(
                        "",
                        "end",
                        values=(
                            a.get("ts") or a.get("time") or "",
                            a.get("src") or "",
                            a.get("dst") or "",
                            a.get("proto") or "",
                            str(a.get("dport") or ""),
                            a.get("attack_type") or a.get("attack") or "Alert",
                            f"{float(a.get('score', 0.0)):.3f}",
                        ),
                    )
                for r in top_ips[:20]:
                    self.offline_top_ips.insert("", "end", values=(r.get("ip"), r.get("count")))
                for r in timeline:
                    self.offline_timeline.insert("", "end", values=(r.get("time"), r.get("count")))
                self.status_var.set(f"Offline done: {len(alerts)} alerts.")
            self.after(0, _ui)

        threading.Thread(target=worker, daemon=True).start()

    # =================================================================
    # Logs / exports
    # =================================================================
    def _logs_build_where(self):
        clauses = []
        params = []
        if self.logs_src_var.get().strip():
            clauses.append("src LIKE ?")
            params.append("%" + self.logs_src_var.get().strip() + "%")
        if self.logs_dst_var.get().strip():
            clauses.append("dst LIKE ?")
            params.append("%" + self.logs_dst_var.get().strip() + "%")
        if self.logs_attack_var.get().strip():
            clauses.append("attack_type LIKE ?")
            params.append("%" + self.logs_attack_var.get().strip() + "%")
        if self.logs_min_score_var.get().strip():
            try:
                clauses.append("score >= ?")
                params.append(float(self.logs_min_score_var.get().strip()))
            except Exception:
                pass
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        return where, params


    def _refresh_logs_ui(self) -> None:
        # Always clear UI first
        for tv in (self.logs_packets, self.logs_alerts):
            for item in tv.get_children():
                tv.delete(item)

        # If persistence is OFF, show current session only (no old history).
        if not getattr(self, 'persist_logs', False):
            pkt = self._get_session_packets_for_logs()
            alt = self._get_session_alerts_for_logs()
            # packets
            for r in (pkt[-500:] if len(pkt) > 500 else pkt):
                self.logs_packets.insert('', 'end', values=(
                    '', r.get('ts'), r.get('src'), r.get('dst'), r.get('proto'), r.get('sport'), r.get('dport'), r.get('length')
                ))
            # alerts
            for r in (alt[-300:] if len(alt) > 300 else alt):
                self.logs_alerts.insert('', 'end', values=(
                    '', r.get('ts'), r.get('src'), r.get('dst'), r.get('proto'), r.get('attack_type'), f"{float(r.get('score',0.0)):.3f}"
                ))
            return

        # Persistence ON => read DB
        import sqlite3
        from log_manager import DB_PATH, init_storage

        conn = None
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute(
                "SELECT id, ts, src, dst, proto, sport, dport, length "
                "FROM packets ORDER BY id DESC LIMIT 500"
            )
            for row in cur.fetchall():
                self.logs_packets.insert('', 'end', values=row)

            where, params = self._logs_build_where()
            cur.execute(
                "SELECT id, ts, src, dst, proto, attack_type, score "
                "FROM alerts" + where + " ORDER BY id DESC LIMIT 300",
                params,
            )
            for row in cur.fetchall():
                self.logs_alerts.insert('', 'end', values=row)
        except sqlite3.OperationalError as e:
            if 'no such table' in str(e).lower():
                try:
                    init_storage()
                except Exception:
                    pass
            else:
                print('[refresh_logs] sqlite error:', e)
        except Exception as e:
            print('[refresh_logs] error:', e)
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
    def _get_session_packets_for_logs(self) -> list[dict]:
        # Build packet rows from current session (UI buffer), NOT DB.
        rows: list[dict] = []
        for iid in list(getattr(self, 'sniffer_rows', [])):
            meta = (getattr(self, 'sniffer_meta_by_item', {}) or {}).get(iid) or {}
            if not meta:
                continue
            rows.append({
                'ts': meta.get('ts'),
                'src': meta.get('src'),
                'dst': meta.get('dst'),
                'proto': meta.get('proto'),
                'sport': meta.get('sport'),
                'dport': meta.get('dport'),
                'length': meta.get('length'),
                'direction': meta.get('direction'),
                'summary': meta.get('summary'),
                'process_name': meta.get('process_name'),
                'pid': meta.get('pid'),
                'country': meta.get('country') or meta.get('country_code'),
                'city': meta.get('city'),
                'org': meta.get('org'),
                'asn': meta.get('asn'),
                'inside_outside': meta.get('inside_outside'),
                'l7': meta.get('l7'),
                'tls_sni': meta.get('tls_sni') or meta.get('sni'),
                'tls_alpn': meta.get('tls_alpn') or meta.get('alpn'),
                'tls_version': meta.get('tls_version'),
                'ja3': meta.get('ja3'),
                'ja4': meta.get('ja4'),
            })
        return rows

    def _get_session_alerts_for_logs(self) -> list[dict]:
        rows: list[dict] = []
        amap = getattr(self, 'alert_meta_by_item', {}) or {}
        for iid in list(getattr(self, 'alert_rows', [])):
            rec = amap.get(iid) or {}
            meta = rec.get('meta') or {}
            alert = rec.get('alert') or {}
            if not meta and not alert:
                continue
            rows.append({
                'ts': meta.get('ts') or meta.get('time'),
                'src': meta.get('src'),
                'dst': meta.get('dst'),
                'proto': meta.get('proto'),
                'attack_type': alert.get('attack_type') or alert.get('attack') or 'Alert',
                'score': float(alert.get('score', 0.0) or 0.0),
                'detail': alert.get('detail') or meta.get('summary') or '',
                'engine': alert.get('engine') or 'IDS',
            })
        return rows
    def _get_session_traceroute_rows(self) -> list[dict]:
        out: list[dict] = []
        try:
            for iid in self.tr_table.get_children():
                vals = self.tr_table.item(iid, "values")
                if not vals:
                    continue
                # columns: hop, ip, rtt, country, city, org, asn, route
                out.append({
                    "hop": vals[0],
                    "ip": vals[1],
                    "rtt": vals[2],
                    "country": vals[3],
                    "city": vals[4],
                    "org": vals[5],
                    "asn": vals[6],
                    "route": vals[7],
                })
        except Exception:
            pass
        return out


    def _export_csv(self) -> None:
        try:
            pkt = self._get_session_packets_for_logs()
            path = export_packets_csv(packet_rows=pkt)
            self.status_var.set(f"CSV exported: {path}")
        except Exception as e:
            messagebox.showerror('Export CSV', str(e))

    def _export_xlsx(self) -> None:
        try:
            pkt = self._get_session_packets_for_logs()
            path = export_packets_excel(packet_rows=pkt)
            self.status_var.set(f"Excel exported: {path}")
        except Exception as e:
            messagebox.showerror('Export Excel', str(e))

    def _export_pdf(self) -> None:
        try:
            alt = self._get_session_alerts_for_logs()
            path = export_alerts_pdf(alert_rows=alt)
            if path:
                self.status_var.set(f"PDF exported: {path}")
            else:
                messagebox.showinfo('Export PDF', 'PDF export is not available (missing dependency).')
        except Exception as e:
            messagebox.showerror('Export PDF', str(e))

    def _export_full_html(self) -> None:
        try:
            pkt = self._get_session_packets_for_logs()
            alt = self._get_session_alerts_for_logs()
            trr = self._get_session_traceroute_rows()
            path = export_full_html_report(packet_rows=pkt, alert_rows=alt, traceroute_rows=trr)
            self.status_var.set(f"HTML exported: {path}")
        except Exception as e:
            messagebox.showerror('Export HTML', str(e))

    def _export_html_report(self) -> None:
        # Sniffer tab quick export = current session only
        self._export_full_html()

    def _export_zip(self) -> None:
        try:
            pkt = self._get_session_packets_for_logs()
            alt = self._get_session_alerts_for_logs()
            trr = self._get_session_traceroute_rows()
            out = export_session_zip(packet_rows=pkt, alert_rows=alt, traceroute_rows=trr)
            if out:
                messagebox.showinfo('Export ZIP', f"Saved: {out}")
                self.status_var.set(f"ZIP exported: {out}")
            else:
                messagebox.showwarning('Export ZIP', 'Nothing to export.')
        except Exception as e:
            messagebox.showerror('Export ZIP', str(e))

    def _export_all_history_zip(self) -> None:
        if not getattr(self, 'persist_logs', False):
            messagebox.showinfo('Export ALL', 'Enable persistence in Settings to export full history.')
            return
        try:
            out = export_all_history_zip()
            messagebox.showinfo('Export ALL', f"Saved: {out}")
            self.status_var.set(f"ALL history exported: {out}")
        except Exception as e:
            messagebox.showerror('Export ALL', str(e))
    def _lint_rules_text(self) -> None:
        data = self.rules_text.get("1.0", "end").strip()
        try:
            parsed = json.loads(data) if data else []
        except Exception as e:
            messagebox.showerror("Rules", f"Invalid JSON: {e}")
            return
        count = len(parsed) if isinstance(parsed, list) else (len(parsed.keys()) if isinstance(parsed, dict) else 0)
        messagebox.showinfo("Rules", f"JSON OK. Items: {count}")

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
        txt = self.rules_text.get("1.0", "end").strip() or "[]"
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
    # Profiles / settings save
    # =================================================================
    def _apply_profile(self, name: str) -> None:
        presets = {
            "Safe": {"auto_block": False, "ml_threshold": 0.35, "group_alerts": True},
            "Home": {"auto_block": False, "ml_threshold": 0.25, "group_alerts": True},
            "Office": {"auto_block": False, "ml_threshold": 0.22, "group_alerts": True},
            "Pentest": {"auto_block": True, "ml_threshold": 0.18, "group_alerts": False},
        }
        p = presets.get(name)
        if not p:
            return
        try:
            self.var_auto_block.set(bool(p["auto_block"]))
            self.var_ml_threshold.set(float(p["ml_threshold"]))
            self.group_alerts_var.set(bool(p["group_alerts"]))
        except Exception:
            pass
        self.status_var.set(f"Profile applied: {name}")

    def _save_settings(self) -> None:
        self.settings["iface"] = self.var_iface.get().strip() or "iface=default"
        self.settings["autostart_sniffer"] = bool(self.var_autostart.get())
        self.settings["auto_block"] = bool(self.var_auto_block.get())
        self.settings["whitelist_ips"] = self.var_whitelist.get().strip()
        self.settings["safe_mode"] = bool(self.safe_mode_var.get())
        self.settings["group_alerts"] = bool(self.group_alerts_var.get())
        self.settings["profile"] = self.var_profile.get()


        # Privacy / Storage
        try:
            new_persist = bool(self.var_persist_logs.get()) if hasattr(self, 'var_persist_logs') else False
            new_retention = int(self.var_retention_minutes.get() or 0) if hasattr(self, 'var_retention_minutes') else 0
            new_mask = bool(self.var_mask_ip_logs.get()) if hasattr(self, 'var_mask_ip_logs') else False
        except Exception:
            new_persist, new_retention, new_mask = False, 0, False

        self.settings["persist_logs"] = new_persist
        self.settings["retention_minutes"] = int(new_retention or 0)
        self.settings["mask_ip_logs"] = new_mask

        # Apply runtime (best-effort). Restart recommended after toggling persistence.
        self.persist_logs = bool(new_persist)
        self.retention_minutes = int(new_retention or 0)
        self.mask_ip_logs = bool(new_mask)
        try:
            set_persist(self.persist_logs)
        except Exception:
            pass
        if self.persist_logs:
            try:
                init_storage()
                if self.retention_minutes > 0:
                    cleanup_retention(self.retention_minutes)
            except Exception:
                pass
            if self.db_queue is None:
                try:
                    self.db_queue = queue.Queue(maxsize=10000)
                    threading.Thread(target=self._db_worker, daemon=True).start()
                except Exception:
                    self.db_queue = None
            if self.retention_minutes > 0:
                try:
                    self.after(60_000, self._retention_tick)
                except Exception:
                    pass
        else:
            # Do not enqueue any more DB writes
            self.db_queue = None

        self.settings["ids_ml_threshold"] = float(self.var_ml_threshold.get() or 0.25)
        self.settings["ids_ml_contamination"] = float(self.var_ml_contamination.get() or 0.06)
        self.settings["ids_signature_enabled"] = bool(self.var_ids_sig_enabled.get())
        self.settings["ids_ml_enabled"] = bool(self.var_ids_ml_enabled.get())

        self.settings["language"] = self.var_language.get()
        self.settings["theme"] = self.var_theme.get()
        self.settings["alert_sound_enabled"] = bool(self.var_alert_sound_enabled.get())
        self.settings["right_log_enabled"] = bool(self.var_right_log_enabled.get())

        try:
            save_settings(self.settings)
        except Exception as e:
            messagebox.showerror("Settings", f"Failed to save:\n{e}")
            return

        messagebox.showinfo("Settings", "Settings saved. Restart recommended for theme / persistence changes.")

    # =================================================================
    # Misc
    # =================================================================
    def _retention_tick(self) -> None:
        """Periodic best-effort DB retention cleanup (if persistence enabled)."""
        try:
            if not getattr(self, 'persist_logs', False):
                return
            minutes = int(getattr(self, 'retention_minutes', 0) or 0)
        except Exception:
            return
        if minutes <= 0:
            return
        try:
            cleanup_retention(minutes)
        except Exception:
            pass
        try:
            if getattr(self, 'persist_logs', False) and minutes > 0:
                self.after(60_000, self._retention_tick)
        except Exception:
            pass

    def _on_tab_changed(self, event=None) -> None:
        cur = self.nb.select()
        if cur == str(self.tab_alerts) and self._alerts_tab_starred:
            self._alerts_tab_starred = False
            self.nb.tab(self.tab_alerts, text=tr("tab.alerts", self.language))


if __name__ == "__main__":
    try:
        init_storage()
    except Exception:
        pass
    app = NetBotKaliGUI()
    app.mainloop()
