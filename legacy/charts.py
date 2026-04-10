# charts.py
# -*- coding: utf-8 -*-
#
# NetBotPRO - Kali Edition
# Live statistics / graphs for:
#   - Packets & Alerts over time (line charts)
#   - Protocol distribution (bar)
#   - Top source IPs (bar)
#   - Packet size trend (approx bandwidth feeling)

from __future__ import annotations

from collections import Counter, deque
from typing import Deque, Dict, Any, List

import tkinter as tk
from tkinter import ttk

from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


class StatsChart:
    """
    Stats widget used by ui_kali.NetBotKaliGUI.

    Usage:
        self.stats_chart = StatsChart(parent_frame)
        self.stats_chart.update_with_packet(meta, total_packets, total_alerts, has_alert)

    - Sliding window روی آخرین max_points تا سنگین نشه
    - Redraw هر refresh_every بار برای کاهش فشار CPU
    - کنترل‌ها:
        * Pause graphs
        * Alerts only
    - Hover: حرکت موس → نمایش مقدار نزدیک‌ترین نقطه در status bar پایین
    """

    def __init__(self, parent: tk.Widget, max_points: int = 200, refresh_every: int = 5):
        self.parent = parent
        self.max_points = max_points
        self.refresh_every = max(refresh_every, 1)

        # History for line charts
        self.steps: Deque[int] = deque(maxlen=max_points)
        self.packets_history: Deque[int] = deque(maxlen=max_points)
        self.alerts_history: Deque[int] = deque(maxlen=max_points)
        self.packet_size_history: Deque[int] = deque(maxlen=max_points)

        # Counters for bar charts
        self.proto_counter: Counter[str] = Counter()
        self.top_src_counter: Counter[str] = Counter()

        self._update_counter = 0  # برای throttle کردن redraw

        # --- Layout root ---
        root = ttk.Frame(parent)
        root.pack(fill="both", expand=True)
        self._root = root

        # ---- Controls (Pause / Alerts only) ----
        ctrl = ttk.Frame(root)
        ctrl.pack(fill="x", padx=4, pady=2)

        self.var_pause = tk.BooleanVar(value=False)
        self.var_alerts_only = tk.BooleanVar(value=False)

        ttk.Checkbutton(
            ctrl, text="Pause graphs", variable=self.var_pause
        ).pack(side="left", padx=(0, 8))

        ttk.Checkbutton(
            ctrl, text="Alerts only", variable=self.var_alerts_only
        ).pack(side="left", padx=(0, 8))

        ttk.Button(
            ctrl, text="Reset window", command=self.reset
        ).pack(side="left", padx=(0, 8))

        # --- Figures ---
        top_frame = ttk.Frame(root)
        top_frame.pack(fill="both", expand=True)
        bottom_frame = ttk.Frame(root)
        bottom_frame.pack(fill="both", expand=True)

        # Figure 1: packets + alerts
        self.fig1 = Figure(figsize=(5, 3), dpi=100)
        self.ax_packets = self.fig1.add_subplot(2, 1, 1)
        self.ax_alerts = self.fig1.add_subplot(2, 1, 2, sharex=self.ax_packets)

        self.canvas1 = FigureCanvasTkAgg(self.fig1, master=top_frame)
        self.canvas1.get_tk_widget().pack(fill="both", expand=True)

        # Figure 2: proto + top src + packet size trend
        self.fig2 = Figure(figsize=(5, 3), dpi=100)
        self.ax_proto = self.fig2.add_subplot(1, 3, 1)
        self.ax_top_src = self.fig2.add_subplot(1, 3, 2)
        self.ax_sizes = self.fig2.add_subplot(1, 3, 3)

        self.canvas2 = FigureCanvasTkAgg(self.fig2, master=bottom_frame)
        self.canvas2.get_tk_widget().pack(fill="both", expand=True)

        # Hover info label
        self.info_var = tk.StringVar(value="Hover mouse over charts to see values")
        ttk.Label(root, textvariable=self.info_var).pack(
            fill="x", padx=4, pady=(2, 4)
        )

        # Init axes & connect hover
        self._init_axes()
        self.canvas1.mpl_connect("motion_notify_event", self._on_motion)
        self.canvas2.mpl_connect("motion_notify_event", self._on_motion)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def reset(self) -> None:
        """Clear all internal buffers & redraw empty state."""
        self.steps.clear()
        self.packets_history.clear()
        self.alerts_history.clear()
        self.packet_size_history.clear()
        self.proto_counter.clear()
        self.top_src_counter.clear()
        self._init_axes()
        self.canvas1.draw_idle()
        self.canvas2.draw_idle()
        self.info_var.set("Window reset")

    def update_with_packet(
        self,
        meta: Dict[str, Any],
        total_packets: int,
        total_alerts: int,
        has_alert: bool = False,
    ) -> None:
        """
        Called from UI for (تقریباً) هر پکت.
        اگر Pause فعال باشد یا Alerts-only و این پکت Alert نداشته باشد، فقط رد می‌شویم.
        """
        # Pause graphs → هیچ داده‌ای وارد بافرها نشود
        if self.var_pause.get():
            return

        alerts_only = self.var_alerts_only.get()
        if alerts_only and not has_alert:
            return

        self._update_counter += 1

        # --- Update history (time series) ---
        step = total_packets  # شماره پکت به عنوان "زمان"
        self.steps.append(step)
        self.packets_history.append(total_packets)
        self.alerts_history.append(total_alerts)

        length = 0
        try:
            length = int(meta.get("length") or 0)
        except Exception:
            length = 0
        self.packet_size_history.append(length)

        # --- Update counters (bars) ---
        proto = str(meta.get("proto") or "OTHER").upper()
        src = str(meta.get("src") or "UNKNOWN")
        self.proto_counter[proto] += 1
        self.top_src_counter[src] += 1

        # هر چند بار یک‌بار redraw کن
        if self._update_counter >= self.refresh_every:
            self._update_counter = 0
            self._redraw()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _init_axes(self) -> None:
        # Line charts
        self.ax_packets.clear()
        self.ax_alerts.clear()

        self.ax_packets.set_title("Packets over time")
        self.ax_packets.set_ylabel("Packets")
        self.ax_packets.grid(True, linestyle="--", linewidth=0.5, alpha=0.5)

        self.ax_alerts.set_title("Alerts over time")
        self.ax_alerts.set_xlabel("Step")
        self.ax_alerts.set_ylabel("Alerts")
        self.ax_alerts.grid(True, linestyle="--", linewidth=0.5, alpha=0.5)

        # Bar + size charts
        self.ax_proto.clear()
        self.ax_top_src.clear()
        self.ax_sizes.clear()

        self.ax_proto.set_title("Protocols")
        self.ax_proto.set_ylabel("Count")

        self.ax_top_src.set_title("Top source IPs")
        self.ax_top_src.set_ylabel("Count")

        self.ax_sizes.set_title("Packet size trend")
        self.ax_sizes.set_ylabel("Bytes")

        self.fig1.tight_layout()
        self.fig2.tight_layout()

    def _redraw(self) -> None:
        # ------------- Figure 1: packets & alerts lines -------------
        self.ax_packets.clear()
        self.ax_alerts.clear()

        if self.steps:
            xs = list(self.steps)
            ys_packets = list(self.packets_history)
            ys_alerts = list(self.alerts_history)

            # Packets line
            self.ax_packets.plot(xs, ys_packets, marker=".", linewidth=1.0)
            self.ax_packets.set_ylabel("Packets")
            self.ax_packets.set_title("Packets over time")
            self.ax_packets.grid(True, linestyle="--", linewidth=0.5, alpha=0.5)

            # Alerts line
            self.ax_alerts.plot(xs, ys_alerts, marker=".", linewidth=1.0)
            self.ax_alerts.set_xlabel("Step")
            self.ax_alerts.set_ylabel("Alerts")
            self.ax_alerts.set_title("Alerts over time")
            self.ax_alerts.grid(True, linestyle="--", linewidth=0.5, alpha=0.5)
        else:
            self.ax_packets.text(
                0.5,
                0.5,
                "No data",
                ha="center",
                va="center",
                transform=self.ax_packets.transAxes,
            )
            self.ax_alerts.text(
                0.5,
                0.5,
                "No data",
                ha="center",
                va="center",
                transform=self.ax_alerts.transAxes,
            )

        self.fig1.tight_layout()
        self.canvas1.draw_idle()

        # ------------- Figure 2: proto + top src + size trend -------------
        self.ax_proto.clear()
        self.ax_top_src.clear()
        self.ax_sizes.clear()

        # Protocol distribution
        self.ax_proto.set_title("Protocols")
        self.ax_proto.set_ylabel("Count")
        if self.proto_counter:
            labels = list(self.proto_counter.keys())
            counts = [self.proto_counter[p] for p in labels]
            xs = range(len(labels))
            self.ax_proto.bar(list(xs), counts)
            self.ax_proto.set_xticks(list(xs))
            self.ax_proto.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
        else:
            self.ax_proto.text(
                0.5,
                0.5,
                "No data",
                ha="center",
                va="center",
                transform=self.ax_proto.transAxes,
            )

        # Top source IPs (۶ تا)
        self.ax_top_src.set_title("Top source IPs")
        self.ax_top_src.set_ylabel("Count")
        if self.top_src_counter:
            top_items = self.top_src_counter.most_common(6)
            labels = [ip for ip, _ in top_items]
            counts = [c for _, c in top_items]
            xs = range(len(labels))
            self.ax_top_src.bar(list(xs), counts)
            self.ax_top_src.set_xticks(list(xs))
            self.ax_top_src.set_xticklabels(
                labels, rotation=45, ha="right", fontsize=7
            )
        else:
            self.ax_top_src.text(
                0.5,
                0.5,
                "No data",
                ha="center",
                va="center",
                transform=self.ax_top_src.transAxes,
            )

        # Packet size trend (تقریباً حس bandwidth)
        self.ax_sizes.set_title("Packet size trend")
        self.ax_sizes.set_ylabel("Bytes")
        if self.steps and self.packet_size_history:
            xs = list(self.steps)
            ys = list(self.packet_size_history)
            self.ax_sizes.plot(xs, ys, marker=".", linewidth=1.0)
            self.ax_sizes.grid(True, linestyle="--", linewidth=0.5, alpha=0.5)
        else:
            self.ax_sizes.text(
                0.5,
                0.5,
                "No data",
                ha="center",
                va="center",
                transform=self.ax_sizes.transAxes,
            )

        self.fig2.tight_layout()
        self.canvas2.draw_idle()

    # ------------------------------------------------------------------
    # Hover handling
    # ------------------------------------------------------------------
    def _on_motion(self, event) -> None:
        """Update info label when mouse moves over any axis."""
        if event.inaxes is None or event.xdata is None or event.ydata is None:
            return

        ax = event.inaxes

        if ax is self.ax_packets:
            self._update_info_line("Packets", self.steps, self.packets_history, event.xdata)
        elif ax is self.ax_alerts:
            self._update_info_line("Alerts", self.steps, self.alerts_history, event.xdata)
        elif ax is self.ax_sizes:
            self._update_info_line("Size", self.steps, self.packet_size_history, event.xdata)
        elif ax is self.ax_proto:
            self._update_info_bar("Protocol", self.proto_counter, event.xdata)
        elif ax is self.ax_top_src:
            self._update_info_bar("Src IP", self.top_src_counter, event.xdata)

    def _update_info_line(
        self,
        label: str,
        xs_deque: Deque[int],
        ys_deque: Deque[int],
        xdata: float,
    ) -> None:
        if not xs_deque:
            return
        xs = list(xs_deque)
        ys = list(ys_deque)
        # نزدیک‌ترین نقطه به xdata
        nearest_idx = min(range(len(xs)), key=lambda i: abs(xs[i] - xdata))
        x_val = xs[nearest_idx]
        y_val = ys[nearest_idx]
        self.info_var.set(f"{label}: step={x_val}, value={y_val}")

    def _update_info_bar(
        self,
        label: str,
        counter: Counter[str],
        xdata: float,
    ) -> None:
        if not counter:
            return
        items: List[tuple[str, int]] = list(counter.items())
        idx = int(round(xdata))
        if idx < 0 or idx >= len(items):
            return
        name, count = items[idx]
        self.info_var.set(f"{label}: {name} → {count}")
