# ids_signature.py
# -*- coding: utf-8 -*-
"""
Signature-based IDS for NetBotPRO v4

Rule types:
- Port Scan
- SYN Flood
- Generic Flood (per-source high rate)
- Custom rules defined in rules.json
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple


class SignatureIDS:
    """
    Simple rule-based IDS.

    All time windows are handled in UTC.
    """

    def __init__(self) -> None:
        # (src, dst) -> list[(ts, dport)]
        self.port_scan_map: Dict[Tuple[str, str], List[Tuple[datetime, int]]] = (
            defaultdict(list)
        )
        # (src, dst) -> list[ts]
        self.syn_counter: Dict[Tuple[str, str], List[datetime]] = defaultdict(list)
        # src -> list[ts]
        self.flood_counter: Dict[str, List[datetime]] = defaultdict(list)

        # Default parameters; can be overridden from settings_manager
        self.port_scan_threshold: int = 3
        self.port_scan_window_sec: int = 10

        self.syn_threshold: int = 30
        self.syn_window_sec: int = 5

        self.flood_threshold: int = 80
        self.flood_window_sec: int = 3

        # Custom rules for Rule Editor
        self.custom_rules: List[Dict[str, Any]] = []
        # (rule_idx, src, dport) -> list[datetime]
        self.custom_state: Dict[Tuple[int, str, int], List[datetime]] = defaultdict(
            list
        )

        base_dir = os.path.abspath(os.path.dirname(__file__))
        self.rules_path: str = os.path.join(base_dir, "rules.json")
        self.load_rules_from_file(self.rules_path)

    # ------------------------------------------------------------------
    # Parameter configuration
    # ------------------------------------------------------------------
    def update_params(
        self,
        port_scan_threshold: Optional[int] = None,
        port_scan_window_sec: Optional[int] = None,
        syn_threshold: Optional[int] = None,
        syn_window_sec: Optional[int] = None,
        flood_threshold: Optional[int] = None,
        flood_window_sec: Optional[int] = None,
    ) -> None:
        if port_scan_threshold is not None:
            self.port_scan_threshold = int(port_scan_threshold)
        if port_scan_window_sec is not None:
            self.port_scan_window_sec = int(port_scan_window_sec)
        if syn_threshold is not None:
            self.syn_threshold = int(syn_threshold)
        if syn_window_sec is not None:
            self.syn_window_sec = int(syn_window_sec)
        if flood_threshold is not None:
            self.flood_threshold = int(flood_threshold)
        if flood_window_sec is not None:
            self.flood_window_sec = int(flood_window_sec)

    # ------------------------------------------------------------------
    # Custom rules: Rule Editor
    # ------------------------------------------------------------------
    def load_rules_from_file(self, path: Optional[str] = None) -> None:
        path = path or self.rules_path
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    self.custom_rules = data
                    self.custom_state.clear()
        except Exception:
            # ignore errors, keep default empty rules
            self.custom_rules = []
            self.custom_state.clear()

    def save_rules_to_file(self, path: Optional[str] = None) -> None:
        path = path or self.rules_path
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.custom_rules, f, ensure_ascii=False, indent=2)
        except Exception:
            # ignore errors
            pass

    def get_custom_rules(self) -> List[Dict[str, Any]]:
        return list(self.custom_rules)

    def set_custom_rules(self, rules: List[Dict[str, Any]]) -> None:
        self.custom_rules = list(rules or [])
        self.custom_state.clear()
        self.save_rules_to_file()

    # ------------------------------------------------------------------
    # Core analysis
    # ------------------------------------------------------------------
    def _cleanup(self, now: datetime) -> None:
        # Port scan
        cutoff_ps = now - timedelta(seconds=self.port_scan_window_sec)
        for key, items in list(self.port_scan_map.items()):
            items[:] = [x for x in items if x[0] >= cutoff_ps]
            if not items:
                del self.port_scan_map[key]

        # SYN
        cutoff_syn = now - timedelta(seconds=self.syn_window_sec)
        for key, items in list(self.syn_counter.items()):
            items[:] = [t for t in items if t >= cutoff_syn]
            if not items:
                del self.syn_counter[key]

        # Flood
        cutoff_flood = now - timedelta(seconds=self.flood_window_sec)
        for src, items in list(self.flood_counter.items()):
            items[:] = [t for t in items if t >= cutoff_flood]
            if not items:
                del self.flood_counter[src]

        # Custom rules
        for key, items in list(self.custom_state.items()):
            if not items:
                del self.custom_state[key]

    def analyze_packet(self, meta: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Input meta must contain at least:
          src, dst, proto, dport, flags, length
        Returns:
          alert dict or None
        """
        now = datetime.now(timezone.utc)
        self._cleanup(now)

        src = meta.get("src")
        dst = meta.get("dst")
        proto = meta.get("proto")
        dport = meta.get("dport")
        flags = meta.get("flags") or ""
        length = int(
            meta.get("length") or 0
        )  # فعلاً استفاده نمی‌کنیم ولی برای آینده خوبه

        alert: Optional[Dict[str, Any]] = None

        # ---------------- Generic Flood detection ----------------
        if src:
            arr = self.flood_counter[src]
            arr.append(now)
            if len(arr) >= self.flood_threshold:
                alert = {
                    "attack_type": "Generic Flood / High Rate",
                    "detail": (
                        f"Source {src} sent {len(arr)} packets in the last "
                        f"{self.flood_window_sec} seconds."
                    ),
                    "score": float(len(arr)),
                }

        # ---------------- Port Scan detection ----------------
        if (
            alert is None
            and src
            and dst
            and dport is not None
            and proto in ("TCP", "UDP")
        ):
            key = (src, dst)
            arr2 = self.port_scan_map[key]
            arr2.append((now, int(dport)))
            cutoff = now - timedelta(seconds=self.port_scan_window_sec)
            arr2[:] = [(t, p) for (t, p) in arr2 if t >= cutoff]
            unique_ports = sorted({p for (_, p) in arr2})
            if len(unique_ports) >= self.port_scan_threshold:
                alert = {
                    "attack_type": "Port Scan / Nmap-like",
                    "detail": (
                        f"{src} → {dst} scanned ports {unique_ports} "
                        f"in about {self.port_scan_window_sec} seconds."
                    ),
                    "score": float(len(unique_ports)),
                }

        # ---------------- SYN Flood detection ----------------
        if (
            alert is None
            and src
            and dst
            and proto == "TCP"
            and "S" in flags
            and "A" not in flags
        ):
            key2 = (src, dst)
            arr3 = self.syn_counter[key2]
            arr3.append(now)
            cutoff = now - timedelta(seconds=self.syn_window_sec)
            arr3[:] = [t for t in arr3 if t >= cutoff]
            if len(arr3) >= self.syn_threshold:
                alert = {
                    "attack_type": "SYN Flood",
                    "detail": (
                        f"{src} → {dst} sent {len(arr3)} SYN packets "
                        f"in about {self.syn_window_sec} seconds."
                    ),
                    "score": float(len(arr3)),
                }

        # ---------------- Custom rules ----------------
        if alert is None:
            alert = self._check_custom_rules(meta, now)

        return alert

    # ------------------------------------------------------------------
    # Custom rules engine
    # ------------------------------------------------------------------
    def _check_custom_rules(
        self,
        meta: Dict[str, Any],
        now: datetime,
    ) -> Optional[Dict[str, Any]]:
        """
        Custom rules structure example:

        {
          "name": "SSH Bruteforce",
          "src_ip": "1.2.3.4" or "*",
          "dport": 22,
          "window_sec": 30,
          "count_threshold": 10,
          "enabled": true
        }
        """
        if not self.custom_rules:
            return None

        src = meta.get("src")
        dport_raw = meta.get("dport")
        try:
            dport = int(dport_raw) if dport_raw is not None else 0
        except Exception:
            dport = 0

        fired: Optional[Dict[str, Any]] = None

        for idx, rule in enumerate(self.custom_rules):
            if not rule or not rule.get("enabled", True):
                continue

            src_ip = (rule.get("src_ip") or "*").strip()
            rule_dport = int(rule.get("dport") or 0)
            window_sec = int(rule.get("window_sec") or 30)
            thr = int(rule.get("count_threshold") or 10)

            if src_ip != "*" and src != src_ip:
                continue
            if rule_dport and dport != rule_dport:
                continue

            key = (idx, src or "-", dport)
            arr = self.custom_state[key]
            cutoff = now - timedelta(seconds=window_sec)
            arr[:] = [t for t in arr if t >= cutoff]
            arr.append(now)

            if len(arr) >= thr:
                fired = {
                    "attack_type": rule.get("name") or "Custom rule",
                    "detail": (
                        f"Custom rule '{rule.get('name')}' fired for src={src} "
                        f"dport={dport} (count={len(arr)}, window={window_sec}s, thr={thr})."
                    ),
                    "score": float(len(arr)),
                }
                break

        return fired
