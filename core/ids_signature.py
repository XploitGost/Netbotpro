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
from core.detection_clock import detection_time
from core.alert_identity import custom_rule_key
from core.scan_response_context import ScanResponseContext

import json
import os
import threading
from functools import wraps
from collections import defaultdict, deque, OrderedDict
from bisect import insort
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple


def _with_state_lock(method):
    @wraps(method)
    def locked(self, *args, **kwargs):
        with self._state_lock:
            return method(self, *args, **kwargs)
    return locked


class SignatureIDS:
    """
    Simple rule-based IDS.

    All time windows are handled in UTC.
    """

    def __init__(self) -> None:
        # Cleanup and packet updates must be atomic across flow workers.
        self._state_lock = threading.RLock()
        self._last_cleanup: Optional[datetime] = None
        self._scan_responses = ScanResponseContext()
        self._scan_reports = OrderedDict()
        self._scan_reports_max = 8192
        self._scan_reports_coalesced = 0
        self._scan_report_evictions = 0
        # (src, dst) -> list[(ts, dport)]
        self.port_scan_map: Dict[Tuple[str, str], List[Tuple[datetime, int]]] = (
            defaultdict(list)
        )
        # (src, dst) -> list[ts]
        self.syn_counter: Dict[Tuple[str, str], List[datetime]] = defaultdict(list)
        # src -> list[ts]
        self.flood_counter: Dict[str, deque[datetime]] = defaultdict(deque)

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
    @_with_state_lock
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
        if port_scan_threshold is not None or port_scan_window_sec is not None:
            self._scan_reports.clear()
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
    @_with_state_lock
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

    @_with_state_lock
    def save_rules_to_file(self, path: Optional[str] = None) -> None:
        path = path or self.rules_path
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.custom_rules, f, ensure_ascii=False, indent=2)
        except Exception:
            # ignore errors
            pass

    @_with_state_lock
    def get_custom_rules(self) -> List[Dict[str, Any]]:
        return list(self.custom_rules)

    @_with_state_lock
    def set_custom_rules(self, rules: List[Dict[str, Any]]) -> None:
        self.custom_rules = list(rules or [])
        self.custom_state.clear()
        self.save_rules_to_file()

    # ------------------------------------------------------------------
    # Core analysis
    # ------------------------------------------------------------------
    @_with_state_lock
    def reset_runtime(self) -> None:
        self.port_scan_map.clear()
        self.syn_counter.clear()
        self.flood_counter.clear()
        self.custom_state.clear()
        self._scan_responses.reset()
        self._scan_reports.clear()
        self._scan_reports_coalesced = 0
        self._scan_report_evictions = 0
        self._last_cleanup = None

    @_with_state_lock
    def port_scan_stats(self) -> Dict[str, Any]:
        return {**self._scan_responses.stats(),
                'tracked_reports': len(self._scan_reports),
                'max_reports': self._scan_reports_max,
                'reports_coalesced_total': self._scan_reports_coalesced,
                'report_capacity_evictions_total': self._scan_report_evictions}

    @_with_state_lock
    def _cleanup(self, now: datetime) -> None:
        self._scan_responses.expire(now)
        # Port scan
        cutoff_ps = now - timedelta(seconds=self.port_scan_window_sec)
        for key, items in list(self.port_scan_map.items()):
            items[:] = [x for x in items if x[0] >= cutoff_ps]
            if not items:
                del self.port_scan_map[key]
                self._scan_reports.pop(key, None)

        # SYN
        cutoff_syn = now - timedelta(seconds=self.syn_window_sec)
        for key, items in list(self.syn_counter.items()):
            items[:] = [t for t in items if t >= cutoff_syn]
            if not items:
                del self.syn_counter[key]

        # Flood
        cutoff_flood = now - timedelta(seconds=self.flood_window_sec)
        for src, items in list(self.flood_counter.items()):
            while items and items[0] < cutoff_flood:
                items.popleft()
            if not items:
                del self.flood_counter[src]

        # Custom rules
        for key, items in list(self.custom_state.items()):
            if not items:
                del self.custom_state[key]

    @_with_state_lock
    def analyze_packet(self, meta: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Input meta must contain at least:
          src, dst, proto, dport, flags, length
        Returns:
          alert dict or None
        """
        now = detection_time(meta, datetime.now(timezone.utc))
        if (self._last_cleanup is None or now < self._last_cleanup
                or (now - self._last_cleanup).total_seconds() >= 1):
            self._cleanup(now)
            self._last_cleanup = now

        src = meta.get("src")
        dst = meta.get("dst")
        proto = meta.get("proto")
        dport = meta.get("dport")
        flags = meta.get("flags") or ""
        if type(flags) is int and 0 <= flags <= 511:
            flags = ''.join(letter for bit, letter in enumerate('FSRPAUECN') if flags & (1 << bit))
        elif type(flags) is int:
            flags = ''
        else:
            flags = str(flags).upper()
        correlated_response = self._scan_responses.observe(meta, now, flags)
        length = int(
            meta.get("length") or 0
        )  # فعلاً استفاده نمی‌کنیم ولی برای آینده خوبه

        alert: Optional[Dict[str, Any]] = None

        # ---------------- Generic Flood detection ----------------
        if src:
            arr = self.flood_counter[src]
            cutoff_flood = now - timedelta(seconds=self.flood_window_sec)
            while arr and arr[0] < cutoff_flood:
                arr.popleft()
            if arr and now < arr[-1]:
                insort(arr, now)
            else:
                arr.append(now)
            if len(arr) >= self.flood_threshold:
                alert = {
                    "attack_type": "Generic Flood / High Rate",
                    "detection_rule_key": "signature.generic_flood",
                    "detection_rule_version": "1",
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
            and not correlated_response
        ):
            key = (src, dst)
            arr2 = self.port_scan_map[key]
            arr2.append((now, int(dport)))
            cutoff = now - timedelta(seconds=self.port_scan_window_sec)
            arr2[:] = [(t, p) for (t, p) in arr2 if t >= cutoff]
            unique_ports = sorted({p for (_, p) in arr2})
            if len(unique_ports) >= self.port_scan_threshold:
                previous = self._scan_reports.get(key)
                emit = (previous is None or now < previous[0]
                        or len(unique_ports) > previous[1]
                        or (now - previous[0]).total_seconds() >= max(0, self.port_scan_window_sec))
                if not emit:
                    self._scan_reports[key] = (previous[0], previous[1], previous[2] + 1)
                    self._scan_reports.move_to_end(key)
                    self._scan_reports_coalesced += 1
                else:
                    occurrences = (previous[2] if previous else 0) + 1
                    self._scan_reports[key] = (now, len(unique_ports), 0)
                    self._scan_reports.move_to_end(key)
                    while len(self._scan_reports) > self._scan_reports_max:
                        self._scan_reports.popitem(last=False)
                        self._scan_report_evictions += 1
                    alert = {
                        "attack_type": "Port Scan / Nmap-like",
                        "detection_rule_key": "signature.port_scan",
                        "detection_rule_version": "1",
                        "detail": (
                            f"{src} → {dst} scanned ports {unique_ports} "
                            f"in about {self.port_scan_window_sec} seconds."
                        ),
                        "score": float(len(unique_ports)),
                        "coalesced_occurrences": occurrences,
                    }
            else:
                self._scan_reports.pop(key, None)

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
                    "detection_rule_key": "signature.syn_flood",
                    "detection_rule_version": "1",
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
    @_with_state_lock
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
                    "detection_rule_key": custom_rule_key('signature.custom', idx,
                        rule.get('name') or 'Custom rule', src_ip, rule_dport, window_sec, thr),
                    "detection_rule_version": "1",
                    "attack_type": rule.get("name") or "Custom rule",
                    "detail": (
                        f"Custom rule '{rule.get('name')}' fired for src={src} "
                        f"dport={dport} (count={len(arr)}, window={window_sec}s, thr={thr})."
                    ),
                    "score": float(len(arr)),
                }
                break

        return fired
