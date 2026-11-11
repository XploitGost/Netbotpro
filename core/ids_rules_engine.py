# ids_rules_engine.py
# -*- coding: utf-8 -*-
import json
from core.detection_clock import detection_time
from core.alert_identity import custom_rule_key
import os
import threading
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple


class RuleEngine:
    """
    موتور قوانین ساده برای IDS امضامحور.
    فایل rules.json را می‌خواند/می‌نویسد.

    هر rule یک dict شبیه این است:
      {
        "name": "SSH Bruteforce",
        "src_ip": "1.2.3.4" یا "*",
        "dport": 22,
        "window_sec": 30,
        "count_threshold": 10,
        "enabled": true
      }
    """

    def __init__(self, path: str | None = None):
        base = os.path.abspath(os.path.dirname(__file__))
        self.rules_path = path or os.path.join(base, "rules.json")
        self.rules: List[Dict[str, Any]] = []
        self.state: Dict[Tuple[int, str, int], List[datetime]] = defaultdict(list)
        self._state_lock = threading.RLock()
        self._last_cleanup_at = 0.0
        self.load()

    # ----------------- فایل -----------------
    def load(self):
        with self._state_lock:
            self._load_locked()

    def _load_locked(self):
        try:
            if os.path.exists(self.rules_path):
                with open(self.rules_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    self.rules = data
                    self.state.clear()
        except Exception:
            self.rules = []
            self.state.clear()

    def save(self):
        try:
            with open(self.rules_path, "w", encoding="utf-8") as f:
                json.dump(self.rules, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    # ----------------- API برای UI -----------------
    def get_rules(self) -> List[Dict[str, Any]]:
        with self._state_lock:
            return list(self.rules)

    def set_rules(self, rules: List[Dict[str, Any]]):
        with self._state_lock:
            self.rules = list(rules or [])
            self.state.clear()
            self._last_cleanup_at = 0.0
            self.save()

    # ----------------- آنالیز بسته -----------------
    def analyze(self, meta: Dict[str, Any]) -> Dict[str, Any] | None:
        with self._state_lock:
            return self._analyze_locked(meta)

    def _cleanup_expired(self, now: datetime) -> None:
        timestamp = now.timestamp()
        if self._last_cleanup_at <= timestamp < self._last_cleanup_at + 1.0:
            return
        self._last_cleanup_at = timestamp
        for key, items in list(self.state.items()):
            index = key[0]
            if index >= len(self.rules) or not self.rules[index] or not self.rules[index].get("enabled", True):
                del self.state[key]
                continue
            try:
                cutoff = now - timedelta(seconds=int(self.rules[index].get("window_sec") or 30))
            except (TypeError, ValueError, OverflowError):
                del self.state[key]
                continue
            items[:] = [value for value in items if value >= cutoff]
            if not items:
                del self.state[key]

    def _analyze_locked(self, meta: Dict[str, Any]) -> Dict[str, Any] | None:
        if not self.rules:
            return None

        src = meta.get("src")
        dport = int(meta.get("dport") or 0)
        now = detection_time(meta, datetime.now(timezone.utc))
        self._cleanup_expired(now)

        for idx, rule in enumerate(self.rules):
            if not rule or not rule.get("enabled", True):
                continue

            src_ip = rule.get("src_ip") or "*"
            rule_dport = int(rule.get("dport") or 0)
            window_sec = int(rule.get("window_sec") or 30)
            thr = int(rule.get("count_threshold") or 10)

            if src_ip != "*" and src != src_ip:
                continue
            if rule_dport and dport != rule_dport:
                continue

            key = (idx, src or "-", dport)
            arr = self.state[key]
            cutoff = now - timedelta(seconds=window_sec)
            arr[:] = [t for t in arr if t >= cutoff]
            arr.append(now)

            if len(arr) >= thr:
                return {
                    "detection_rule_key": custom_rule_key('rules.custom', idx,
                        rule.get('name') or 'Custom rule', src_ip, rule_dport, window_sec, thr),
                    "detection_rule_version": "1",
                    "attack_type": rule.get("name") or "Custom rule",
                    "score": 1.0,
                    "detail": f"rule: {rule.get('name')} window={window_sec}s thr={thr}",
                }

        return None
