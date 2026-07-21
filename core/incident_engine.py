# incident_engine.py
# -*- coding: utf-8 -*-
"""
NetBotPro - Balanced Pro correlation

- Groups repeated alerts into "incidents" within a rolling time window
- Adds incident_id and incident counters
- Does NOT remove any features; it only enriches alert metadata

Defensive/blue-team use only; run on networks you own or have permission to monitor.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple


def _safe_str(x: Any) -> str:
    try:
        return "" if x is None else str(x)
    except Exception:
        return ""


@dataclass
class Incident:
    id: str
    key: Tuple[str, str, str, str, str]
    first_seen: datetime
    last_seen: datetime
    count: int
    max_score: float


class IncidentCorrelator:
    """
    Correlates alerts into incidents based on:
      (src, dst, attack_type, dport, engine)

    If the same key repeats within `window_sec`, it is considered the same incident.
    """

    def __init__(self, window_sec: int = 120) -> None:
        self.window = timedelta(seconds=int(window_sec))
        self._incidents: Dict[Tuple[str, str, str, str, str], Incident] = {}

    def _make_key(
        self, meta: Dict[str, Any], alert: Dict[str, Any]
    ) -> Tuple[str, str, str, str, str]:
        src = _safe_str(meta.get("src"))
        dst = _safe_str(meta.get("dst"))
        atk = _safe_str(alert.get("attack_type") or alert.get("attack") or "Alert")
        dport = _safe_str(meta.get("dport"))
        eng = _safe_str(alert.get("engine") or "IDS")
        return (src, dst, atk, dport, eng)

    def _make_id(
        self, key: Tuple[str, str, str, str, str], first_seen: datetime
    ) -> str:
        base = "|".join(key) + "|" + first_seen.strftime("%Y%m%d%H%M%S")
        h = hashlib.sha1(base.encode("utf-8", errors="ignore")).hexdigest()
        return h[:12]

    def enrich_alert(self, meta: Dict[str, Any], alert: Dict[str, Any]) -> None:
        now = datetime.now(timezone.utc)
        key = self._make_key(meta, alert)

        # Parse normalized score if present
        try:
            score = float(alert.get("score", 0.0))
        except Exception:
            score = 0.0

        inc = self._incidents.get(key)
        if inc and (now - inc.last_seen) <= self.window:
            inc.last_seen = now
            inc.count += 1
            if score > inc.max_score:
                inc.max_score = score
        else:
            first = now
            iid = self._make_id(key, first)
            inc = Incident(
                id=iid,
                key=key,
                first_seen=first,
                last_seen=now,
                count=1,
                max_score=score,
            )
            self._incidents[key] = inc

        alert["incident_id"] = inc.id
        alert["incident_count"] = inc.count
        alert["incident_first_seen"] = inc.first_seen.isoformat(timespec="seconds")
        alert["incident_last_seen"] = inc.last_seen.isoformat(timespec="seconds")

        # Incident score: max score + small bump for repetition
        bump = 0.0
        if inc.count >= 2:
            bump = min(0.20, 0.03 * (inc.count - 1))  # cap bump
        incident_score = score
        try:
            incident_score = min(1.0, float(inc.max_score) + bump)
        except Exception:
            incident_score = min(1.0, score + bump)

        alert["incident_score"] = incident_score
