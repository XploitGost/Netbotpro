# score_engine.py
# -*- coding: utf-8 -*-
"""
NetBotPro - Balanced Pro scoring

Goal:
- Keep all existing detectors (SIG/RULE/ML) intact
- Normalize scores into [0..1] for UI + auto-block logic
- Add severity labels without breaking existing fields

This module is defensive/blue-team oriented and meant for authorized monitoring.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class ScoreResult:
    raw_score: float
    score: float
    severity: str
    threat_score: int


class AlertScorer:
    """
    Normalizes alert score into [0..1] and derives severity.

    - ML scores are expected to be already in [0..1].
    - Signature IDS historically used raw counts (ports scanned, SYN count, etc).
      We normalize those based on detector thresholds so that:
        raw == threshold  -> ~0.70
        raw == 2*thr      -> ~1.00
    """

    def __init__(
        self,
        high: float = 0.70,
        critical: float = 0.90,
        medium: float = 0.50,
    ) -> None:
        self.th_high = float(high)
        self.th_critical = float(critical)
        self.th_medium = float(medium)

    @staticmethod
    def _clamp01(x: float) -> float:
        if x < 0.0:
            return 0.0
        if x > 1.0:
            return 1.0
        return x

    def _severity(self, s: float) -> str:
        if s >= self.th_critical:
            return "CRITICAL"
        if s >= self.th_high:
            return "HIGH"
        if s >= self.th_medium:
            return "MEDIUM"
        return "LOW"

    def _normalize_sig(self, alert: Dict[str, Any], sig_engine: Any) -> float:
        try:
            raw = float(alert.get("score", 0.0))
        except Exception:
            raw = 0.0

        atk = (alert.get("attack_type") or alert.get("attack") or "").lower()

        # fallback thresholds
        port_thr = int(getattr(sig_engine, "port_scan_threshold", 3) or 3)
        syn_thr = int(getattr(sig_engine, "syn_threshold", 60) or 60)
        flood_thr = int(getattr(sig_engine, "flood_threshold", 80) or 80)

        thr = 1.0
        if "port scan" in atk or "nmap" in atk or "scan" in atk:
            thr = float(max(1, port_thr))
        elif "syn flood" in atk:
            thr = float(max(1, syn_thr))
        elif "flood" in atk or "high rate" in atk:
            thr = float(max(1, flood_thr))
        else:
            # unknown signature type: treat as "already normalized-ish"
            thr = float(max(1.0, raw))

        # Map raw counts to 0..1 where threshold ~= 0.70
        # score = 0.70 * (raw / thr)
        s = 0.70 * (raw / thr) if thr > 0 else 0.0
        return self._clamp01(s)

    def normalize(
        self,
        meta: Dict[str, Any],
        alert: Dict[str, Any],
        sig_engine: Any = None,
    ) -> ScoreResult:
        engine = (alert.get("engine") or "").upper()
        # preserve original
        try:
            raw = float(alert.get("score", 0.0))
        except Exception:
            raw = 0.0

        if engine == "ML":
            s = self._clamp01(raw)
        elif engine == "SIG":
            s = self._normalize_sig(alert, sig_engine)
        elif engine == "RULE":
            # most custom rules already give 0..1
            s = self._clamp01(raw)
        else:
            # unknown engine; clamp and move on
            s = self._clamp01(raw)

        sev = self._severity(s)
        threat = int(round(s * 100.0))
        return ScoreResult(raw_score=raw, score=s, severity=sev, threat_score=threat)

    def enrich_alert(self, meta: Dict[str, Any], alert: Dict[str, Any], sig_engine: Any = None) -> None:
        """
        In-place enrichment:
          - score_raw
          - score (normalized)
          - severity
          - threat_score (0..100)
        """
        res = self.normalize(meta, alert, sig_engine=sig_engine)
        alert["score_raw"] = res.raw_score
        alert["score"] = res.score
        alert["severity"] = res.severity
        alert["threat_score"] = res.threat_score
