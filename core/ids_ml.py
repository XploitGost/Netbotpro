# ids_ml.py
# -*- coding: utf-8 -*-
"""
ML-based IDS using IsolationForest for NetBotPRO v4 / v5.

طراحی شده برای:
- سرعت بالاتر (نمونه‌برداری روی پکت‌ها)
- کاهش False-Positive
- تمرکز روی ترافیک مشکوک (خارج از LAN / پورت‌های غیرمعمول)
"""

from __future__ import annotations

from collections import deque
from typing import Dict, Any, Optional

import ipaddress
import numpy as np
from sklearn.ensemble import IsolationForest


def _is_private_ip(ip: Optional[str]) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


class MLIDS:
    """
    پنل ML IDS سبک شده:

    - از ویژگی‌های ساده برای هر پکت استفاده می‌کند.
    - فقط هر `sample_rate` پکت یک‌بار آنالیز می‌کند.
    - روی ترافیک داخل LAN کار نمی‌کند (تمرکز روی اینترنت).
    - مدل فقط وقتی حداقل `min_train_size` نمونه داشت train می‌شود.
    """

    def __init__(self, contamination: float = 0.06, sample_rate: int = 5,
                 min_train_size: int = 200, max_buffer: int = 5000) -> None:
        self.contamination = float(contamination)
        self.sample_rate = max(1, int(sample_rate))
        self.min_train_size = max(50, int(min_train_size))
        self.max_buffer = max_buffer

        self._buffer: deque[list[float]] = deque(maxlen=self.max_buffer)
        self._model: Optional[IsolationForest] = None
        self._trained: bool = False
        self._seen_packets: int = 0
        self._since_last_train: int = 0

    # ------------------------------------------------------------------
    # مدل
    # ------------------------------------------------------------------
    def reset_model(self, contamination: Optional[float] = None) -> None:
        """
        reset کامل مدل و بافر.
        """
        if contamination is not None:
            self.contamination = float(contamination)
        self._buffer.clear()
        self._model = None
        self._trained = False
        self._seen_packets = 0
        self._since_last_train = 0

    def _train_if_needed(self) -> None:
        """
        وقتی داده کافی داریم و از آخرین train مدت زیادی گذشته، مدل را به‌روزرسانی می‌کند.
        """
        if len(self._buffer) < self.min_train_size:
            return
        # هر 300 نمونه جدید یکبار train کن
        if self._since_last_train < 300 and self._trained:
            return

        X = np.asarray(self._buffer, dtype=float)
        try:
            self._model = IsolationForest(
                n_estimators=100,
                contamination=self.contamination,
                max_features=1.0,
                bootstrap=False,
                n_jobs=-1,
                random_state=42,
            )
            self._model.fit(X)
            self._trained = True
            self._since_last_train = 0
        except Exception:
            # اگر به هر دلیل شکست خورد، دفعه بعد دوباره تلاش می‌کنیم
            self._model = None
            self._trained = False

    # ------------------------------------------------------------------
    # Feature استخراج
    # ------------------------------------------------------------------
    def _extract_features(self, meta: Dict[str, Any]) -> Optional[list[float]]:
        proto = (meta.get("proto") or "").upper()
        if proto == "TCP":
            proto_id = 1
        elif proto == "UDP":
            proto_id = 2
        elif proto == "ICMP":
            proto_id = 3
        else:
            proto_id = 0

        sport = int(meta.get("sport") or 0)
        dport = int(meta.get("dport") or 0)
        length = int(meta.get("length") or 0)
        ttl = int(meta.get("ttl") or 0)

        # چند feature مشتق‌شده ساده
        # high_port = 1 اگر پورت بالا (غیر سیستمی) باشد
        high_port = 1 if (sport > 1024 or dport > 1024) else 0
        is_udp = 1 if proto == "UDP" else 0

        return [
            float(proto_id),
            float(sport),
            float(dport),
            float(length),
            float(ttl),
            float(high_port),
            float(is_udp),
        ]

    # ------------------------------------------------------------------
    # امتیاز anomaly
    # ------------------------------------------------------------------
    def score(self, meta: Dict[str, Any]) -> Optional[float]:
        """
        نمره anomaly در بازه تقریبی [0,1].
        اگر مدل هنوز train نشده باشد → None
        """
        if not self._trained or self._model is None:
            return None

        features = self._extract_features(meta)
        if features is None:
            return None

        X = np.asarray([features], dtype=float)
        pred = self._model.decision_function(X)  # مقدار بالاتر = نرمال‌تر
        if pred is None or len(pred) == 0:
            return None

        raw = float(pred[0])
        # نگاشت ساده: decision_function معمولاً حدود [-0.5 .. 0.5]
        # ما می‌خواهیم 0 = نرمال، 1 = خیلی مشکوک
        # بنابراین:
        score = 0.5 - raw  # هرچه کوچک‌تر بوده، score بزرگ‌تر
        # clamp
        if score < 0.0:
            score = 0.0
        if score > 1.0:
            score = 1.0
        return score

    # ------------------------------------------------------------------
    # آنالیز پکت
    # ------------------------------------------------------------------
    def analyze_packet(self, meta: Dict[str, Any], threshold: float = 0.25) -> Optional[Dict[str, Any]]:
        """
        اگر score >= threshold باشد، alert برمی‌گرداند.
        در غیر این صورت None
        """

        self._seen_packets += 1

        # 1) فقط هر sample_rate پکت یک‌بار کار سنگین انجام بده
        if (self._seen_packets % self.sample_rate) != 0:
            return None

        # 2) فقط روی ترافیک اینترنت (خارج از LAN) کار کن
        src = meta.get("src")
        dst = meta.get("dst")
        if _is_private_ip(src) and _is_private_ip(dst):
            return None

        # 3) پکت‌های خیلی کوچک (مثلاً ACK خالی) معمولاً مهم نیستند
        length = int(meta.get("length") or 0)
        if length < 80:
            return None

        # 4) ویژگی‌ها را به بافر اضافه کن و در صورت نیاز train کن
        f = self._extract_features(meta)
        if f is not None:
            self._buffer.append(f)
            self._since_last_train += 1
            self._train_if_needed()

        # اگر هنوز مدلی train نشده، alert نده
        if not self._trained or self._model is None:
            return None

        try:
            s = self.score(meta)
        except Exception:
            return None

        if s is None:
            return None

        if s >= threshold:
            detail = (
                "این یک ترافیک غیرعادی (anomaly) است که توسط مدل ML شناسایی شده است.\n"
                "ممکنه ناشی از اسکن پورت، ربات خودکار، ابزار تست نفوذ یا یک الگوی ناشناخته جدید باشد."
            )
            return {
                "attack_type": "ML Anomaly / Robot Detection",
                "detail": detail,
                "score": float(s),
            }
        return None
