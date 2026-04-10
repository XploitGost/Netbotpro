# mac_vendor.py
# -*- coding: utf-8 -*-
"""MAC vendor lookup for NetBotPRO.

ترکیب دیتابیس آفلاین OUI + API آنلاین (به‌صورت محدود و سریع).
"""

from __future__ import annotations

import csv
import functools
import os
from typing import Optional

import requests

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

LOCAL_OUI_MAP = {}
_LOCAL_DB_LOADED = False

# محدود کردن تعداد درخواست آنلاین
_MAX_HTTP_LOOKUPS = 200
_http_lookups_done = 0
_HTTP_TIMEOUT = 1.0  # seconds


def _load_local_if_needed():
    global _LOCAL_DB_LOADED
    if _LOCAL_DB_LOADED:
        return
    _LOCAL_DB_LOADED = True

    path = os.path.join(DATA_DIR, "oui_local.csv")
    if not os.path.exists(path):
        return

    try:
        with open(path, "r", encoding="utf-8", newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row or len(row) < 2:
                    continue
                prefix = (row[0] or "").strip().upper()
                name = (row[1] or "").strip()

                # تبدیل فرمت‌ها مانند "AA-BB-CC", "AA:BB:CC", "AABBCC"
                prefix = (
                    prefix.replace("-", "")
                    .replace(":", "")
                    .replace(".", "")
                    .replace(" ", "")
                )
                if len(prefix) < 6:
                    continue
                key = prefix[:6]
                if key and name:
                    LOCAL_OUI_MAP[key] = name
    except Exception:
        # اگر دیتابیس خراب بود، ساکت می‌مانیم
        pass


def _normalize_mac(mac: str) -> Optional[str]:
    if not mac:
        return None
    mac = mac.strip().upper()
    # فقط حروف هگز را نگه می‌داریم
    hex_chars = "".join(ch for ch in mac if ch in "0123456789ABCDEF")
    if len(hex_chars) < 6:
        return None
    return hex_chars


@functools.lru_cache(maxsize=4096)
def lookup_vendor(mac: str) -> str:
    """MAC vendor lookup.

    - ابتدا دیتابیس آفلاین لوکال را چک می‌کند.
    - سپس اگر لازم بود و هنوز محدودیت نرسیده، API آنلاین را صدا می‌زند.
    - نتیجه روی MAC نرمال‌شده cache می‌شود.
    """
    global _http_lookups_done

    norm = _normalize_mac(mac)
    if not norm:
        return "Unknown"

    prefix = norm[:6]

    # 1) دیتابیس آفلاین
    _load_local_if_needed()
    if prefix in LOCAL_OUI_MAP:
        return LOCAL_OUI_MAP[prefix]

    # 2) API آنلاین (در صورت امکان)
    if _http_lookups_done >= _MAX_HTTP_LOOKUPS:
        return f"Unknown ({prefix})"

    try:
        url = f"https://api.macvendors.com/{norm}"
        _http_lookups_done += 1
        r = requests.get(url, timeout=_HTTP_TIMEOUT)
        if r.status_code == 200:
            name = r.text.strip()
            if name:
                return name
    except Exception:
        pass

    # 3) fallback
    return f"Unknown ({prefix})"
