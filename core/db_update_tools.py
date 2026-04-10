# db_update_tools.py
# -*- coding: utf-8 -*-
"""Database/Data updater for netbotpro.

هدف: آپدیت دیتای سبکِ لازم برای lookup ها (بدون سنگین کردن برنامه)
- OUI / MAC Vendor list → data/oui_local.csv
- (GeoIP در این پروژه آنلاین/Cache شده است و به mmdb وابسته نیست)

خروجی: (ok: bool, message: str)
"""

import os
import csv
import time
from typing import Tuple

import requests  # type: ignore

BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(BASE_DIR, "data")

# IEEE OUI list (CSV)
IEEE_OUI_CSV_URL = "https://standards-oui.ieee.org/oui/oui.csv"

def _ensure_dirs() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)

def update_oui_database(timeout: int = 20) -> Tuple[bool, str]:
    """Downloads IEEE oui.csv and converts it to a small local CSV for fast lookup."""
    _ensure_dirs()
    target = os.path.join(DATA_DIR, "oui_local.csv")

    try:
        r = requests.get(IEEE_OUI_CSV_URL, timeout=timeout)
        r.raise_for_status()
    except Exception as e:
        return False, f"OUI download failed: {e}"

    # Parse IEEE CSV. Columns usually include: Registry, Assignment, Organization Name, Organization Address
    # We keep: prefix, org_name
    try:
        decoded = r.content.decode("utf-8", errors="ignore").splitlines()
        reader = csv.DictReader(decoded)
        rows = 0
        with open(target, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            for row in reader:
                prefix = (row.get("Assignment") or "").strip()
                org = (row.get("Organization Name") or "").strip()
                if not prefix or not org:
                    continue
                # Normalize: remove separators and keep first 6 hex
                key = prefix.replace("-", "").replace(":", "").replace(".", "").replace(" ", "")[:6].upper()
                if len(key) != 6:
                    continue
                w.writerow([key, org])
                rows += 1
        if rows == 0:
            return False, "OUI update failed: parsed 0 rows"
    except Exception as e:
        return False, f"OUI parse/write failed: {e}"

    return True, f"OUI database updated: {rows} entries → {target}"

def update_databases() -> Tuple[bool, str]:
    """Convenience entrypoint used by UI."""
    ok, msg = update_oui_database()
    return ok, msg
