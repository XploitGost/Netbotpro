# settings_manager.py
# -*- coding: utf-8 -*-
import json
import os
from typing import Dict, Any

DEFAULT_BASE_DIR = os.path.abspath(os.path.dirname(__file__))
BASE_DIR = os.environ.get("NETBOT_CONFIG_DIR", DEFAULT_BASE_DIR)
os.makedirs(BASE_DIR, exist_ok=True)
SETTINGS_PATH = os.path.join(BASE_DIR, "settings.json")

# مقادیر پیش‌فرض برای تنظیمات
DEFAULT_SETTINGS: Dict[str, Any] = {
    "language": "fa",               # fa / en
    "theme": "dark",                # dark / light
    "iface": "iface=default",       # نام اینترفیس Sniffer
    "autostart_sniffer": False,     # Auto-start Sniffer on app launch

    # Sniffer / performance
    "sniffer_sample_rate": 2,       # نمونه‌برداری نرم‌افزاری UI

    # IDS / امنیت
    "auto_block": False,            # بلاک خودکار IPهای آلوده
    "whitelist_ips": "127.0.0.1, 192.168.1.1",

    # ML IDS config
    "ids_ml_threshold": 0.25,       # threshold برای Anomaly (0..1)
    "ids_ml_contamination": 0.06,   # نسبت آنومالی مورد انتظار

    # Signature IDS
    "ids_signature_enabled": True,
    "ids_ml_enabled": True,

    # سایر گزینه‌ها (رزرو)
    "right_log_enabled": True,

    # UI / Alerts
    "group_alerts": True,
    "safe_mode": True,

    # Privacy / Storage
    "persist_logs": False,
    "retention_minutes": 0,
    "mask_ip_logs": False,
    "payload_capture_enabled": False,
    "alert_only_mode": False,
    "safe_use_policy_accepted": False,
    "remote_dashboard_allowlist": "",

    # TraceRoute defaults
    "tr_mode": "UDP",
    "tr_timeout": 1.5,
    "tr_max_hops": 30,
    "tr_queries": 1,
    "tr_port": 443,
}


def _merge_defaults(user_data: Dict[str, Any] | None) -> Dict[str, Any]:
    """
    داده‌ی خوانده‌شده از فایل را با DEFAULT_SETTINGS ترکیب می‌کند.
    """
    merged = dict(DEFAULT_SETTINGS)
    if not user_data:
        return merged
    for k, v in user_data.items():
        if k in DEFAULT_SETTINGS:
            merged[k] = v
    return merged


def load_settings() -> Dict[str, Any]:
    """
    تنظیمات را از settings.json می‌خواند.
    اگر فایل نباشد یا خراب باشد، مقادیر پیش‌فرض را برمی‌گرداند.
    """
    try:
        if os.path.exists(SETTINGS_PATH):
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return _merge_defaults(data)
    except Exception:
        pass
    return dict(DEFAULT_SETTINGS)


def save_settings(data: Dict[str, Any]) -> None:
    """
    تنظیمات فعلی را در settings.json ذخیره می‌کند.
    فقط keyهایی که در DEFAULT_SETTINGS تعریف شده‌اند ذخیره می‌شوند.
    """
    cfg: Dict[str, Any] = {}
    for k in DEFAULT_SETTINGS.keys():
        if k in data:
            cfg[k] = data[k]

    try:
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print("Error saving settings:", e)
