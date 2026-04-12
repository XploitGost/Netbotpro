from __future__ import annotations

import os
import sys
from pathlib import Path


def runtime_cache_root() -> Path:
    cache_override = os.environ.get("NETBOT_CACHE_DIR")
    if cache_override:
        return Path(cache_override)

    data_dir = os.environ.get("NETBOT_DATA_DIR")
    if data_dir:
        return Path(data_dir) / "cache"

    xdg_cache_home = os.environ.get("XDG_CACHE_HOME")
    if xdg_cache_home:
        return Path(xdg_cache_home) / "netbotpro"

    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "Netbotpro" / "cache"

    return Path.home() / ".netbotpro" / "cache"


def ensure_project_root_on_path() -> Path:
    project_root = Path(__file__).resolve().parents[2]
    root_str = str(project_root)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    cache_root = runtime_cache_root()
    scapy_cache = cache_root / "scapy"
    scapy_cache.mkdir(parents=True, exist_ok=True)
    os.environ["XDG_CACHE_HOME"] = str(cache_root)
    os.environ["SCAPY_CACHE_FOLDER"] = str(scapy_cache)
    return project_root
