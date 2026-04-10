from __future__ import annotations

import os
import sys
from pathlib import Path


def ensure_project_root_on_path() -> Path:
    project_root = Path(__file__).resolve().parents[2]
    root_str = str(project_root)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    cache_root = project_root / ".runtime-cache"
    scapy_cache = cache_root / "scapy"
    scapy_cache.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("XDG_CACHE_HOME", str(cache_root))
    os.environ.setdefault("SCAPY_CACHE_FOLDER", str(scapy_cache))
    return project_root
