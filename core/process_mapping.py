# process_mapping.py
# -*- coding: utf-8 -*-
"""
Cross-platform process mapping (Linux + Windows) for NetBotPRO.
"""

from __future__ import annotations

import logging
import platform
import re
import socket
import subprocess
import time
from typing import Any, Dict, Optional, Tuple

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # type: ignore

logger = logging.getLogger(__name__)

_LAST_SCAN: float = 0.0
_CACHE: Dict[Tuple[str, int, str], Dict[str, Any]] = {}
_SCAN_INTERVAL = 3.0
_NETSTAT_TIMEOUT = 2.0


def _scan_with_psutil() -> None:
    global _CACHE, _LAST_SCAN
    if psutil is None:
        return
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        logger.debug("psutil net_connections failed", exc_info=True)
        return

    for c in conns:
        if not c.laddr:
            continue
        local_ip = getattr(c.laddr, "ip", None) or c.laddr[0]
        local_port = getattr(c.laddr, "port", None) or c.laddr[1]
        if not local_ip or not local_port:
            continue
        proto = None
        if c.type == socket.SOCK_STREAM:
            proto = "TCP"
        elif c.type == socket.SOCK_DGRAM:
            proto = "UDP"
        if proto is None:
            continue
        pid: Optional[int] = c.pid
        name: Optional[str] = None
        if pid is not None and pid > 0:
            try:
                p = psutil.Process(pid)  # type: ignore
                name = p.name()
            except Exception:
                name = None
        _CACHE[(local_ip, int(local_port), proto)] = {
            "pid": pid,
            "process_name": name or "unknown",
        }
    _LAST_SCAN = time.time()


def _scan_with_netstat_windows() -> None:
    global _CACHE, _LAST_SCAN
    if platform.system().lower() != "windows":
        return
    try:
        output = subprocess.check_output(
            ["netstat", "-ano"],
            text=True,
            stderr=subprocess.DEVNULL,  # type: ignore[arg-type]
            timeout=_NETSTAT_TIMEOUT,
        )
    except Exception:
        logger.debug("netstat fallback failed", exc_info=True)
        return

    tcp_re = re.compile(
        r"^(TCP)\s+(\S+):(\d+)\s+(\S+):(\d+|\*)\s+(\S+)\s+(\d+)$",
        re.IGNORECASE,
    )
    udp_re = re.compile(
        r"^(UDP)\s+(\S+):(\d+)\s+(\S+):(\d+|\*)\s+(\d+)$",
        re.IGNORECASE,
    )
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        pid: Optional[int] = None
        match = tcp_re.match(line)
        proto = None
        local_ip = None
        local_port = None
        if match:
            proto = match.group(1).upper()
            local_ip = match.group(2)
            try:
                local_port = int(match.group(3))
                pid = int(match.group(7))
            except Exception:
                continue
        else:
            match = udp_re.match(line)
            if not match:
                continue
            proto = match.group(1).upper()
            local_ip = match.group(2)
            try:
                local_port = int(match.group(3))
                pid = int(match.group(6))
            except Exception:
                continue

        if not local_ip or local_port is None or proto is None:
            continue
        name = None
        if psutil is not None and pid is not None:
            try:
                p = psutil.Process(pid)  # type: ignore
                name = p.name()
            except Exception:
                name = None
        _CACHE[(local_ip, local_port, proto)] = {
            "pid": pid,
            "process_name": name or "unknown",
        }
    _LAST_SCAN = time.time()


def _refresh_cache() -> None:
    global _CACHE
    _CACHE.clear()
    _scan_with_psutil()
    if _CACHE:
        return
    _scan_with_netstat_windows()


def get_process_for_flow(local_ip: str, local_port: Optional[int], proto: Optional[str]) -> Dict[str, Any]:
    if not local_ip or local_port is None or not proto:
        return {"pid": None, "process_name": None}
    now = time.time()
    if now - _LAST_SCAN > _SCAN_INTERVAL:
        _refresh_cache()
    key = (local_ip, int(local_port), proto.upper())
    info = _CACHE.get(key)
    if not info:
        return {"pid": None, "process_name": None}
    return info.copy()
