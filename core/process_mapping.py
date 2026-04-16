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


def _unavailable_process_info(reason: str) -> Dict[str, Any]:
    return {
        "pid": None,
        "process_name": None,
        "parent_pid": None,
        "parent_process_name": None,
        "executable_path": None,
        "attribution_confidence": "unavailable",
        "attribution_reason_unavailable": reason,
        "attribution_source": "unavailable",
    }


def _safe_process_metadata(pid: Optional[int]) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "pid": pid,
        "process_name": None,
        "parent_pid": None,
        "parent_process_name": None,
        "executable_path": None,
    }
    if psutil is None or pid is None or pid <= 0:
        return info
    try:
        process = psutil.Process(pid)  # type: ignore
        info["process_name"] = process.name()
    except Exception:
        process = None
    if process is None:
        return info
    try:
        info["executable_path"] = process.exe() or None
    except Exception:
        info["executable_path"] = None
    try:
        parent_pid = process.ppid()
        info["parent_pid"] = parent_pid or None
    except Exception:
        parent_pid = None
        info["parent_pid"] = None
    if parent_pid:
        try:
            parent = psutil.Process(parent_pid)  # type: ignore
            info["parent_process_name"] = parent.name()
        except Exception:
            info["parent_process_name"] = None
    return info


def _confidence_for_metadata(info: Dict[str, Any], *, source: str) -> str:
    if not info.get("pid") and not info.get("process_name"):
        return "unavailable"
    if source == "netstat":
        return "medium"
    if info.get("executable_path") and info.get("parent_process_name"):
        return "high"
    if info.get("process_name"):
        return "medium"
    return "low"


def _finalize_process_info(info: Dict[str, Any], *, source: str, reason: str | None = None) -> Dict[str, Any]:
    if not info.get("pid") and not info.get("process_name"):
        return _unavailable_process_info(reason or "No active socket match / kernel-owned / stale mapping.")
    return {
        "pid": info.get("pid"),
        "process_name": info.get("process_name"),
        "parent_pid": info.get("parent_pid"),
        "parent_process_name": info.get("parent_process_name"),
        "executable_path": info.get("executable_path"),
        "attribution_confidence": _confidence_for_metadata(info, source=source),
        "attribution_reason_unavailable": None,
        "attribution_source": source,
    }


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
        info = _safe_process_metadata(pid)
        _CACHE[(local_ip, int(local_port), proto)] = _finalize_process_info(info, source="psutil")
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
        info = _safe_process_metadata(pid)
        _CACHE[(local_ip, local_port, proto)] = _finalize_process_info(info, source="netstat")
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
        return _unavailable_process_info("No local socket key was available for process attribution.")
    now = time.time()
    if now - _LAST_SCAN > _SCAN_INTERVAL:
        _refresh_cache()
    key = (local_ip, int(local_port), proto.upper())
    info = _CACHE.get(key)
    if not info:
        if psutil is None and platform.system().lower() != "windows":
            return _unavailable_process_info("Process attribution is unavailable in this runtime.")
        return _unavailable_process_info("No active socket match / kernel-owned / stale mapping.")
    return info.copy()
