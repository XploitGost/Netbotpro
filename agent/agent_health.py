from __future__ import annotations

import time
from typing import Any

import psutil


def collect_health() -> dict[str, Any]:
    boot_time = psutil.boot_time()
    disk = psutil.disk_usage("/")
    return {
        "cpu_percent": psutil.cpu_percent(interval=None),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_percent": disk.percent,
        "uptime_seconds": max(0, int(time.time() - boot_time)),
        "boot_time": int(boot_time),
        "process_count": len(psutil.pids()),
    }


def collect_network() -> dict[str, Any]:
    counters = psutil.net_io_counters() or None
    interfaces = []
    for name, addrs in psutil.net_if_addrs().items():
        addresses = []
        for item in addrs[:4]:
            address = getattr(item, "address", "")
            if address:
                addresses.append(str(address))
        interfaces.append({"name": name, "addresses": addresses[:4]})
    return {
        "interface_count": len(interfaces),
        "interfaces": interfaces[:24],
        "bytes_sent": int(getattr(counters, "bytes_sent", 0) or 0),
        "bytes_recv": int(getattr(counters, "bytes_recv", 0) or 0),
        "packets_sent": int(getattr(counters, "packets_sent", 0) or 0),
        "packets_recv": int(getattr(counters, "packets_recv", 0) or 0),
    }
