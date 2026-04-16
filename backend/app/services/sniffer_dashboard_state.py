from __future__ import annotations

import threading
from collections import Counter, deque
from typing import Any

from core.netbotpro_sniffer_core.ip_utils import is_local_ip, is_public_ip, preferred_remote_ip

def _is_local_ip(value: str | None) -> bool:
    return is_local_ip(value)


def _is_public_ip(value: str | None) -> bool:
    return is_public_ip(value)


def _preferred_remote_ip(*candidates: str | None) -> str | None:
    return preferred_remote_ip(*candidates)


def _remote_ip(packet: dict[str, Any]) -> str:
    remote_ip = str(packet.get("remote_ip") or "").strip()
    src = str(packet.get("src") or "").strip()
    dst = str(packet.get("dst") or "").strip()
    preferred = _preferred_remote_ip(dst, src, remote_ip)
    if preferred:
        return preferred

    if remote_ip:
        return remote_ip
    if src and dst:
        if _is_local_ip(src) and not _is_local_ip(dst):
            return dst
        if _is_local_ip(dst) and not _is_local_ip(src):
            return src
        return dst
    return dst or src or "-"


def _conversation_key(packet: dict[str, Any]) -> str:
    src = str(packet.get("src") or "-").strip() or "-"
    dst = str(packet.get("dst") or "-").strip() or "-"
    proto = str(packet.get("proto") or "OTHER").upper()
    return f"{src} -> {dst} ({proto})"


def _process_meta(packet: dict[str, Any]) -> dict[str, Any]:
    process_name = str(packet.get("process_name") or "").strip()
    pid = str(packet.get("pid") or "").strip()
    label = "Unknown process"
    if process_name and pid:
        label = f"{process_name} (PID {pid})"
    elif process_name:
        label = process_name
    elif pid:
        label = f"PID {pid}"
    return {
        "label": label,
        "process_name": process_name or None,
        "pid": pid or None,
    }


class SnifferDashboardState:
    def __init__(self, max_items: int = 300) -> None:
        self._lock = threading.Lock()
        self._packets: deque[dict[str, Any]] = deque(maxlen=max_items)
        self._alerts: deque[dict[str, Any]] = deque(maxlen=max_items)
        self._counter_src: Counter[str] = Counter()
        self._counter_dst: Counter[str] = Counter()
        self._counter_proto: Counter[str] = Counter()
        self._counter_process: Counter[str] = Counter()
        self._process_meta: dict[str, dict[str, Any]] = {}
        self._counter_remote: Counter[str] = Counter()
        self._counter_conversation: Counter[str] = Counter()
        self._total_packets = 0
        self._total_alerts = 0

    def add_packet(self, packet: dict[str, Any]) -> None:
        src = str(packet.get("src") or "-")
        dst = str(packet.get("dst") or "-")
        proto = str(packet.get("proto") or "OTHER").upper()
        process = _process_meta(packet)
        remote = _remote_ip(packet)
        conversation = _conversation_key(packet)
        with self._lock:
            self._total_packets += 1
            self._packets.appendleft(packet)
            self._counter_src[src] += 1
            self._counter_dst[dst] += 1
            self._counter_proto[proto] += 1
            self._counter_process[process["label"]] += 1
            self._process_meta[process["label"]] = process
            self._counter_remote[remote] += 1
            self._counter_conversation[conversation] += 1

    def add_alerts(self, alerts: list[dict[str, Any]]) -> None:
        if not alerts:
            return
        with self._lock:
            for alert in reversed(alerts):
                self._alerts.appendleft(alert)
                self._total_alerts += 1

    def reset(self) -> None:
        with self._lock:
            self._packets.clear()
            self._alerts.clear()
            self._counter_src.clear()
            self._counter_dst.clear()
            self._counter_proto.clear()
            self._counter_process.clear()
            self._process_meta.clear()
            self._counter_remote.clear()
            self._counter_conversation.clear()
            self._total_packets = 0
            self._total_alerts = 0

    def state(self, running: bool, iface: str | None) -> dict[str, Any]:
        with self._lock:
            return {
                "running": running,
                "iface": iface,
                "packet_count": len(self._packets),
                "total_packets": self._total_packets,
                "total_alerts": self._total_alerts,
            }

    def recent_packets(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._packets)

    def recent_alerts(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._alerts)

    def dashboard(self, running: bool, iface: str | None) -> dict[str, Any]:
        with self._lock:
            top_sources = [{"label": key, "count": value} for key, value in self._counter_src.most_common(5)]
            top_destinations = [{"label": key, "count": value} for key, value in self._counter_dst.most_common(5)]
            top_protocols = [{"label": key, "count": value} for key, value in self._counter_proto.most_common(5)]
            top_processes = [
                {
                    "label": key,
                    "count": value,
                    "process_name": self._process_meta.get(key, {}).get("process_name"),
                    "pid": self._process_meta.get(key, {}).get("pid"),
                }
                for key, value in self._counter_process.most_common(5)
            ]
            top_remotes = [{"label": key, "count": value} for key, value in self._counter_remote.most_common(5)]
            top_conversations = [{"label": key, "count": value} for key, value in self._counter_conversation.most_common(5)]
            recent_alerts = list(self._alerts)[:10]
            recent_packets = list(self._packets)[:10]
            state = {
                "running": running,
                "iface": iface,
                "packet_count": len(self._packets),
                "total_packets": self._total_packets,
                "total_alerts": self._total_alerts,
            }
        return {
            "state": state,
            "top_sources": top_sources,
            "top_destinations": top_destinations,
            "top_protocols": top_protocols,
            "top_processes": top_processes,
            "top_remotes": top_remotes,
            "top_conversations": top_conversations,
            "recent_alerts": recent_alerts,
            "recent_packets": recent_packets,
        }
