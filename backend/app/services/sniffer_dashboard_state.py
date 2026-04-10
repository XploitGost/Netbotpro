from __future__ import annotations

import threading
from collections import Counter, deque
import re
from typing import Any


def _is_private_ip(value: str | None) -> bool:
    text = str(value or "").strip()
    return (
        text.startswith("10.")
        or text.startswith("192.168.")
        or text.startswith("127.")
        or text.startswith("169.254.")
        or re.match(r"^172\.(1[6-9]|2\d|3[01])\.", text) is not None
    )


def _remote_ip(packet: dict[str, Any]) -> str:
    remote_ip = str(packet.get("remote_ip") or "").strip()
    if remote_ip:
        return remote_ip
    src = str(packet.get("src") or "").strip()
    dst = str(packet.get("dst") or "").strip()
    if src and dst:
        if _is_private_ip(src) and not _is_private_ip(dst):
            return dst
        if _is_private_ip(dst) and not _is_private_ip(src):
            return src
        return dst
    return dst or src or "-"


def _conversation_key(packet: dict[str, Any]) -> str:
    src = str(packet.get("src") or "-").strip() or "-"
    dst = str(packet.get("dst") or "-").strip() or "-"
    proto = str(packet.get("proto") or "OTHER").upper()
    return f"{src} -> {dst} ({proto})"


class SnifferDashboardState:
    def __init__(self, max_items: int = 300) -> None:
        self._lock = threading.Lock()
        self._packets: deque[dict[str, Any]] = deque(maxlen=max_items)
        self._alerts: deque[dict[str, Any]] = deque(maxlen=max_items)
        self._counter_src: Counter[str] = Counter()
        self._counter_dst: Counter[str] = Counter()
        self._counter_proto: Counter[str] = Counter()
        self._counter_remote: Counter[str] = Counter()
        self._counter_conversation: Counter[str] = Counter()
        self._total_packets = 0
        self._total_alerts = 0

    def add_packet(self, packet: dict[str, Any]) -> None:
        src = str(packet.get("src") or "-")
        dst = str(packet.get("dst") or "-")
        proto = str(packet.get("proto") or "OTHER").upper()
        remote = _remote_ip(packet)
        conversation = _conversation_key(packet)
        with self._lock:
            self._total_packets += 1
            self._packets.appendleft(packet)
            self._counter_src[src] += 1
            self._counter_dst[dst] += 1
            self._counter_proto[proto] += 1
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
            "top_remotes": top_remotes,
            "top_conversations": top_conversations,
            "recent_alerts": recent_alerts,
            "recent_packets": recent_packets,
        }
