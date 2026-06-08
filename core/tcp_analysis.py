from __future__ import annotations

from collections import Counter
from typing import Any


def _flags(packet: dict[str, Any]) -> set[str]:
    raw = str(packet.get("flags") or packet.get("tcp_flags") or "").upper()
    names = {
        "S": "SYN",
        "A": "ACK",
        "F": "FIN",
        "R": "RST",
        "P": "PSH",
        "U": "URG",
        "E": "ECE",
        "C": "CWR",
    }
    return {name for marker, name in names.items() if marker in raw}


def analyze_tcp_packets(packets: list[dict[str, Any]]) -> dict[str, Any]:
    tcp_packets = [
        packet for packet in packets if str(packet.get("proto") or "").upper() == "TCP"
    ]
    flags = Counter(flag for packet in tcp_packets for flag in _flags(packet))
    syn_seen = flags["SYN"] > 0
    syn_ack_seen = any(
        {"SYN", "ACK"}.issubset(_flags(packet)) for packet in tcp_packets
    )
    ack_seen = flags["ACK"] > 0
    resets = flags["RST"]
    duplicate_acks = sum(bool(packet.get("duplicate_ack")) for packet in tcp_packets)
    retransmissions = sum(bool(packet.get("retransmission")) for packet in tcp_packets)
    zero_windows = sum(int(packet.get("window") or 1) == 0 for packet in tcp_packets)
    handshake_complete = syn_seen and syn_ack_seen and ack_seen
    hints: list[dict[str, Any]] = []

    def hint(kind: str, title: str, count: int, action: str) -> None:
        if count:
            hints.append(
                {
                    "type": kind,
                    "severity": "warn",
                    "title": title,
                    "count": count,
                    "recommended_action": action,
                }
            )

    hint("tcp_reset", "TCP resets observed", resets, "Review flow termination.")
    hint(
        "tcp_duplicate_ack",
        "Duplicate ACK hints observed",
        duplicate_acks,
        "Check latency and packet loss.",
    )
    hint(
        "tcp_retransmission",
        "Retransmission hints observed",
        retransmissions,
        "Inspect path quality and congestion.",
    )
    hint(
        "tcp_zero_window",
        "Zero-window hints observed",
        zero_windows,
        "Inspect receiver pressure.",
    )
    if syn_seen and not handshake_complete:
        hint(
            "tcp_incomplete_handshake",
            "TCP handshake appears incomplete",
            1,
            "Validate reachability and firewall policy.",
        )

    return {
        "total_packets": len(tcp_packets),
        "flags": dict(flags),
        "syn_seen": syn_seen,
        "syn_ack_seen": syn_ack_seen,
        "ack_seen": ack_seen,
        "handshake_complete": handshake_complete,
        "handshake_incomplete": syn_seen and not handshake_complete,
        "resets": resets,
        "duplicate_ack_hints": duplicate_acks,
        "retransmission_hints": retransmissions,
        "zero_window_hints": zero_windows,
        "expert_hints": hints,
    }


__all__ = ["analyze_tcp_packets"]
