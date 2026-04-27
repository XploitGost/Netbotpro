from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.repositories import AlertListQuery, MemoryHistoryRepository, PacketListQuery


@dataclass
class _SyntheticSnifferService:
    packet_count: int = 6000
    remote_hosts: int = 120
    process_count: int = 8

    def recent_packets(self):
        packets = []
        for index in range(self.packet_count):
            remote_octet = (index % self.remote_hosts) + 10
            process_index = index % self.process_count
            packets.append(
                {
                    "id": f"perf-pkt-{index}",
                    "capture_id": f"perf-cap-{index}",
                    "ts": f"10:{(index // 60) % 60:02d}:{index % 60:02d}",
                    "src": "192.168.1.10" if index % 2 == 0 else f"198.51.100.{remote_octet}",
                    "dst": f"198.51.100.{remote_octet}" if index % 2 == 0 else "192.168.1.10",
                    "proto": "TCP",
                    "sport": 52000 + (index % 400),
                    "dport": 443 if index % 3 else 8443,
                    "direction": "OUTGOING" if index % 2 == 0 else "INCOMING",
                    "length": 90 + (index % 150),
                    "summary": f"synthetic-{index}",
                    "remote_ip": f"198.51.100.{remote_octet}",
                    "process_name": f"process-{process_index}.exe",
                    "pid": 3000 + process_index,
                    "parent_pid": 2000,
                    "parent_process_name": "services.exe",
                    "executable_path": f"C:/Program Files/Netbotpro/process-{process_index}.exe",
                    "attribution_confidence": "high",
                    "attribution_source": "synthetic",
                    "app_protocol": "HTTPS" if index % 3 else "HTTP",
                    "http_method": "GET" if index % 3 == 0 else None,
                    "http_host": "example.test" if index % 3 == 0 else None,
                    "http_path": f"/api/{index % 17}" if index % 3 == 0 else None,
                }
            )
        return list(reversed(packets))

    def recent_alerts(self):
        alerts = []
        for index in range(self.packet_count // 12):
            remote_octet = (index % self.remote_hosts) + 10
            process_index = index % self.process_count
            alerts.append(
                {
                    "id": f"perf-alert-{index}",
                    "ts": f"10:{(index // 60) % 60:02d}:{index % 60:02d}",
                    "src": f"198.51.100.{remote_octet}",
                    "dst": "192.168.1.10",
                    "proto": "TCP",
                    "sport": 443,
                    "dport": 52000 + (index % 400),
                    "direction": "INCOMING",
                    "attack_type": "Synthetic Alert",
                    "score": 0.61,
                    "detail": "Synthetic alert for perf smoke",
                    "severity": "MEDIUM",
                    "engine": "RULE",
                    "packet_id": f"perf-cap-{index * 2}",
                    "remote_ip": f"198.51.100.{remote_octet}",
                    "process_name": f"process-{process_index}.exe",
                    "pid": 3000 + process_index,
                }
            )
        return list(reversed(alerts))


def run_perf_smoke() -> dict[str, float | int | str]:
    repository = MemoryHistoryRepository(_SyntheticSnifferService())

    started = time.perf_counter()
    packets = repository.list_packets(PacketListQuery.from_raw({"limit": 25, "offset": 0}))
    packets_ms = round((time.perf_counter() - started) * 1000, 2)

    started = time.perf_counter()
    alerts = repository.list_alerts(AlertListQuery.from_raw({"limit": 25, "offset": 0}))
    alerts_ms = round((time.perf_counter() - started) * 1000, 2)

    selected_packet_id = str(packets["items"][0]["id"])
    started = time.perf_counter()
    context = repository.get_packet_flow_context(selected_packet_id)
    context_ms = round((time.perf_counter() - started) * 1000, 2)

    return {
        "packets_total": int(packets.get("total") or 0),
        "alerts_total": int(alerts.get("total") or 0),
        "packet_list_ms": packets_ms,
        "alert_list_ms": alerts_ms,
        "packet_context_ms": context_ms,
        "behavior_labels_total": len(context.get("behavior_labels") or []),
        "stream_status": str((context.get("stream_context") or {}).get("status") or "fallback"),
    }


def main() -> int:
    print(json.dumps(run_perf_smoke(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
