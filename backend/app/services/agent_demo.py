from __future__ import annotations

import argparse
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from backend.app.services.agent_registry import AgentRegistry

DEMO_TOKEN = "netbotpro-demo-token"

DEMO_PROFILES: list[dict[str, Any]] = [
    {
        "role": "Web Server",
        "hostname": "web-demo-01",
        "os": "Ubuntu Server 24.04",
        "health": {"cpu_percent": 18, "memory_percent": 34, "disk_percent": 41},
        "alerts": {"total_alerts": 1, "low_count": 1, "recent_alerts": []},
        "flows": {"flow_count": 320, "protocol_counts": {"HTTPS": 280, "DNS": 40}},
        "capture": {"capture_running": True, "capture_mode": "metadata"},
        "offline": False,
    },
    {
        "role": "Database Server",
        "hostname": "db-demo-01",
        "os": "Windows Server 2022",
        "health": {"cpu_percent": 88, "memory_percent": 91, "disk_percent": 73},
        "alerts": {"total_alerts": 5, "medium_count": 3, "high_count": 2},
        "flows": {"flow_count": 840, "protocol_counts": {"SQL": 650, "TLS": 190}},
        "capture": {"capture_running": True, "capture_mode": "metadata"},
        "offline": False,
    },
    {
        "role": "API Server",
        "hostname": "api-demo-01",
        "os": "Ubuntu Server 22.04",
        "health": {"cpu_percent": 66, "memory_percent": 72, "disk_percent": 58},
        "alerts": {
            "total_alerts": 9,
            "critical_count": 2,
            "high_count": 4,
            "medium_count": 3,
            "recent_alerts": [
                {"severity": "critical", "detail": "Repeated admin endpoint probing"}
            ],
        },
        "flows": {"flow_count": 1260, "protocol_counts": {"HTTPS": 1180, "DNS": 80}},
        "capture": {"capture_running": True, "capture_mode": "metadata"},
        "offline": False,
    },
    {
        "role": "File Server",
        "hostname": "files-demo-01",
        "os": "Windows Server 2019",
        "health": {"cpu_percent": 8, "memory_percent": 27, "disk_percent": 82},
        "alerts": {"total_alerts": 0, "recent_alerts": []},
        "flows": {"flow_count": 120, "protocol_counts": {"SMB": 110, "DNS": 10}},
        "capture": {"capture_running": False, "capture_mode": "metadata"},
        "offline": True,
    },
]


def _agent_id(index: int) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"netbotpro-demo-agent-{index}"))


def _sample_payload(profile: dict[str, Any], index: int) -> dict[str, Any]:
    return {
        "source": "demo_seed",
        "health": profile["health"],
        "network": {
            "interface_count": 2,
            "bytes_sent": 1_500_000 + index * 180_000,
            "bytes_received": 4_250_000 + index * 220_000,
        },
        "capture": profile["capture"],
        "alerts_summary": profile["alerts"],
        "flows_summary": profile["flows"],
    }


def seed_demo_data(
    db_path: str | Path,
    *,
    count: int = 4,
    reset: bool = False,
) -> dict[str, Any]:
    registry = AgentRegistry(db_path)
    removed = registry.delete_demo_agents() if reset else 0
    created: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    for index in range(max(1, min(50, count))):
        profile = DEMO_PROFILES[index % len(DEMO_PROFILES)]
        agent_id = _agent_id(index + 1)
        registered = registry.register(
            {
                "agent_id": agent_id,
                "hostname": (
                    profile["hostname"]
                    if index < len(DEMO_PROFILES)
                    else f"{profile['hostname']}-{index + 1}"
                ),
                "display_name": (
                    profile["role"]
                    if index < len(DEMO_PROFILES)
                    else f"{profile['role']} {index + 1}"
                ),
                "os": profile["os"],
                "platform": "windows" if "Windows" in profile["os"] else "linux",
                "agent_version": "demo",
                "capabilities": [
                    "health",
                    "capture_status",
                    "alerts_summary",
                    "flows_summary",
                    "demo",
                ],
            },
            DEMO_TOKEN,
        )
        registry.heartbeat(agent_id, {"status": "online", "source": "demo_seed"})
        registry.telemetry(agent_id, _sample_payload(profile, index))
        if profile["offline"]:
            registry.set_agent_last_seen(
                agent_id,
                (now - timedelta(minutes=12)).isoformat(),
                status="online",
            )
        created.append(registered)
    return {
        "ok": True,
        "database": str(Path(db_path)),
        "reset": reset,
        "removed_demo_agents": removed,
        "created_agents": len(created),
        "agent_ids": [item["agent_id"] for item in created],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed NetBotPro demo agent data.")
    parser.add_argument("--db-path", default=".runtime/logs/agents.db")
    parser.add_argument("--count", type=int, default=4)
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args()
    result = seed_demo_data(args.db_path, count=args.count, reset=args.reset)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
