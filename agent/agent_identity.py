from __future__ import annotations

import json
import platform
import socket
import uuid
from pathlib import Path
from typing import Any

AGENT_VERSION = "0.1.3"
AGENT_CAPABILITIES = ["health", "capture_status", "alerts_summary", "flows_summary"]


def default_identity_path(base_dir: str | Path | None = None) -> Path:
    root = Path(base_dir) if base_dir else Path.cwd()
    return root / ".runtime" / "agent-identity.json"


def _valid_uuid(value: str) -> str:
    return str(uuid.UUID(str(value).strip()))


def load_or_create_agent_id(path: str | Path, configured_agent_id: str = "") -> str:
    identity_path = Path(path)
    if configured_agent_id:
        agent_id = _valid_uuid(configured_agent_id)
        identity_path.parent.mkdir(parents=True, exist_ok=True)
        identity_path.write_text(
            json.dumps({"agent_id": agent_id}, indent=2), encoding="utf-8"
        )
        return agent_id
    if identity_path.exists():
        try:
            data = json.loads(identity_path.read_text(encoding="utf-8"))
            return _valid_uuid(str(data.get("agent_id") or ""))
        except Exception:
            pass
    agent_id = str(uuid.uuid4())
    identity_path.parent.mkdir(parents=True, exist_ok=True)
    identity_path.write_text(
        json.dumps({"agent_id": agent_id}, indent=2), encoding="utf-8"
    )
    return agent_id


def build_registration_payload(agent_id: str, display_name: str = "") -> dict[str, Any]:
    hostname = socket.gethostname() or "unknown"
    return {
        "agent_id": agent_id,
        "hostname": hostname,
        "display_name": display_name or hostname,
        "os": f"{platform.system()} {platform.release()}".strip(),
        "platform": platform.system().lower() or platform.platform(),
        "os_version": platform.version(),
        "machine": platform.machine(),
        "agent_version": AGENT_VERSION,
        "capabilities": list(AGENT_CAPABILITIES),
    }
