from __future__ import annotations

from collections import deque
from typing import Any

from backend.app.bootstrap import ensure_project_root_on_path
from backend.app.security import validate_traceroute_target

ensure_project_root_on_path()

from core.traceroute_tools import run_traceroute  # noqa: E402


class TracerouteService:
    def __init__(self) -> None:
        self._history: deque[dict[str, Any]] = deque(maxlen=30)

    def run(self, payload: dict[str, Any]) -> dict[str, Any]:
        target = validate_traceroute_target(str(payload.get("target") or ""))
        mode = str(payload.get("mode") or "UDP").upper()
        timeout = float(payload.get("timeout") or 1.5)
        max_hops = int(payload.get("max_hops") or 30)
        queries = int(payload.get("queries") or 1)
        port = int(payload.get("port") or 443)
        hops = run_traceroute(
            target=target,
            mode=mode,
            timeout=timeout,
            max_hops=max_hops,
            queries=queries,
            port=port,
        )
        result = {
            "target": target,
            "mode": mode,
            "timeout": timeout,
            "max_hops": max_hops,
            "queries": queries,
            "port": port,
            "hops": hops,
        }
        self._history.appendleft(result)
        return result

    def history(self) -> list[dict[str, Any]]:
        return list(self._history)
