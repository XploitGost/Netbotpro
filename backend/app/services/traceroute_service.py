from __future__ import annotations

from collections import deque
from typing import Any

from fastapi import HTTPException

from backend.app.bootstrap import ensure_project_root_on_path
from backend.app.security import validate_traceroute_target

ensure_project_root_on_path()

from core.traceroute_tools import run_traceroute  # noqa: E402


class TracerouteService:
    def __init__(self) -> None:
        self._history: deque[dict[str, Any]] = deque(maxlen=30)

    def run(self, payload: dict[str, Any]) -> dict[str, Any]:
        target = validate_traceroute_target(str(payload.get("target") or ""))
        mode = self._normalize_mode(payload.get("mode"))
        timeout = self._clamp_float(payload.get("timeout"), default=1.5, minimum=0.2, maximum=10.0, field="timeout")
        max_hops = self._clamp_int(payload.get("max_hops"), default=30, minimum=1, maximum=64, field="max_hops")
        queries = self._clamp_int(payload.get("queries"), default=1, minimum=1, maximum=5, field="queries")
        port = self._clamp_int(payload.get("port"), default=443, minimum=1, maximum=65535, field="port")
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

    @staticmethod
    def _normalize_mode(value: Any) -> str:
        mode = str(value or "UDP").strip().upper()
        if mode not in {"UDP", "TCP", "ICMP"}:
            raise HTTPException(status_code=400, detail="Invalid traceroute mode")
        return mode

    @staticmethod
    def _clamp_float(value: Any, *, default: float, minimum: float, maximum: float, field: str) -> float:
        try:
            numeric = float(value if value not in (None, "") else default)
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"Invalid traceroute {field}") from exc
        return max(minimum, min(maximum, numeric))

    @staticmethod
    def _clamp_int(value: Any, *, default: int, minimum: int, maximum: int, field: str) -> int:
        try:
            numeric = int(value if value not in (None, "") else default)
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"Invalid traceroute {field}") from exc
        return max(minimum, min(maximum, numeric))
