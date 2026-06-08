from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.display_filter import compile_display_filter
from core.privacy_redaction import redact_sensitive_data, redact_sensitive_text

BUILTIN_FILTERS = (
    ("DNS traffic", "protocol == DNS"),
    ("HTTP errors", "http.status >= 400"),
    ("TLS traffic", "protocol == TLS"),
    ("High risk flows", "risk >= 60"),
    ("TCP resets", "tcp.flags.reset == true"),
    ("DNS failures", "dns.rcode != NOERROR"),
    ("External HTTP", "protocol == HTTP and direction == outbound"),
)


class SavedFilterService:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(
            path
            or os.environ.get(
                "NETBOT_SAVED_FILTERS_PATH", ".runtime/logs/saved_filters.json"
            )
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def _custom(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            return value if isinstance(value, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    def _write(self, rows: list[dict[str, Any]]) -> None:
        self.path.write_text(
            json.dumps(rows, indent=2, ensure_ascii=True), encoding="utf-8"
        )

    def list(self) -> list[dict[str, Any]]:
        builtins = [
            {
                "id": f"builtin-{index}",
                "name": name,
                "expression": expression,
                "description": "Built-in safe display filter",
                "is_builtin": True,
            }
            for index, (name, expression) in enumerate(BUILTIN_FILTERS, 1)
        ]
        with self._lock:
            return redact_sensitive_data(builtins + self._custom())

    def create(self, payload: dict[str, Any]) -> dict[str, Any]:
        expression = redact_sensitive_text(str(payload.get("expression") or "").strip())
        compile_display_filter(expression)
        now = datetime.now(timezone.utc).isoformat()
        row = {
            "id": f"filter-{uuid.uuid4().hex[:12]}",
            "name": redact_sensitive_text(
                str(payload.get("name") or "Saved filter").strip()
            )[:80],
            "expression": expression[:500],
            "description": redact_sensitive_text(
                str(payload.get("description") or "").strip()
            )[:240],
            "created_at": now,
            "updated_at": now,
            "is_builtin": False,
        }
        with self._lock:
            rows = self._custom()
            rows.append(row)
            self._write(rows)
        return row

    def update(self, filter_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            rows = self._custom()
            for row in rows:
                if row.get("id") != filter_id:
                    continue
                if "expression" in payload:
                    expression = redact_sensitive_text(
                        str(payload["expression"]).strip()
                    )
                    compile_display_filter(expression)
                    row["expression"] = expression[:500]
                for key, limit in (("name", 80), ("description", 240)):
                    if key in payload:
                        row[key] = redact_sensitive_text(str(payload[key]).strip())[
                            :limit
                        ]
                row["updated_at"] = datetime.now(timezone.utc).isoformat()
                self._write(rows)
                return row
        raise KeyError(filter_id)

    def delete(self, filter_id: str) -> None:
        with self._lock:
            rows = self._custom()
            remaining = [row for row in rows if row.get("id") != filter_id]
            if len(remaining) == len(rows):
                raise KeyError(filter_id)
            self._write(remaining)


__all__ = ["BUILTIN_FILTERS", "SavedFilterService"]
