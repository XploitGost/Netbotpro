from __future__ import annotations

from pathlib import Path

from backend.app.bootstrap import ensure_project_root_on_path

ensure_project_root_on_path()

from log_manager import LOG_DIR  # noqa: E402


class ReportService:
    def list_reports(self) -> list[dict[str, str | int]]:
        root = Path(LOG_DIR).resolve()
        if not root.exists():
            return []
        items: list[dict[str, str | int]] = []
        for path in sorted(root.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True):
            if not path.is_file():
                continue
            stat = path.stat()
            items.append(
                {
                    "name": path.name,
                    "path": path.name,
                    "size": int(stat.st_size),
                    "modified": str(int(stat.st_mtime)),
                }
            )
        return items[:50]
