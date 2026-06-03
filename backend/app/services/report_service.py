from __future__ import annotations

from pathlib import Path
import time

from backend.app.bootstrap import ensure_project_root_on_path
from backend.app.security import validate_report_download_path

ensure_project_root_on_path()

from log_manager import LOG_DIR  # noqa: E402


class ReportService:
    def cleanup_retention(self, retention_minutes: int) -> int:
        try:
            minutes = int(retention_minutes)
        except Exception:
            return 0
        if minutes <= 0:
            return 0
        cutoff = time.time() - minutes * 60
        removed = 0
        root = Path(LOG_DIR).resolve()
        if not root.exists():
            return 0
        for path in root.glob("*"):
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                validate_report_download_path(path.name)
                if path.stat().st_mtime >= cutoff:
                    continue
                path.unlink()
                removed += 1
            except Exception:
                continue
        return removed

    def list_reports(self) -> list[dict[str, str | int]]:
        root = Path(LOG_DIR).resolve()
        if not root.exists():
            return []
        candidates: list[tuple[float, Path]] = []
        for path in root.glob("*"):
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                stat = path.stat()
            except OSError:
                continue
            candidates.append((stat.st_mtime, path))
        items: list[dict[str, str | int]] = []
        for _, path in sorted(candidates, key=lambda item: item[0], reverse=True):
            try:
                safe_name = validate_report_download_path(path.name)
                stat = path.stat()
            except Exception:
                continue
            items.append(
                {
                    "name": safe_name,
                    "path": safe_name,
                    "size": int(stat.st_size),
                    "modified": str(int(stat.st_mtime)),
                }
            )
        return items[:50]
