from __future__ import annotations

import shutil
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DIST_BUNDLE_DIR = PROJECT_ROOT / "dist" / "netbotpro-backend"
PACKAGED_BACKEND_DIR = PROJECT_ROOT / "packaging" / "runtime" / "backend"


def expected_binary_name(platform_name: str | None = None) -> str:
    effective_platform = platform_name or sys.platform
    return "netbotpro-backend.exe" if effective_platform.startswith("win") else "netbotpro-backend"


def stage_backend_runtime(
    source_bundle_dir: Path = DIST_BUNDLE_DIR,
    packaged_backend_dir: Path = PACKAGED_BACKEND_DIR,
) -> Path:
    source_bundle_dir = Path(source_bundle_dir)
    packaged_backend_dir = Path(packaged_backend_dir)

    if not source_bundle_dir.exists():
        raise FileNotFoundError(f"PyInstaller bundle not found: {source_bundle_dir}")

    binary_name = expected_binary_name()
    binary_path = source_bundle_dir / binary_name
    if not binary_path.exists():
        raise FileNotFoundError(f"Packaged backend binary not found: {binary_path}")

    if packaged_backend_dir.exists():
        shutil.rmtree(packaged_backend_dir)
    packaged_backend_dir.mkdir(parents=True, exist_ok=True)

    for entry in source_bundle_dir.iterdir():
        destination = packaged_backend_dir / entry.name
        if entry.is_dir():
            shutil.copytree(entry, destination)
        else:
            shutil.copy2(entry, destination)

    return packaged_backend_dir / binary_name


def main() -> int:
    staged_binary = stage_backend_runtime()
    print(f"Staged backend runtime to {staged_binary.parent}")
    print(f"Backend binary: {staged_binary.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
