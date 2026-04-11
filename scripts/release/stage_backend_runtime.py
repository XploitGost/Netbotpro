from __future__ import annotations

import shutil
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DIST_DIR = REPO_ROOT / "dist" / "netbotpro-backend"
RUNTIME_DIR = REPO_ROOT / "packaging" / "runtime" / "backend"


def find_executable(bundle_dir: Path) -> Path:
    candidates = [
        bundle_dir / "netbotpro-backend.exe",
        bundle_dir / "netbotpro-backend",
    ]
    executable = next((path for path in candidates if path.exists()), None)
    if executable is None:
        raise SystemExit(f"backend executable not found in {bundle_dir}")
    return executable


def stage_runtime_bundle(source_dir: Path, runtime_dir: Path) -> Path:
    if not source_dir.exists():
        raise SystemExit(f"backend bundle not found: {source_dir}")

    executable = find_executable(source_dir)
    if runtime_dir.exists():
        shutil.rmtree(runtime_dir)
    shutil.copytree(source_dir, runtime_dir)
    return runtime_dir / executable.name


def main() -> int:
    target = stage_runtime_bundle(DIST_DIR, RUNTIME_DIR)
    print(f"staged backend runtime: {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
