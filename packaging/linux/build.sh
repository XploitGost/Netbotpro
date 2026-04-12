#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
cd "$REPO_ROOT"

python3 -m PyInstaller packaging/pyinstaller/netbotpro_backend.spec --noconfirm
python3 scripts/release/stage_backend_runtime.py
npm --prefix desktop/electron install
npm --prefix desktop/electron run dist -- --linux
