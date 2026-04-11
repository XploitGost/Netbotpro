#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
cd "$REPO_ROOT"

python3 -m PyInstaller packaging/pyinstaller/netbotpro_backend.spec --noconfirm
mkdir -p packaging/runtime/backend
cp dist/netbotpro-backend/netbotpro-backend packaging/runtime/backend/netbotpro-backend
npm --prefix desktop/electron install
npm --prefix desktop/electron run dist -- --linux
