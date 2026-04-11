$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $RepoRoot

python -m PyInstaller packaging\pyinstaller\netbotpro_backend.spec --noconfirm
python scripts\release\stage_backend_runtime.py
npm --prefix desktop\electron install
npm --prefix desktop\electron run dist -- --win
