$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $RepoRoot

python -m PyInstaller packaging\pyinstaller\netbotpro_backend.spec --noconfirm
New-Item -ItemType Directory -Force -Path packaging\runtime\backend | Out-Null
Copy-Item -Force dist\netbotpro-backend\netbotpro-backend.exe packaging\runtime\backend\netbotpro-backend.exe
npm --prefix desktop\electron install
npm --prefix desktop\electron run dist -- --win
