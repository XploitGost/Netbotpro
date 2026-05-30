$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$downloadDir = Join-Path $RepoRoot ".downloads"
$installer = Join-Path $downloadDir "npcap-1.88.exe"
$url = "https://npcap.com/dist/npcap-1.88.exe"

New-Item -ItemType Directory -Force -Path $downloadDir | Out-Null

if (-not (Test-Path $installer)) {
    Write-Host "Downloading Npcap installer..."
    Invoke-WebRequest -Uri $url -OutFile $installer
} else {
    Write-Host "Reusing existing installer: $installer"
}

Write-Host "Launching Npcap installer as Administrator."
Write-Host "Recommended option: Install Npcap in WinPcap API-compatible Mode."
Start-Process -FilePath $installer -Verb RunAs -Wait

$npcapDll = Join-Path $env:WINDIR "System32\Npcap\Packet.dll"
if (Test-Path $npcapDll) {
    Write-Host "[OK] Npcap runtime detected: $npcapDll"
} else {
    Write-Host "[WARN] Npcap runtime was not detected yet. Restart Windows or rerun the installer if capture still reports 0 interfaces."
}
