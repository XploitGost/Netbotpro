$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\\..")).Path
$VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
$FrontendNodeModules = Join-Path $RepoRoot "frontend\node_modules"
$DesktopNodeModules = Join-Path $RepoRoot "desktop\electron\node_modules"
$ElectronBinary = Join-Path $RepoRoot "desktop\electron\node_modules\electron\dist\electron.exe"
$NpcapDll = Join-Path $env:WINDIR "System32\Npcap\Packet.dll"

function Test-PortListening {
    param([int]$Port)
    $connections = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    return [bool]$connections
}

function Test-HttpReady {
    param([string]$Uri)
    try {
        $null = Invoke-WebRequest -UseBasicParsing -Uri $Uri -TimeoutSec 5
        return $true
    } catch {
        return $false
    }
}

function Write-Check {
    param(
        [string]$Name,
        [bool]$Ok,
        [string]$Detail
    )

    $status = if ($Ok) { "OK" } else { "FAIL" }
    Write-Host ("[{0}] {1} - {2}" -f $status, $Name, $Detail)
}

Set-Location $RepoRoot

$pythonOk = Test-Path $VenvPython
Write-Check -Name ".venv python" -Ok $pythonOk -Detail ($(if ($pythonOk) { $VenvPython } else { "Run scripts\\dev\\setup.ps1" }))

$depsOk = $false
if ($pythonOk) {
    try {
        & $VenvPython -c "import fastapi, uvicorn, pandas, scapy, sklearn" | Out-Null
        $depsOk = $true
    } catch {
        $depsOk = $false
    }
}
Write-Check -Name "python dependencies" -Ok $depsOk -Detail ($(if ($depsOk) { "Core backend dependencies import cleanly" } else { "Install dependencies with scripts\\dev\\setup.ps1" }))

$frontendDepsOk = Test-Path $FrontendNodeModules
Write-Check -Name "frontend node_modules" -Ok $frontendDepsOk -Detail ($(if ($frontendDepsOk) { $FrontendNodeModules } else { "Run scripts\\dev\\setup.ps1" }))

$desktopDepsOk = Test-Path $DesktopNodeModules
Write-Check -Name "desktop node_modules" -Ok $desktopDepsOk -Detail ($(if ($desktopDepsOk) { $DesktopNodeModules } else { "Run scripts\\dev\\setup.ps1" }))

$electronBinaryOk = Test-Path $ElectronBinary
Write-Check -Name "electron binary" -Ok $electronBinaryOk -Detail ($(if ($electronBinaryOk) { $ElectronBinary } else { "Run npm install in desktop\\electron until Electron binary download completes" }))

$npcapOk = Test-Path $NpcapDll
Write-Check -Name "Npcap runtime" -Ok $npcapOk -Detail ($(if ($npcapOk) { $NpcapDll } else { "Install Npcap with scripts\\dev\\install-npcap.ps1 for live capture" }))

$backendReady = Test-HttpReady -Uri "http://127.0.0.1:8765/api/status"
$backendPortBusy = Test-PortListening -Port 8765
Write-Check -Name "backend port 8765" -Ok ($backendReady -or -not $backendPortBusy) -Detail ($(if ($backendReady) { "NetBotPro backend is already running" } elseif ($backendPortBusy) { "Port already in use by another process" } else { "Ready" }))

$frontendReady = Test-HttpReady -Uri "http://127.0.0.1:5173"
$frontendPortBusy = Test-PortListening -Port 5173
Write-Check -Name "frontend port 5173" -Ok ($frontendReady -or -not $frontendPortBusy) -Detail ($(if ($frontendReady) { "NetBotPro frontend is already running" } elseif ($frontendPortBusy) { "Port already in use by another process" } else { "Ready" }))
