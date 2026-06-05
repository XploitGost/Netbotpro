param(
    [int]$AgentCount = 4,
    [int]$BackendPort = 8765,
    [switch]$StartFrontend
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$RuntimeDir = Join-Path $RepoRoot ".runtime"
$LogDir = Join-Path $RuntimeDir "logs"
$BackendPidFile = Join-Path $RuntimeDir "demo-backend.pid"
$FrontendPidFile = Join-Path $RuntimeDir "demo-frontend.pid"
$TokenFile = Join-Path $RuntimeDir "demo-local-token.txt"
$AgentDbPath = Join-Path $LogDir "agents.db"
$BackendLog = Join-Path $LogDir "demo-backend.log"
$BackendErrLog = Join-Path $LogDir "demo-backend.err.log"
$FrontendLog = Join-Path $LogDir "demo-frontend.log"
$FrontendErrLog = Join-Path $LogDir "demo-frontend.err.log"
$FrontendDir = Join-Path $RepoRoot "frontend"
$DashboardUrl = "http://127.0.0.1:5173/?page=agents"
$BackendStatusUrl = "http://127.0.0.1:$BackendPort/api/status"

function Resolve-PythonExe {
    $VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
    if (Test-Path $VenvPython) {
        return $VenvPython
    }
    $Python = Get-Command python -ErrorAction SilentlyContinue
    if ($Python) {
        return $Python.Source
    }
    throw "Python is required. Install Python, then run: python -m pip install -r requirements-dev.txt"
}

function Test-HttpReady {
    param([string]$Uri)
    try {
        $null = Invoke-WebRequest -UseBasicParsing -Uri $Uri -TimeoutSec 3
        return $true
    } catch {
        return $false
    }
}

function Get-ListeningPid {
    param([int]$Port)
    $Owner = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty OwningProcess -First 1
    if ($Owner) {
        return [int]$Owner
    }
    return $null
}

function Resolve-DemoToken {
    if (Test-Path $TokenFile) {
        $Existing = (Get-Content -LiteralPath $TokenFile -Raw -ErrorAction SilentlyContinue).Trim()
        if ($Existing) {
            return $Existing
        }
    }
    $Bytes = [byte[]]::new(32)
    $Rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $Rng.GetBytes($Bytes)
    } finally {
        $Rng.Dispose()
    }
    $Token = ([System.BitConverter]::ToString($Bytes) -replace "-", "").ToLowerInvariant()
    Set-Content -LiteralPath $TokenFile -Value $Token -Encoding ascii
    return $Token
}

New-Item -ItemType Directory -Force -Path $RuntimeDir, $LogDir | Out-Null
$PythonExe = Resolve-PythonExe

& $PythonExe -c "import fastapi, uvicorn" 2>$null
if ($LASTEXITCODE -ne 0) {
    throw "Backend requirements are missing. Run: python -m pip install -r requirements-dev.txt"
}

$DemoToken = Resolve-DemoToken

if (-not (Test-HttpReady -Uri $BackendStatusUrl)) {
    $env:NETBOT_HOST = "127.0.0.1"
    $env:NETBOT_PORT = [string]$BackendPort
    $env:NETBOT_LOCAL_TOKEN = $DemoToken
    $env:NETBOT_ALLOWED_ORIGINS = "http://127.0.0.1:5173,http://localhost:5173"

    $Backend = Start-Process `
        -FilePath $PythonExe `
        -ArgumentList @("-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", [string]$BackendPort) `
        -WorkingDirectory $RepoRoot `
        -RedirectStandardOutput $BackendLog `
        -RedirectStandardError $BackendErrLog `
        -WindowStyle Hidden `
        -PassThru

    Start-Sleep -Seconds 3
    if (-not (Test-HttpReady -Uri $BackendStatusUrl)) {
        throw "Demo backend failed to start. Review: $BackendErrLog"
    }
    $BackendPid = Get-ListeningPid -Port $BackendPort
    if (-not $BackendPid) {
        $BackendPid = $Backend.Id
    }
    Set-Content -LiteralPath $BackendPidFile -Value $BackendPid -Encoding ascii
    Write-Host "Demo backend started with PID $BackendPid"
} else {
    Write-Host "Reusing the backend already listening on port $BackendPort"
}

Push-Location $RepoRoot
$PreviousAgentToken = $env:NETBOT_AGENT_TOKEN
try {
    $env:NETBOT_AGENT_TOKEN = ""
    & $PythonExe -m backend.app.services.agent_demo --db-path $AgentDbPath --count $AgentCount --reset
    if ($LASTEXITCODE -ne 0) {
        throw "Demo Agent seed failed."
    }
} finally {
    $env:NETBOT_AGENT_TOKEN = $PreviousAgentToken
    Pop-Location
}

if ($StartFrontend) {
    if (-not (Test-Path (Join-Path $FrontendDir "node_modules"))) {
        throw "Frontend dependencies are missing. Run: cd frontend; npm ci"
    }
    if (-not (Test-HttpReady -Uri "http://127.0.0.1:5173")) {
        $Frontend = Start-Process `
            -FilePath "npm.cmd" `
            -ArgumentList @("run", "dev", "--", "--host", "127.0.0.1") `
            -WorkingDirectory $FrontendDir `
            -RedirectStandardOutput $FrontendLog `
            -RedirectStandardError $FrontendErrLog `
            -WindowStyle Hidden `
            -PassThru
        Set-Content -LiteralPath $FrontendPidFile -Value $Frontend.Id -Encoding ascii
        Write-Host "Demo frontend started with PID $($Frontend.Id)"
    } else {
        Write-Host "Reusing the frontend already listening on port 5173"
    }
}

Write-Host ""
Write-Host "NetBotPro v0.2.0 demo is ready."
Write-Host "Dashboard: $DashboardUrl"
Write-Host "Agent database: $AgentDbPath"
Write-Host "Token file: $TokenFile"
Write-Host "Backend logs: $BackendLog | $BackendErrLog"
Write-Host "The raw token is never printed by this command."

if (-not $StartFrontend) {
    Write-Host ""
    Write-Host "Next command:"
    Write-Host "cd frontend"
    Write-Host "npm run dev"
}
