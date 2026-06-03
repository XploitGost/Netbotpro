param(
    [string]$BindHost = "0.0.0.0",
    [int]$Port = 8765,
    [string]$AllowedOrigins = "",
    [string]$Token = "",
    [string]$CaptureMode = "metadata",
    [string]$Allowlist = "",
    [switch]$ShowToken,
    [switch]$Background
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$RuntimeDir = Join-Path $RepoRoot ".runtime"
$LogDir = Join-Path $RuntimeDir "logs"
$TokenFile = Join-Path $RuntimeDir "sensor-token.txt"
$PidFile = Join-Path $RuntimeDir "sensor-backend.pid"
$StdoutLog = Join-Path $LogDir "sensor-backend.log"
$StderrLog = Join-Path $LogDir "sensor-backend.err.log"

New-Item -ItemType Directory -Force -Path $RuntimeDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function Resolve-PythonBin {
    $candidate = Join-Path $RepoRoot ".venv\Scripts\python.exe"
    if (Test-Path $candidate) {
        return (Resolve-Path $candidate).Path
    }
    throw "No local project Python runtime was found. Run scripts\dev\setup.ps1 first."
}

function New-SecureToken {
    $bytes = [byte[]]::new(32)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    return ([System.BitConverter]::ToString($bytes) -replace "-", "").ToLowerInvariant()
}

function Resolve-SensorToken {
    if ($Token.Trim()) {
        return $Token.Trim()
    }
    $configured = [string]$env:NETBOT_LOCAL_TOKEN
    if ($configured.Trim()) {
        return $configured.Trim()
    }
    if (Test-Path $TokenFile) {
        $existing = (Get-Content -Path $TokenFile -Raw -ErrorAction SilentlyContinue).Trim()
        if ($existing) {
            return $existing
        }
    }
    $generated = New-SecureToken
    Set-Content -Path $TokenFile -Value $generated -Encoding ascii
    return $generated
}

$PythonBin = Resolve-PythonBin
$SensorToken = Resolve-SensorToken
$EffectiveOrigins = $AllowedOrigins.Trim()
if (-not $EffectiveOrigins) {
    $EffectiveOrigins = "http://127.0.0.1:5173,http://localhost:5173"
}

$env:NETBOT_HOST = $BindHost
$env:NETBOT_PORT = [string]$Port
$env:NETBOT_REMOTE_ACCESS = "1"
$env:NETBOT_LOCAL_TOKEN = $SensorToken
$env:NETBOT_ALLOWED_ORIGINS = $EffectiveOrigins
$env:NETBOT_CAPTURE_MODE = $CaptureMode
if ($Allowlist.Trim()) {
    $env:NETBOT_REMOTE_IP_ALLOWLIST = $Allowlist.Trim()
}

$uvicornArgs = @(
    "-m", "uvicorn",
    "backend.app.main:app",
    "--host", $BindHost,
    "--port", [string]$Port
)

Write-Host "NetBotPro sensor mode"
Write-Host "Backend bind: http://$BindHost`:$Port"
Write-Host "Remote access: enabled"
Write-Host "Allowed origins: $EffectiveOrigins"
Write-Host "Capture mode: $CaptureMode"
Write-Host "Remote IP allowlist: $(if ($env:NETBOT_REMOTE_IP_ALLOWLIST) { $env:NETBOT_REMOTE_IP_ALLOWLIST } else { '<not set>' })"
Write-Host "Token file: $TokenFile"
if ($ShowToken) {
    Write-Host "Token: $SensorToken"
}
Write-Host "PID file: $PidFile"
Write-Host "Logs: $StdoutLog | $StderrLog"
Write-Host "Dashboard hint: http://127.0.0.1:5173/?api=http://SERVER_IP:$Port/api&ws=ws://SERVER_IP:$Port/ws"

if ($Background) {
    if (Test-Path $StdoutLog) {
        Remove-Item $StdoutLog -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $StderrLog) {
        Remove-Item $StderrLog -Force -ErrorAction SilentlyContinue
    }
    $process = Start-Process `
        -FilePath $PythonBin `
        -ArgumentList $uvicornArgs `
        -WorkingDirectory $RepoRoot `
        -RedirectStandardOutput $StdoutLog `
        -RedirectStandardError $StderrLog `
        -WindowStyle Hidden `
        -PassThru
    Set-Content -Path $PidFile -Value $process.Id -Encoding ascii
    Write-Host "Sensor PID: $($process.Id)"
    Write-Host "Logs: $StdoutLog | $StderrLog"
    exit 0
}

Set-Location $RepoRoot
& $PythonBin @uvicornArgs
