param(
    [string]$CentralApi = $env:NETBOT_CENTRAL_API,
    [string]$AgentToken = $env:NETBOT_AGENT_TOKEN,
    [string]$AgentId = $env:NETBOT_AGENT_ID,
    [int]$HeartbeatInterval = 30,
    [int]$TelemetryInterval = 60,
    [switch]$Foreground
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$RuntimeDir = Join-Path $RepoRoot ".runtime"
$LogDir = Join-Path $RuntimeDir "logs"
$PidFile = Join-Path $RuntimeDir "agent-runner.pid"
$StdoutLog = Join-Path $LogDir "agent-runner.log"
$StderrLog = Join-Path $LogDir "agent-runner.err.log"
$PythonExe = Join-Path $RepoRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $PythonExe)) {
    $PythonExe = "python"
}

if ([string]::IsNullOrWhiteSpace($CentralApi)) {
    throw "Central API is required. Pass -CentralApi or set NETBOT_CENTRAL_API."
}

if ([string]::IsNullOrWhiteSpace($AgentToken)) {
    throw "Agent token is required. Pass -AgentToken or set NETBOT_AGENT_TOKEN."
}

New-Item -ItemType Directory -Force -Path $RuntimeDir, $LogDir | Out-Null

if (Test-Path $PidFile) {
    $ExistingPid = (Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($ExistingPid -match "^\d+$") {
        $ExistingProcess = Get-Process -Id ([int]$ExistingPid) -ErrorAction SilentlyContinue
        if ($ExistingProcess) {
            Write-Host "Agent already running with PID $ExistingPid"
            Write-Host "Log: $StdoutLog"
            Write-Host "Error log: $StderrLog"
            exit 0
        }
    }
    Remove-Item -Force $PidFile
}

$env:NETBOT_AGENT_MODE = "1"
$env:NETBOT_CENTRAL_API = $CentralApi
$env:NETBOT_AGENT_TOKEN = $AgentToken
$env:NETBOT_AGENT_HEARTBEAT_INTERVAL = [string]$HeartbeatInterval
$env:NETBOT_AGENT_TELEMETRY_INTERVAL = [string]$TelemetryInterval
if (-not [string]::IsNullOrWhiteSpace($AgentId)) {
    $env:NETBOT_AGENT_ID = $AgentId
}

Write-Host "Starting NetBotPro Agent Mode"
Write-Host "Central API: $CentralApi"
Write-Host "PID file: $PidFile"
Write-Host "Log: $StdoutLog"
Write-Host "Error log: $StderrLog"
Write-Host "Agent token is configured and hidden."

if ($Foreground) {
    & $PythonExe -m agent.agent_runner
    exit $LASTEXITCODE
}

$Process = Start-Process `
    -FilePath $PythonExe `
    -ArgumentList @("-m", "agent.agent_runner") `
    -WorkingDirectory $RepoRoot `
    -RedirectStandardOutput $StdoutLog `
    -RedirectStandardError $StderrLog `
    -WindowStyle Hidden `
    -PassThru

Set-Content -Path $PidFile -Value $Process.Id -Encoding ascii
Write-Host "Agent started with PID $($Process.Id)"
