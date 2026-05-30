$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\\..")).Path
$BackendPort = if ($env:NETBOT_PORT) { [int]$env:NETBOT_PORT } else { 8765 }
$FrontendPort = 5173

function Resolve-PythonBin {
    $candidates = @(
        (Join-Path $RepoRoot ".venv\Scripts\python.exe")
    )
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return (Resolve-Path $candidate).Path
        }
    }
    throw "No local project Python runtime was found. Run scripts\\dev\\setup.ps1 first."
}

function Get-ListeningPids {
    param([int]$Port)
    $connections = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    if (-not $connections) {
        return @()
    }
    return @($connections | Select-Object -ExpandProperty OwningProcess -Unique)
}

function Test-HttpReady {
    param(
        [string]$Uri,
        [int]$TimeoutSec = 10
    )
    try {
        $null = Invoke-WebRequest -UseBasicParsing -Uri $Uri -TimeoutSec $TimeoutSec
        return $true
    } catch {
        return $false
    }
}

function Start-LoggedProcess {
    param(
        [string]$Name,
        [string]$FilePath,
        [string[]]$ArgumentList,
        [string]$WorkingDirectory,
        [hashtable]$Environment,
        [string]$StdoutPath,
        [string]$StderrPath
    )

    if (Test-Path $StdoutPath) {
        Remove-Item $StdoutPath -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $StderrPath) {
        Remove-Item $StderrPath -Force -ErrorAction SilentlyContinue
    }

    foreach ($key in $Environment.Keys) {
        [System.Environment]::SetEnvironmentVariable($key, [string]$Environment[$key], "Process")
    }

    $startInfo = @{
        FilePath = $FilePath
        ArgumentList = $ArgumentList
        WorkingDirectory = $WorkingDirectory
        RedirectStandardOutput = $StdoutPath
        RedirectStandardError = $StderrPath
        WindowStyle = "Hidden"
        PassThru = $true
    }

    $process = Start-Process @startInfo
    if (-not $process) {
        throw "Failed to start $Name"
    }
    return $process
}

$runtimeDir = Join-Path $RepoRoot ".runtime"
New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null

$backendLog = Join-Path $runtimeDir "backend-dev.log"
$backendErrLog = Join-Path $runtimeDir "backend-dev.err.log"
$frontendLog = Join-Path $runtimeDir "frontend-dev.log"
$frontendErrLog = Join-Path $runtimeDir "frontend-dev.err.log"
$backendPidFile = Join-Path $runtimeDir "backend-dev.pid"
$frontendPidFile = Join-Path $runtimeDir "frontend-dev.pid"

$backendReady = Test-HttpReady -Uri "http://127.0.0.1:$BackendPort/api/status"
$backendPid = $null
if (-not $backendReady) {
    $backendPortOwners = Get-ListeningPids -Port $BackendPort
    if ($backendPortOwners.Count -gt 0) {
        throw "Backend port $BackendPort is busy but unhealthy. PID(s): $($backendPortOwners -join ', ')"
    }

    $pythonBin = Resolve-PythonBin
    Write-Host "Using Python runtime: $pythonBin"
    $backendEnv = @{
        NETBOT_HOST = "127.0.0.1"
        NETBOT_PORT = "$BackendPort"
        NETBOT_ALLOWED_ORIGINS = "http://127.0.0.1:5173,http://localhost:5173"
    }

    $backendProcess = Start-LoggedProcess `
        -Name "backend" `
        -FilePath $pythonBin `
        -ArgumentList @("-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", "$BackendPort") `
        -WorkingDirectory $RepoRoot `
        -Environment $backendEnv `
        -StdoutPath $backendLog `
        -StderrPath $backendErrLog

    Start-Sleep -Seconds 3
    if (-not (Test-HttpReady -Uri "http://127.0.0.1:$BackendPort/api/status")) {
        try { Stop-Process -Id $backendProcess.Id -Force -ErrorAction SilentlyContinue } catch {}
        throw "Backend failed health check. See $backendLog and $backendErrLog"
    }

    $backendPid = $backendProcess.Id
    Set-Content -Path $backendPidFile -Value $backendPid -Encoding ascii
} else {
    Remove-Item $backendPidFile -Force -ErrorAction SilentlyContinue
}

$frontendReady = Test-HttpReady -Uri "http://127.0.0.1:$FrontendPort"
$frontendPid = $null
if (-not $frontendReady) {
    $frontendPortOwners = Get-ListeningPids -Port $FrontendPort
    if ($frontendPortOwners.Count -gt 0) {
        throw "Frontend port $FrontendPort is busy but unhealthy. PID(s): $($frontendPortOwners -join ', ')"
    }

    $frontendProcess = Start-LoggedProcess `
        -Name "frontend" `
        -FilePath "npm.cmd" `
        -ArgumentList @("run", "dev", "--", "--host", "127.0.0.1") `
        -WorkingDirectory (Join-Path $RepoRoot "frontend") `
        -Environment @{} `
        -StdoutPath $frontendLog `
        -StderrPath $frontendErrLog

    Start-Sleep -Seconds 4
    if (-not (Test-HttpReady -Uri "http://127.0.0.1:$FrontendPort")) {
        try { Stop-Process -Id $frontendProcess.Id -Force -ErrorAction SilentlyContinue } catch {}
        if ($backendPid) {
            try { Stop-Process -Id $backendPid -Force -ErrorAction SilentlyContinue } catch {}
            Remove-Item $backendPidFile -Force -ErrorAction SilentlyContinue
        }
        throw "Frontend failed health check. See $frontendLog and $frontendErrLog"
    }

    $frontendPid = $frontendProcess.Id
    Set-Content -Path $frontendPidFile -Value $frontendPid -Encoding ascii
} else {
    Remove-Item $frontendPidFile -Force -ErrorAction SilentlyContinue
}

Write-Host "Backend URL: http://127.0.0.1:$BackendPort"
if ($backendPid) {
    Write-Host "Started backend PID: $backendPid"
} else {
    Write-Host "Reused existing backend on port $BackendPort"
}

Write-Host "Frontend URL: http://127.0.0.1:$FrontendPort"
if ($frontendPid) {
    Write-Host "Started frontend PID: $frontendPid"
} else {
    Write-Host "Reused existing frontend on port $FrontendPort"
}

Write-Host "Backend logs: $backendLog | $backendErrLog"
Write-Host "Frontend logs: $frontendLog | $frontendErrLog"
