$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $RepoRoot

function Resolve-BuildPython {
    $venvPython = Join-Path $RepoRoot ".venv-pack312\Scripts\python.exe"
    if (Test-Path $venvPython) {
        return $venvPython
    }

    try {
        $py312 = & py -3.12 -c "import sys; print(sys.executable)"
        if ($LASTEXITCODE -eq 0 -and $py312) {
            return $py312.Trim()
        }
    } catch {
    }

    return "python"
}

function Resolve-BuildNodeHome {
    if ($env:NETBOT_NODE_HOME -and (Test-Path (Join-Path $env:NETBOT_NODE_HOME "node.exe"))) {
        return $env:NETBOT_NODE_HOME
    }

    $portableNode = Join-Path $RepoRoot ".tools\node-v22.22.2-win-x64"
    if (Test-Path (Join-Path $portableNode "node.exe")) {
        return $portableNode
    }

    return $null
}

$PythonCmd = Resolve-BuildPython
$NodeHome = Resolve-BuildNodeHome

& $PythonCmd -m PyInstaller packaging\pyinstaller\netbotpro_backend.spec --clean --noconfirm
& $PythonCmd scripts\release\stage_backend_runtime.py

Push-Location (Join-Path $RepoRoot "desktop\electron")
try {
    if ($NodeHome) {
        $env:PATH = "$NodeHome;$env:PATH"
    }

    npm install --prefer-offline --no-audit --no-fund
    npm run dist -- --win
} finally {
    Pop-Location
}
