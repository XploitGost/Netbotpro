$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\\..")).Path
$VenvDir = Join-Path $RepoRoot ".venv"

Set-Location $RepoRoot

function Resolve-Python312 {
    if ($env:NETBOT_PYTHON_BIN -and (Test-Path $env:NETBOT_PYTHON_BIN)) {
        return $env:NETBOT_PYTHON_BIN
    }

    try {
        $py312 = & py -3.12 -c "import sys; print(sys.executable)"
        if ($LASTEXITCODE -eq 0 -and $py312) {
            return $py312.Trim()
        }
    } catch {
    }

    try {
        $pyDefault = & py -3 -c "import sys; print(sys.executable)"
        if ($LASTEXITCODE -eq 0 -and $pyDefault) {
            return $pyDefault.Trim()
        }
    } catch {
    }

    return "python"
}

$pythonBin = Resolve-Python312

if (-not (Test-Path (Join-Path $VenvDir "Scripts\\python.exe"))) {
    & $pythonBin -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create .venv with $pythonBin"
    }
}

$venvPython = Join-Path $VenvDir "Scripts\\python.exe"
& $venvPython -m pip install --upgrade pip
& $venvPython -m pip install -r requirements.txt

Push-Location (Join-Path $RepoRoot "frontend")
try {
    npm install
    if ($LASTEXITCODE -ne 0) {
        throw "frontend npm install failed"
    }
} finally {
    Pop-Location
}

Push-Location (Join-Path $RepoRoot "desktop\\electron")
try {
    npm install
    if ($LASTEXITCODE -ne 0) {
        throw "desktop electron npm install failed"
    }
} finally {
    Pop-Location
}

Write-Host "Setup complete."
Write-Host "Python: $venvPython"
