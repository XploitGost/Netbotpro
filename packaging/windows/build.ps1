$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $RepoRoot

function Resolve-BuildPython {
    try {
        $py312 = & py -3.12 -c "import sys; print(sys.executable)"
        if ($LASTEXITCODE -eq 0 -and $py312) {
            return $py312.Trim()
        }
    } catch {
    }

    $venvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
    if (Test-Path $venvPython) {
        return $venvPython
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

function Resolve-ArchiveTool {
    $candidates = @()

    try {
        $sevenZa = Get-Command 7za.exe -ErrorAction Stop
        if ($sevenZa.Source) {
            return $sevenZa.Source
        }
    } catch {
    }

    try {
        $sevenZ = Get-Command 7z.exe -ErrorAction Stop
        if ($sevenZ.Source) {
            return $sevenZ.Source
        }
    } catch {
    }

    $candidates += "C:\Program Files\7-Zip\7za.exe"
    $candidates += "C:\Program Files\7-Zip\7z.exe"
    $candidates += "C:\Program Files\Autodesk\AdODIS\V1\Setup\7za.exe"
    $candidates += "C:\Program Files\Autodesk\AdODIS\V1\Setup\7z.exe"

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    return $null
}

function Test-DesktopDependenciesReady {
    param(
        [string]$ElectronDir
    )

    $requiredPaths = @(
        (Join-Path $ElectronDir "node_modules\electron\package.json"),
        (Join-Path $ElectronDir "node_modules\electron-builder\package.json")
    )

    foreach ($requiredPath in $requiredPaths) {
        if (-not (Test-Path $requiredPath)) {
            return $false
        }
    }

    return $true
}

function Ensure-ArchiveToolInPath {
    param(
        [string]$ToolPath
    )

    if (-not $ToolPath) {
        return
    }

    $toolDir = Split-Path -Parent $ToolPath
    $toolName = Split-Path -Leaf $ToolPath
    $shimDir = Join-Path $RepoRoot ".tools\7zip-shims"

    if ($env:PATH -notlike "*$toolDir*") {
        $env:PATH = "$toolDir;$env:PATH"
    }

    if ($toolName -ieq "7za.exe") {
        return
    }

    New-Item -ItemType Directory -Force -Path $shimDir | Out-Null
    $shimPath = Join-Path $shimDir "7za.cmd"
    $shimContent = "@echo off`r`n""$ToolPath"" %*`r`n"
    Set-Content -LiteralPath $shimPath -Value $shimContent -Encoding ASCII

    if ($env:PATH -notlike "*$shimDir*") {
        $env:PATH = "$shimDir;$env:PATH"
    }
}

function Initialize-NsisTools {
    param(
        [string]$ArchiveToolPath
    )

    if ($env:ELECTRON_BUILDER_NSIS_DIR -and (Test-Path (Join-Path $env:ELECTRON_BUILDER_NSIS_DIR "makensis.exe"))) {
        return
    }

    $nsisRoot = Join-Path $RepoRoot ".tools\electron-builder-binaries\nsis-3.0.4.1"
    $nsisArchive = Join-Path $nsisRoot "nsis-3.0.4.1.7z"
    $nsisUnpacked = Join-Path $nsisRoot "unpacked"

    if (Test-Path (Join-Path $nsisUnpacked "makensis.exe")) {
        $env:ELECTRON_BUILDER_NSIS_DIR = $nsisUnpacked
        return
    }

    if (-not (Test-Path $nsisArchive)) {
        return
    }

    if (-not $ArchiveToolPath) {
        throw "A 7-Zip command-line tool (7za.exe or 7z.exe) is required to unpack $nsisArchive for electron-builder."
    }

    if ((Test-Path $nsisArchive) -and $ArchiveToolPath) {
        if (Test-Path $nsisUnpacked) {
            Remove-Item -LiteralPath $nsisUnpacked -Recurse -Force
        }
        New-Item -ItemType Directory -Force -Path $nsisUnpacked | Out-Null
        & $ArchiveToolPath x "-y" "-o$nsisUnpacked" $nsisArchive | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path (Join-Path $nsisUnpacked "makensis.exe"))) {
            throw "Failed to unpack NSIS helper from $nsisArchive"
        }
        $env:ELECTRON_BUILDER_NSIS_DIR = $nsisUnpacked
    }
}

$PythonCmd = Resolve-BuildPython
$NodeHome = Resolve-BuildNodeHome
$ElectronDist = Join-Path $RepoRoot ".tools\\electron-v36.3.1-win32-x64"
$ArchiveTool = Resolve-ArchiveTool

Ensure-ArchiveToolInPath -ToolPath $ArchiveTool
Initialize-NsisTools -ArchiveToolPath $ArchiveTool

& $PythonCmd -m PyInstaller packaging\pyinstaller\netbotpro_backend.spec --clean --noconfirm
& $PythonCmd scripts\release\stage_backend_runtime.py

Push-Location (Join-Path $RepoRoot "desktop\electron")
try {
    $ElectronBuilderCmd = Join-Path (Get-Location).Path "node_modules\.bin\electron-builder.cmd"

    if ($NodeHome) {
        $env:PATH = "$NodeHome;$env:PATH"
    }
    if (Test-Path $ElectronDist) {
        $env:ELECTRON_SKIP_BINARY_DOWNLOAD = "1"
    }
    $env:npm_config_audit = "false"
    $env:npm_config_fund = "false"

    if (-not (Test-DesktopDependenciesReady -ElectronDir (Get-Location).Path)) {
        npm install --prefer-offline --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) {
            throw "npm install failed while preparing desktop dependencies."
        }
    } else {
        Write-Host "Reusing existing desktop node_modules; skipping npm install."
    }

    if (Test-Path $ElectronDist) {
        $ElectronPackageDist = Join-Path (Join-Path $RepoRoot "desktop\\electron\\node_modules\\electron") "dist"
        if (Test-Path $ElectronPackageDist) {
            Remove-Item -LiteralPath $ElectronPackageDist -Recurse -Force
        }
        Copy-Item -LiteralPath $ElectronDist -Destination $ElectronPackageDist -Recurse -Force
    }
    npm run build:frontend
    if ($LASTEXITCODE -ne 0) {
        throw "Frontend build failed."
    }

    if (-not (Test-Path $ElectronBuilderCmd)) {
        throw "electron-builder executable not found at $ElectronBuilderCmd"
    }

    $electronBuilderArgs = @("--win")
    if (Test-Path $ElectronDist) {
        $electronBuilderArgs += "--config.electronDist=$ElectronDist"
    }

    & $ElectronBuilderCmd @electronBuilderArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Electron packaging failed."
    }
} finally {
    Pop-Location
}
