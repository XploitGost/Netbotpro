$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$ElectronDir = Join-Path $RepoRoot "desktop\electron"
$WindowsBuildScript = Join-Path $RepoRoot "packaging\windows\build.ps1"

function Write-Check {
    param(
        [string]$Name,
        [string]$Detail
    )
    Write-Host "[OK] $Name - $Detail"
}

function Read-DesktopPackageMetadata {
    Push-Location $ElectronDir
    try {
        $script = @"
const pkg = require('./package.json');
const lock = require('./package-lock.json');
const electron = lock.packages?.['node_modules/electron']?.version || '';
const builder = lock.packages?.['node_modules/electron-builder']?.version || '';
const declared = pkg.devDependencies?.electron || '';
process.stdout.write(JSON.stringify({ electron, builder, declared }));
"@
        $json = node -e $script
        if ($LASTEXITCODE -ne 0 -or -not $json) {
            throw "Unable to read desktop package metadata with Node."
        }
        return $json | ConvertFrom-Json
    } finally {
        Pop-Location
    }
}

$metadata = Read-DesktopPackageMetadata
$lockedElectronVersion = [string]$metadata.electron
$declaredElectronVersion = [string]$metadata.declared
$lockedBuilderVersion = [string]$metadata.builder

if (-not $lockedElectronVersion) {
    throw "Electron version is missing from package-lock.json"
}
if (-not $lockedBuilderVersion) {
    throw "electron-builder version is missing from package-lock.json"
}
if ($declaredElectronVersion -and -not $declaredElectronVersion.Contains($lockedElectronVersion)) {
    $normalizedDeclared = $declaredElectronVersion.TrimStart("^", "~", ">=", "<=", ">", "<", "=")
    if ($normalizedDeclared -ne $lockedElectronVersion) {
        throw "package.json declares Electron $declaredElectronVersion but package-lock has $lockedElectronVersion"
    }
}
Write-Check -Name "Electron lockfile" -Detail $lockedElectronVersion
Write-Check -Name "electron-builder lockfile" -Detail $lockedBuilderVersion

$localElectronPackage = Join-Path $ElectronDir "node_modules\electron\package.json"
if (Test-Path $localElectronPackage) {
    Push-Location $ElectronDir
    try {
        $localElectronVersion = node -e "process.stdout.write(require('./node_modules/electron/package.json').version)"
    } finally {
        Pop-Location
    }
    if ([string]$localElectronVersion -ne $lockedElectronVersion) {
        throw "Local Electron node_modules version $localElectronVersion does not match lockfile $lockedElectronVersion"
    }
    Write-Check -Name "Local Electron install" -Detail $localElectronVersion
} else {
    Write-Host "[INFO] Local Electron node_modules is missing; npm install will restore it from lockfile."
}

$buildScriptText = Get-Content -LiteralPath $WindowsBuildScript -Raw
if ($buildScriptText -match "electron-v36\.3\.1") {
    throw "Windows build script still references the retired Electron 36.3.1 cache."
}
if ($buildScriptText -notmatch "Resolve-ElectronVersion") {
    throw "Windows build script must resolve Electron version dynamically."
}
Write-Check -Name "Windows packaging script" -Detail "Electron version is resolved dynamically"

Write-Host "[OK] release readiness passed"
