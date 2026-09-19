#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Build a standalone sentinel-v.exe with PyInstaller.

    The result runs on a Windows machine with no Python install at
    all -- useful for handing the CLI to someone without a dev
    environment. Requires only Python + pip on the *build* machine.

.PARAMETER Clean
    Remove previous build/dist output and the generated .spec file
    before building.
#>
param(
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

if ($Clean) {
    Remove-Item -Recurse -Force build, dist, sentinel-v.spec -ErrorAction SilentlyContinue
}

Write-Host "[INFO] Installing sentinel-v with CLI + build extras..." -ForegroundColor Green
python -m pip install -e ".[cli,build]"

# PyInstaller's static analysis can't see through this project's PEP 660
# editable install (a dynamic __editable__*_finder.py import hook, not a
# real sentinel_v/ directory in site-packages) - it silently omits the
# package, producing an exe that fails at startup with
# "ModuleNotFoundError: No module named 'sentinel_v'". Installing a real
# (non-editable) copy just for the build sidesteps that; the editable
# install is restored afterward so normal dev use keeps reflecting
# on-disk source without a reinstall.
Write-Host "[INFO] Installing a non-editable copy for PyInstaller to bundle..." -ForegroundColor Green
python -m pip install --no-deps --force-reinstall .

try {
    Write-Host "[INFO] Running PyInstaller..." -ForegroundColor Green
    pyinstaller --onefile --name sentinel-v --clean scripts/pyinstaller_entry.py
} finally {
    Write-Host "[INFO] Restoring editable install..." -ForegroundColor Green
    python -m pip install --no-deps -e .
}

if (Test-Path "dist/sentinel-v.exe") {
    Write-Host "[INFO] Built dist/sentinel-v.exe" -ForegroundColor Green
    Write-Host "       Run it standalone, e.g.: dist\sentinel-v.exe status"
} else {
    Write-Host "[ERROR] Build did not produce dist/sentinel-v.exe" -ForegroundColor Red
    exit 1
}
