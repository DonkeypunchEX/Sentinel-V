#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Sentinel-V Deployment Script (Windows/PowerShell equivalent of deploy.sh).

.PARAMETER Command
    One of: install, start, stop, restart, status, test, help
#>
param(
    [Parameter(Position = 0)]
    [string]$Command = "help"
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$PidFile = "logs/sentinel.pid"

function Log-Info($msg) { Write-Host "[INFO] $msg" -ForegroundColor Green }
function Log-Warn($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Log-Error($msg) { Write-Host "[ERROR] $msg" -ForegroundColor Red }

function Check-Prerequisites {
    Log-Info "Checking prerequisites..."

    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) {
        Log-Error "Python not found. Please install Python 3.10 or higher."
        exit 1
    }

    $versionOk = python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)"
    if ($LASTEXITCODE -ne 0) {
        $found = (python --version)
        Log-Error "Python 3.10 or higher required. Found: $found"
        exit 1
    }

    Log-Info "Python version: $(python --version)"

    if (-not $env:VIRTUAL_ENV) {
        Log-Warn "Not running in a virtual environment. Consider using one."
    }
}

function Install-Dependencies {
    Log-Info "Installing dependencies..."
    python -m pip install --upgrade pip
    python -m pip install -e ".[dev,cli]"
    Log-Info "Dependencies installed successfully"
}

function Configure-System {
    Log-Info "Configuring Sentinel-V system..."

    New-Item -ItemType Directory -Force -Path config, logs, data | Out-Null

    if (-not (Test-Path "config/sentinel.yaml")) {
        if (Test-Path "config/sentinel.default.yaml") {
            Copy-Item "config/sentinel.default.yaml" "config/sentinel.yaml"
            Log-Info "Created config/sentinel.yaml from default"
        } else {
            Log-Warn "No configuration file found. Using defaults."
        }
    }

    Log-Info "Configuration complete"
}

function Run-Tests {
    Log-Info "Running tests..."

    if (Get-Command pytest -ErrorAction SilentlyContinue) {
        pytest tests/ -v --tb=short
        if ($LASTEXITCODE -eq 0) {
            Log-Info "Tests passed"
        } else {
            Log-Error "Tests failed"
            exit 1
        }
    } else {
        Log-Warn "pytest not found. Skipping tests."
    }
}

function Get-SentinelProcess {
    Get-CimInstance Win32_Process -Filter "Name = 'sentinel-v.exe' or Name = 'python.exe'" |
        Where-Object { $_.CommandLine -and $_.CommandLine -match "sentinel-v(\.exe)?\s+start" }
}

function Start-System {
    Log-Info "Starting Sentinel-V system..."

    $existing = Get-SentinelProcess
    if ($existing) {
        Log-Warn "Sentinel-V appears to be already running (PID: $($existing.ProcessId -join ', '))"
        $reply = Read-Host "Do you want to stop it and restart? (y/n)"
        if ($reply -match '^[Yy]') {
            Stop-System
        } else {
            Log-Info "Exiting without changes"
            exit 0
        }
    }

    New-Item -ItemType Directory -Force -Path logs | Out-Null
    $configPath = if (Test-Path "config/sentinel.yaml") { "config/sentinel.yaml" } else { "config/sentinel.default.yaml" }

    $proc = Start-Process -FilePath "sentinel-v" -ArgumentList "start", "--config", $configPath `
        -RedirectStandardOutput "logs/sentinel.log" -RedirectStandardError "logs/sentinel.err.log" `
        -PassThru -WindowStyle Hidden

    $proc.Id | Out-File -FilePath $PidFile -Encoding ascii
    Log-Info "Sentinel-V started with PID: $($proc.Id)"
    Log-Info "Logs: logs/sentinel.log"

    Start-Sleep -Seconds 3
    if (Get-Process -Id $proc.Id -ErrorAction SilentlyContinue) {
        Log-Info "Sentinel-V is running"
        sentinel-v status
    } else {
        Log-Error "Failed to start Sentinel-V"
        if (Test-Path "logs/sentinel.err.log") { Get-Content "logs/sentinel.err.log" -Tail 20 }
        exit 1
    }
}

function Stop-System {
    Log-Info "Stopping Sentinel-V system..."

    $procs = Get-SentinelProcess
    if (-not $procs) {
        Log-Warn "No Sentinel-V processes found"
    } else {
        foreach ($p in $procs) {
            Log-Info "Stopping process $($p.ProcessId)"
            Stop-Process -Id $p.ProcessId -ErrorAction SilentlyContinue
        }

        Start-Sleep -Seconds 2

        $stillRunning = Get-SentinelProcess
        foreach ($p in $stillRunning) {
            Log-Warn "Force killing process $($p.ProcessId)"
            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
        }

        Log-Info "Sentinel-V stopped"
    }

    Remove-Item $PidFile -ErrorAction SilentlyContinue
}

function Show-Help {
    @"
Sentinel-V Deployment Script

Usage: deploy.ps1 [command]

Commands:
  install     Install and configure Sentinel-V
  start       Start the Sentinel-V system
  stop        Stop the Sentinel-V system
  restart     Restart the Sentinel-V system
  status      Show system status
  test        Run tests
  help        Show this help message

Examples:
  .\deploy.ps1 install   # Install and configure
  .\deploy.ps1 start     # Start the system
  .\deploy.ps1 status    # Check status
"@
}

switch ($Command) {
    "install" {
        Check-Prerequisites
        Install-Dependencies
        Configure-System
        Run-Tests
    }
    "start" { Start-System }
    "stop" { Stop-System }
    "restart" {
        Stop-System
        Start-Sleep -Seconds 2
        Start-System
    }
    "status" {
        if (Get-Command sentinel-v -ErrorAction SilentlyContinue) {
            sentinel-v status
        } else {
            Log-Error "sentinel-v command not found"
        }
    }
    "test" { Run-Tests }
    { $_ -in "help", "--help", "-h" } { Show-Help }
    default {
        Log-Error "Unknown command: $Command"
        Show-Help
        exit 1
    }
}
