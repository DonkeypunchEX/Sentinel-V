#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Sentinel-V Deployment Script (Windows/PowerShell equivalent of deploy.sh).

.PARAMETER Command
    One of: install, start, stop, restart, status, test, help
#>
param(
    [Parameter(Position = 0)]
    [string]$Command = "help",

    [switch]$WindowsEvents
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$PidFile = "logs/sentinel.pid"
$StateDir = if ($env:SENTINEL_V_STATE_DIR) { $env:SENTINEL_V_STATE_DIR } else { Join-Path $env:LOCALAPPDATA "Sentinel-V" }

function Log-Info($msg) { Write-Host "[INFO] $msg" -ForegroundColor Green }
function Log-Warn($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Log-Error($msg) { Write-Host "[ERROR] $msg" -ForegroundColor Red }

function Test-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

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
    # CommandLine for a full-path invocation is quoted (`"...\sentinel-v.exe" start`),
    # so a literal `"` can sit right after `.exe` and before the separating
    # space - the `"?` here tolerates that, otherwise this never matches and
    # an already-running daemon goes undetected.
    Get-CimInstance Win32_Process -Filter "Name = 'sentinel-v.exe' or Name = 'python.exe'" |
        Where-Object { $_.CommandLine -and $_.CommandLine -match 'sentinel-v(\.exe)?"?\s+start' }
}

function Start-System {
    param(
        [switch]$WindowsEvents
    )

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

    New-Item -ItemType Directory -Force -Path logs, $StateDir | Out-Null
    $configPath = if (Test-Path "config/sentinel.yaml") { "config/sentinel.yaml" } else { "config/sentinel.default.yaml" }
    $stderrLog = Join-Path $StateDir "sentinel.err.log"

    $startArgs = @("start", "--config", $configPath)
    if ($WindowsEvents) {
        if (-not (Test-IsElevated)) {
            Log-Warn "-WindowsEvents requires an elevated (Administrator) shell to read the Sysmon/Security logs - collection will fail every poll without it."
        }
        $startArgs += "--windows-events"
    }

    $proc = Start-Process -FilePath "sentinel-v" -ArgumentList $startArgs `
        -RedirectStandardOutput (Join-Path $StateDir "sentinel.out.log") -RedirectStandardError $stderrLog `
        -PassThru -WindowStyle Hidden

    $proc.Id | Out-File -FilePath $PidFile -Encoding ascii
    Log-Info "Sentinel-V started with PID: $($proc.Id)"
    Log-Info "Logs: $StateDir"

    Start-Sleep -Seconds 3
    if (Get-Process -Id $proc.Id -ErrorAction SilentlyContinue) {
        Log-Info "Sentinel-V is running"
        sentinel-v status
    } else {
        Log-Error "Failed to start Sentinel-V"
        if (Test-Path $stderrLog) { Get-Content $stderrLog -Tail 20 }
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

Usage: deploy.ps1 [command] [-WindowsEvents]

Commands:
  install     Install and configure Sentinel-V
  start       Start the Sentinel-V system
  stop        Stop the Sentinel-V system
  restart     Restart the Sentinel-V system
  status      Show system status
  test        Run tests
  help        Show this help message

Options:
  -WindowsEvents   With start/restart, feed local Sysmon (process/network/
                   DNS) and Security (failed logon) events into the running
                   system. Requires an elevated (Administrator) shell.

Examples:
  .\deploy.ps1 install                  # Install and configure
  .\deploy.ps1 start                    # Start the system
  .\deploy.ps1 start -WindowsEvents     # Start with live event collection
  .\deploy.ps1 status                   # Check status
"@
}

switch ($Command) {
    "install" {
        Check-Prerequisites
        Install-Dependencies
        Configure-System
        Run-Tests
    }
    "start" { Start-System -WindowsEvents:$WindowsEvents }
    "stop" { Stop-System }
    "restart" {
        Stop-System
        Start-Sleep -Seconds 2
        Start-System -WindowsEvents:$WindowsEvents
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
