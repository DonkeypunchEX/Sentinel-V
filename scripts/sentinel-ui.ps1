#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Sentinel-V interactive console UI for PowerShell.

.DESCRIPTION
    A menu-driven front end over the existing `sentinel-v` CLI and
    `deploy.ps1` lifecycle commands. This script adds no new behavior to
    the Python package - it only wraps commands that already exist, so
    everything it shows is exactly what `sentinel-v --help` can do.

.NOTES
    `sentinel-v start` publishes a heartbeat file that `sentinel-v status`
    (run from any other process) reads, so "Status" below reflects the
    real running daemon's live counters, not a throwaway instance.
#>

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$DeployScript = Join-Path $PSScriptRoot "deploy.ps1"
$StateDir = if ($env:SENTINEL_V_STATE_DIR) { $env:SENTINEL_V_STATE_DIR } else { Join-Path $env:LOCALAPPDATA "Sentinel-V" }
$LogPath = Join-Path $StateDir "sentinel.log"

function Write-Info($msg) { Write-Host "[INFO] $msg" -ForegroundColor Green }
function Write-Warn2($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err($msg) { Write-Host "[ERROR] $msg" -ForegroundColor Red }

function Test-SentinelInstalled {
    return [bool](Get-Command sentinel-v -ErrorAction SilentlyContinue)
}

function Test-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SentinelProcess {
    # See the matching comment in deploy.ps1: a full-path invocation's
    # CommandLine is quoted, so `"?` is needed between `.exe` and the space
    # before `start` or an already-running daemon goes undetected.
    Get-CimInstance Win32_Process -Filter "Name = 'sentinel-v.exe' or Name = 'python.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine -match 'sentinel-v(\.exe)?"?\s+start' }
}

function Get-RunningBadge {
    $proc = Get-SentinelProcess
    if ($proc) {
        return "RUNNING (PID $($proc.ProcessId -join ', '))"
    }
    return "STOPPED"
}

function Pause-ForUser {
    Write-Host ""
    Read-Host "Press Enter to return to the menu" | Out-Null
}

function Show-Banner {
    Clear-Host
    $badge = Get-RunningBadge
    $badgeColor = if ($badge -like "RUNNING*") { "Green" } else { "Red" }
    Write-Host "+---------------------------------------------------------------+" -ForegroundColor DarkRed
    Write-Host "|  SSSSS  EEEEE  N   N TTTTT III N   N EEEEE L     - V          |" -ForegroundColor Red
    Write-Host "|  S      E      NN  N   T    I  NN  N E     L     - V          |" -ForegroundColor Red
    Write-Host "|  SSSSS  EEEE   N N N   T    I  N N N EEEE  L     - V          |" -ForegroundColor Red
    Write-Host "|      S  E      N  NN   T    I  N  NN E     L     - V          |" -ForegroundColor Red
    Write-Host "|  SSSSS  EEEEE  N   N   T    I  N   N EEEEE LLLLL - V          |" -ForegroundColor Red
    Write-Host "|       AUTONOMOUS CYBER-DEFENSE COMMAND CENTER                 |" -ForegroundColor Yellow
    Write-Host "+---------------------------------------------------------------+" -ForegroundColor DarkRed
    Write-Host "|  Background process: " -NoNewline -ForegroundColor DarkRed
    Write-Host $badge -ForegroundColor $badgeColor
    Write-Host "+---------------------------------------------------------------+" -ForegroundColor DarkRed
    if (-not (Test-SentinelInstalled)) {
        Write-Host "  sentinel-v CLI not found on PATH - run [8] Install first." -ForegroundColor Red
    }
    Write-Host ""
}

function Show-Menu {
    Show-Banner
    Write-Host " 1) Status"
    Write-Host " 2) Start system (background, optionally with live Windows events)"
    Write-Host " 3) Stop system"
    Write-Host " 4) Restart system (optionally with live Windows events)"
    Write-Host " 5) Analyze events file"
    Write-Host " 6) Deploy decoys"
    Write-Host " 7) Validate a config file"
    Write-Host " 8) Install / check prerequisites"
    Write-Host " 9) Export SBOM"
    Write-Host "10) Run tests"
    Write-Host "11) Tail logs (live)"
    Write-Host " 0) Exit"
    Write-Host ""
}

function Invoke-Status {
    if (-not (Test-SentinelInstalled)) { Write-Err "sentinel-v is not installed."; return }
    sentinel-v status
}

function Invoke-Start {
    $reply = Read-Host "Feed live Sysmon/Security events into the system? Requires Administrator (y/N)"
    if ($reply -match "^[Yy]") {
        if (-not (Test-IsElevated)) {
            Write-Warn2 "This shell is not running as Administrator - event collection will fail every poll without it."
        }
        & $DeployScript start -WindowsEvents
    } else {
        & $DeployScript start
    }
}

function Invoke-Stop {
    & $DeployScript stop
}

function Invoke-Restart {
    $reply = Read-Host "Feed live Sysmon/Security events into the system? Requires Administrator (y/N)"
    if ($reply -match "^[Yy]") {
        if (-not (Test-IsElevated)) {
            Write-Warn2 "This shell is not running as Administrator - event collection will fail every poll without it."
        }
        & $DeployScript restart -WindowsEvents
    } else {
        & $DeployScript restart
    }
}

function Invoke-Install {
    & $DeployScript install
}

function Invoke-Test {
    & $DeployScript test
}

function Invoke-Analyze {
    if (-not (Test-SentinelInstalled)) { Write-Err "sentinel-v is not installed."; return }

    $eventFile = Read-Host "Path to events JSON file"
    if (-not (Test-Path $eventFile)) {
        Write-Err "File not found: $eventFile"
        return
    }

    $tempOut = Join-Path ([System.IO.Path]::GetTempPath()) "sentinel-v-analyze-$([guid]::NewGuid()).json"
    try {
        sentinel-v analyze $eventFile --output $tempOut
        if ($LASTEXITCODE -ne 0) { return }

        $results = Get-Content $tempOut -Raw | ConvertFrom-Json
        Write-Host ""
        Write-Host "Results ($($results.Count) events):" -ForegroundColor Cyan
        $results |
            Select-Object `
                @{N = "source_ip"; E = { $_.event.source_ip } }, `
                @{N = "dest_ip"; E = { $_.event.dest_ip } }, `
                threat_level, `
                @{N = "anomaly_score"; E = { [math]::Round([double]$_.anomaly_score, 3) } }, `
                is_decoy_interaction |
            Format-Table -AutoSize

        $summary = $results | Group-Object threat_level | Sort-Object Name
        Write-Host "By threat level:" -ForegroundColor Cyan
        $summary | ForEach-Object {
            $levelColor = switch ($_.Name.ToUpperInvariant()) {
                "BENIGN" { "Green" }
                "SUSPICIOUS" { "Yellow" }
                "MALICIOUS" { "DarkYellow" }
                "CRITICAL" { "Magenta" }
                default { "Gray" }
            }
            Write-Host ("  {0}: {1}" -f $_.Name, $_.Count) -ForegroundColor $levelColor
        }
    }
    finally {
        Remove-Item $tempOut -ErrorAction SilentlyContinue
    }
}

function Invoke-DeployDecoys {
    if (-not (Test-SentinelInstalled)) { Write-Err "sentinel-v is not installed."; return }

    $network = Read-Host "Network range (default 10.0.0.0/24)"
    if ([string]::IsNullOrWhiteSpace($network)) { $network = "10.0.0.0/24" }

    $countInput = Read-Host "Decoy count (default 5)"
    $count = 5
    if (-not [string]::IsNullOrWhiteSpace($countInput)) {
        if (-not [int]::TryParse($countInput, [ref]$count)) {
            Write-Err "Invalid count: $countInput"
            return
        }
    }

    sentinel-v deploy-decoys --network $network --count $count
}

function Invoke-ValidateConfig {
    if (-not (Test-SentinelInstalled)) { Write-Err "sentinel-v is not installed."; return }

    $configFile = Read-Host "Path to config file"
    if (-not (Test-Path $configFile)) {
        Write-Err "File not found: $configFile"
        return
    }
    sentinel-v validate-config $configFile
}

function Invoke-ExportSbom {
    if (-not (Test-SentinelInstalled)) { Write-Err "sentinel-v is not installed."; return }
    sentinel-v export-sbom
}

function Show-LiveLog {
    if (-not (Test-Path $LogPath)) {
        Write-Warn2 "No log file at $LogPath yet - start the system first (option 2)."
        return
    }

    Write-Host "Tailing $LogPath - press Q to return to the menu." -ForegroundColor Cyan
    Write-Host ""

    while ($true) {
        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            if ($key.Key -eq [ConsoleKey]::Q) { break }
        }

        $lines = Get-Content -Path $LogPath -Tail 25 -ErrorAction SilentlyContinue
        Clear-Host
        Write-Host "Tailing $LogPath - press Q to return to the menu." -ForegroundColor Cyan
        Write-Host ("-" * 60)
        if ($lines) { $lines | ForEach-Object { Write-Host $_ } }
        Start-Sleep -Milliseconds 500
    }
}

while ($true) {
    Show-Menu
    $choice = Read-Host "Select an option"

    switch ($choice) {
        "1" { Invoke-Status; Pause-ForUser }
        "2" { Invoke-Start; Pause-ForUser }
        "3" { Invoke-Stop; Pause-ForUser }
        "4" { Invoke-Restart; Pause-ForUser }
        "5" { Invoke-Analyze; Pause-ForUser }
        "6" { Invoke-DeployDecoys; Pause-ForUser }
        "7" { Invoke-ValidateConfig; Pause-ForUser }
        "8" { Invoke-Install; Pause-ForUser }
        "9" { Invoke-ExportSbom; Pause-ForUser }
        "10" { Invoke-Test; Pause-ForUser }
        "11" { Show-LiveLog }
        "0" { break }
        default { Write-Warn2 "Unknown option: $choice"; Pause-ForUser }
    }

    if ($choice -eq "0") { break }
}

Write-Host "Goodbye." -ForegroundColor Cyan
