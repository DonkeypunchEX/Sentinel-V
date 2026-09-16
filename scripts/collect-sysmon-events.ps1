<#
.SYNOPSIS
  Emits Sysmon (process create / network connect / DNS query) and Security
  (failed logon) events newer than -Since as JSON Lines on stdout.

.DESCRIPTION
  Called by sentinel_v.windows_events.WindowsEventCollector on a poll
  interval; not meant to be run interactively, though it works fine invoked
  by hand for debugging. Both the Security log and Sysmon's Operational
  channel are access-controlled - reading either requires the caller to be
  an administrator or a member of "Event Log Readers", and Sysmon must
  also be installed. A caller lacking permission on one log, or missing
  Sysmon entirely, gets "no events" for that source instead of a raised
  error, so collection degrades gracefully rather than one unavailable
  source blocking the other.
#>
param(
    [string]$Since
)

$ErrorActionPreference = 'Stop'

$sinceTime = if ($Since) {
    [datetime]::Parse($Since).ToUniversalTime()
} else {
    (Get-Date).ToUniversalTime().AddMinutes(-5)
}

function ConvertTo-EventDataHash {
    param($Record)

    $xml = [xml]$Record.ToXml()
    $hash = @{}
    foreach ($item in $xml.Event.EventData.Data) {
        if ($item.Name) {
            $hash[$item.Name] = $item.'#text'
        }
    }
    return $hash
}

function Get-EventsSafely {
    param(
        [string]$LogName,
        [int[]]$Id,
        [datetime]$StartTime
    )

    try {
        return @(Get-WinEvent -FilterHashtable @{
            LogName   = $LogName
            Id        = $Id
            StartTime = $StartTime
        } -ErrorAction Stop)
    } catch {
        # Missing log (Sysmon not installed), insufficient permissions, or
        # simply no matching events in range all land here - every case
        # means "nothing to report right now."
        return @()
    }
}

$sysmonEvents = Get-EventsSafely -LogName 'Microsoft-Windows-Sysmon/Operational' -Id 1, 3, 22 -StartTime $sinceTime
$securityEvents = Get-EventsSafely -LogName 'Security' -Id 4625 -StartTime $sinceTime

foreach ($record in (@($sysmonEvents) + @($securityEvents))) {
    $payload = [ordered]@{
        LogName     = $record.LogName
        EventId     = [int]$record.Id
        TimeCreated = $record.TimeCreated.ToUniversalTime().ToString('o')
        Data        = ConvertTo-EventDataHash -Record $record
    }
    $payload | ConvertTo-Json -Compress -Depth 6
}
