<#
.SYNOPSIS
    Summarize Windows Security event 4625 (failed logon).

.DESCRIPTION
    Day 2 of my learning log. Windows writes event 4625 every time a logon
    fails. One or two is usually a typo. A burst from one address is someone
    guessing passwords.

    Two modes:

      -Sample   reads the made-up CSV next to this script. Works on any
                machine, no Windows event log and no admin rights needed.

      (default) reads the real Security log on a Windows machine. Reading
                the Security log needs administrator rights.

    Both modes print the same summary: failures per user, per source IP and
    per failure reason, then a short list of anything with -Threshold or
    more failures that is worth a closer look.

.EXAMPLE
    .\Get-FailedLogons.ps1 -Sample

.EXAMPLE
    .\Get-FailedLogons.ps1 -Hours 24 -Threshold 10
#>

[CmdletBinding()]
param(
    [switch]$Sample,
    [string]$SamplePath = (Join-Path $PSScriptRoot 'sample-4625-events.csv'),
    [int]$Hours = 24,
    [int]$Threshold = 5
)

# LogonType says HOW the logon was attempted.
$LogonTypeName = @{
    2  = 'Interactive (keyboard, or runas)'
    3  = 'Network (file share, SMB)'
    4  = 'Batch (scheduled task)'
    5  = 'Service'
    7  = 'Unlock'
    8  = 'NetworkCleartext'
    9  = 'NewCredentials (runas /netonly)'
    10 = 'RemoteInteractive (RDP)'
    11 = 'CachedInteractive (no domain controller reachable)'
}

# SubStatus says WHY it failed.
$StatusMeaning = @{
    '0xC0000064' = 'user name does not exist'
    '0xC000006A' = 'correct user, wrong password'
    '0xC0000234' = 'account locked out'
    '0xC0000071' = 'password expired'
    '0xC0000072' = 'account disabled'
    '0xC0000070' = 'workstation restriction'
}

function Get-SampleFailedLogons {
    param([string]$Path)
    Import-Csv $Path | ForEach-Object {
        [pscustomobject]@{
            TimeCreated    = [datetime]$_.TimeCreated
            TargetUserName = $_.TargetUserName
            IpAddress      = $_.IpAddress
            LogonType      = [int]$_.LogonType
            SubStatus      = $_.SubStatus
        }
    }
}

function Get-RealFailedLogons {
    param([int]$Hours)
    $start = (Get-Date).AddHours(-$Hours)
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $start } -ErrorAction Stop
    foreach ($e in $events) {
        # The useful fields live in the event XML. Pulling them by name is
        # clearer (and safer) than guessing array positions.
        $xml = [xml]$e.ToXml()
        $data = @{}
        foreach ($node in $xml.Event.EventData.Data) {
            $data[$node.Name] = $node.'#text'
        }
        [pscustomobject]@{
            TimeCreated    = $e.TimeCreated
            TargetUserName = $data['TargetUserName']
            IpAddress      = $data['IpAddress']
            LogonType      = [int]$data['LogonType']
            SubStatus      = $data['SubStatus']
        }
    }
}

if ($Sample) {
    Write-Host "Parsing sample data from $SamplePath"
    $rows = @(Get-SampleFailedLogons -Path $SamplePath)
} else {
    Write-Host "Parsing the real Security log (last $Hours hours, needs admin)"
    try {
        $rows = @(Get-RealFailedLogons -Hours $Hours)
    } catch {
        Write-Host "Could not read the Security log: $($_.Exception.Message)"
        Write-Host 'Try running PowerShell as administrator, or use -Sample.'
        exit 1
    }
}

if ($rows.Count -eq 0) {
    Write-Host 'No failed logons found.'
    exit 0
}

Write-Host "$($rows.Count) failed logons (event 4625)"
Write-Host ''

Write-Host 'Failures by user:'
$byUser = $rows | Group-Object TargetUserName | Sort-Object Count -Descending
$byUser | Format-Table Name, Count -AutoSize

Write-Host 'Failures by source IP:'
$byIp = $rows | Group-Object IpAddress | Sort-Object Count -Descending
$byIp | Format-Table Name, Count -AutoSize

Write-Host 'Failures by reason:'
$rows | Group-Object SubStatus | Sort-Object Count -Descending | ForEach-Object {
    [pscustomobject]@{
        SubStatus = $_.Name
        Meaning   = $StatusMeaning[$_.Name]
        Count     = $_.Count
    }
} | Format-Table -AutoSize

Write-Host "Worth a closer look ($Threshold+ failures):"
$found = $false
foreach ($g in ($byUser | Where-Object Count -ge $Threshold)) {
    $found = $true
    $lastIp = ($rows | Where-Object TargetUserName -eq $g.Name |
        Sort-Object TimeCreated -Descending | Select-Object -First 1).IpAddress
    Write-Host "- user '$($g.Name)': $($g.Count) failures, last from $lastIp"
}
foreach ($g in ($byIp | Where-Object Count -ge $Threshold)) {
    $found = $true
    $userCount = @($rows | Where-Object IpAddress -eq $g.Name |
        Group-Object TargetUserName).Count
    Write-Host "- source $($g.Name): $($g.Count) failures against $userCount user name(s)"
}
if (-not $found) {
    Write-Host '- nothing over the threshold'
}
