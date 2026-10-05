#Requires -RunAsAdministrator
param([switch]$PassThru)
$ErrorActionPreference = 'Stop'
$alert = Get-Content 'C:\Lab\Alert\WIN-AI-001.json' -Raw | ConvertFrom-Json
$start = ([DateTime]$alert.AlertUtc).AddSeconds(-1).ToLocalTime()
$end = ([DateTime]$alert.AlertUtc).AddSeconds($alert.SuggestedSecondsAfter).ToLocalTime()

#Match the script block and registry write to the encoded process.
$sysmon = @(Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$start; EndTime=$end } -Oldest)
$process = @($sysmon | Where-Object { $_.Id -eq 1 -and $_.Message -match '(?m)^CommandLine:.*-EncodedCommand' })
if ($process.Count -ne 1) { throw 'Expected one encoded PowerShell process.' }
$data = ([xml]$process[0].ToXml()).Event.EventData.Data
$processId = ($data | Where-Object Name -eq 'ProcessId').'#text'
$processGuid = ($data | Where-Object Name -eq 'ProcessGuid').'#text'
$scriptBlock = @(Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=$start; EndTime=$end } -Oldest | Where-Object { $_.ProcessId -eq $processId -and $_.Message -match 'WIN-AI-001' })
$registry = @($sysmon | Where-Object { $_.Id -eq 13 -and $_.Message -match [regex]::Escape($processGuid) -and $_.Message -match '\\Run\\GloboManticsTelemetry' })
$taskEvent = @(Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4698; StartTime=$start; EndTime=$end } -Oldest | Where-Object { $_.Message -match '\\GloboMantics\\Telemetry Updater' })
$task = Get-ScheduledTask -TaskPath '\GloboMantics\' -TaskName 'Telemetry Updater'
$run = Get-ItemPropertyValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name GloboManticsTelemetry
$checks = [ordered]@{
    'Sysmon 1' = $process.Count -eq 1
    'PowerShell 4104' = $scriptBlock.Count -eq 1
    'Sysmon 13' = $registry.Count -eq 1
    'Security 4698' = $taskEvent.Count -eq 1
    'Task and Run value match' = $run -ceq "$($task.Actions.Execute) $($task.Actions.Arguments)"
    'Payload file exists' = Test-Path 'C:\ProgramData\GloboMantics\TelemetryCheck.ps1'
}
$checks.GetEnumerator() | Format-Table Key, Value -AutoSize | Out-String | Tee-Object -FilePath 'C:\Lab\test-results.txt' | Write-Host
if ($checks.Values -contains $false) { throw 'See C:\Lab\test-results.txt for the failed check.' }
if ($PassThru) { $process + $scriptBlock + $registry + $taskEvent }
