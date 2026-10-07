$decodedScript = @'
#WIN-AI-001: create a logon task and Run value for the same script.
$ErrorActionPreference = 'Stop'
$payload = 'C:\ProgramData\GloboMantics\TelemetryCheck.ps1'
New-Item -ItemType Directory -Path (Split-Path $payload) -Force | Out-Null
New-Item -ItemType File -Path $payload -Value 'Add-Content "C:\ProgramData\GloboMantics\execution.log" -Value ([DateTime]::UtcNow.ToString("o")) -Encoding UTF8' | Out-Null
$arguments = '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\GloboMantics\TelemetryCheck.ps1"'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskPath '\GloboMantics\' -TaskName 'Telemetry Updater' -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
New-Item -Path $runKey -Force | Out-Null
New-ItemProperty -Path $runKey -Name GloboManticsTelemetry -PropertyType String -Value "powershell.exe $arguments" -Force | Out-Null
'@

$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($decodedScript))
$process = Start-Process "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList '-NoProfile', '-WindowStyle', 'Hidden', '-EncodedCommand', $encoded -PassThru -Wait
if ($process.ExitCode -ne 0) { throw "Scenario setup failed ($($process.ExitCode))." }
#Use the process start time for the alert's evidence window.
New-Item -ItemType Directory -Path 'C:\Users\Public\Desktop\LAB_FILES\Alert' -Force | Out-Null
[ordered]@{
    ScenarioId = 'WIN-AI-001'
    AlertUtc = $process.StartTime.ToUniversalTime().ToString('o')
    Signal = 'Hidden Windows PowerShell with EncodedCommand'
    SuggestedSecondsBefore = 5
    SuggestedSecondsAfter = 15
} | ConvertTo-Json | Set-Content 'C:\Users\Public\Desktop\LAB_FILES\Alert\WIN-AI-001.json' -Encoding UTF8
