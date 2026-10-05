$ErrorActionPreference = 'Stop'
$package = Get-Content 'C:\Lab\Evidence\learner-case\ai-sanitized\evidence-package.json' -Raw | ConvertFrom-Json
foreach ($record in $package.Records) { $record.TimeCreatedUtc = ([DateTime]$record.TimeCreatedUtc).ToUniversalTime().ToString('o') }
$process = $package.Records | Where-Object EventId -eq 1
$block = $package.Records | Where-Object EventId -eq 4104
$registry = $package.Records | Where-Object EventId -eq 13
$task = $package.Records | Where-Object EventId -eq 4698
$taskXml = [xml]$task.TaskContent
if ($process.ProcessGuid -ne $registry.ProcessGuid -or $process.ProcessId -ne $block.ProcessId) { throw 'The selected records do not correlate.' }
if ($registry.Details -cne "$($taskXml.Task.Actions.Exec.Command) $($taskXml.Task.Actions.Exec.Arguments)") { throw 'The recorded task and Run commands differ.' }
@(
    '# Reference analysis'
    '## 1. Observed'
    "- Sysmon 1, RecordId $($process.RecordId), UTC $($process.TimeCreatedUtc): Image is $($process.Image). CommandLine contains -EncodedCommand. ProcessId is $($process.ProcessId)."
    "- PowerShell 4104, RecordId $($block.RecordId), UTC $($block.TimeCreatedUtc): ProcessId is $($block.ProcessId). ScriptBlockText contains the task and Run-value definitions."
    "- Sysmon 13, RecordId $($registry.RecordId), UTC $($registry.TimeCreatedUtc): TargetObject is $($registry.TargetObject). Details is $($registry.Details)."
    "- Security 4698, RecordId $($task.RecordId), UTC $($task.TimeCreatedUtc): TaskName is $($task.TaskName). TaskContent specifies a logon trigger. ClientProcessId is $($task.ClientProcessId)."
    '## 2. AI interpretation'
    '- High confidence: the matching ProcessGuid links the encoded process to the Run-value write. The matching ProcessId links it to the script block.'
    '- High confidence: the task and Run value configure the same script to launch at logon. This establishes configuration; later execution still needs evidence.'
    '- Moderate confidence: the task name, action, and timing support a relationship to the script block. Check the task client PID separately before attributing task creation to a process.'
    '## 3. Missing evidence'
    '- These four records do not establish a later payload launch, a network transfer, or authorization. They also do not establish the current endpoint state.'
    '- Encoding and persistence alone do not establish malicious intent.'
    '## 4. Local verification steps'
    'Run these in the affected account. Decode the command as text and inspect the named artifacts before accepting the interpretation.'
    '```powershell'
    '$package = Get-Content C:\Lab\Evidence\learner-case\ai-sanitized\evidence-package.json -Raw | ConvertFrom-Json'
    '$encoded = (($package.Records | Where-Object EventId -eq 1).CommandLine -split ''-EncodedCommand\s+'', 2)[1].Trim()'
    '[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded))'
    'Get-ScheduledTask -TaskPath ''\GloboMantics\'' -TaskName ''Telemetry Updater'' | Select-Object -ExpandProperty Actions'
    'Export-ScheduledTask -TaskPath ''\GloboMantics\'' -TaskName ''Telemetry Updater'''
    'Get-ItemPropertyValue ''HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'' -Name GloboManticsTelemetry'
    'Get-Content C:\ProgramData\GloboMantics\TelemetryCheck.ps1'
    'Test-Path C:\ProgramData\GloboMantics\execution.log'
    '```'
) | Set-Content 'C:\Lab\Analysis\ai-review.md' -Encoding UTF8
