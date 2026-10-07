## 1. Observed

Finding label: Observed. Every item below is a field value in a named record. Timestamps are shown as the package tokens.

- **Sysmon, Event ID 1, <SYSMON-1-UTC>, RecordId <SYSMON-1-RECORD-ID>.**
  - `Image` is `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`.
  - `CommandLine` begins `powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand` followed by a Base64 string.
  - `ProcessGuid` is <ENCODED-PROCESS-GUID> and `ProcessId` is <ENCODED-PROCESS-ID>.
  - `ParentImage` is `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`. `ParentCommandLine` is <PARENT-COMMAND-LINE>, so the package does not show what the parent was running.
  - `User` is <LAB-HOST>\<LAB-USER>. `Hashes` is <POWERSHELL-SHA256>.
- **Decoding the Base64 in that `CommandLine` field as UTF-16LE** gives text identical to the `ScriptBlockText` of the 4104 record below. I decoded it for reading only and did not run it.
- **PowerShell Operational, Event ID 4104, <POWERSHELL-4104-UTC>, RecordId <POWERSHELL-4104-RECORD-ID>.**
  - `ProcessId` is <ENCODED-PROCESS-ID>, matching the Sysmon 1 record. `ScriptBlockId` is <SCRIPT-BLOCK-ID>. `MessageNumber` and `MessageTotal` are both 1. `Path` is empty.
  - `ScriptBlockText` begins with the comment `#WIN-AI-001: create a logon task and Run value for the same script.`
  - It sets `$payload` to `C:\ProgramData\GloboMantics\TelemetryCheck.ps1`.
  - It calls `New-Item -ItemType File -Path $payload -Value` with the content `Add-Content "C:\ProgramData\GloboMantics\execution.log" -Value ([DateTime]::UtcNow.ToString("o")) -Encoding UTF8`.
  - It sets `$arguments` to `-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\GloboMantics\TelemetryCheck.ps1"`.
  - It calls `New-ScheduledTaskTrigger -AtLogOn`.
  - It calls `New-ScheduledTaskPrincipal` with `-LogonType Interactive -RunLevel Limited`.
  - It calls `Register-ScheduledTask -TaskPath '\GloboMantics\' -TaskName 'Telemetry Updater'`.
  - It writes a value named `GloboManticsTelemetry` under `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`, with the value `"powershell.exe $arguments"`.
- **Sysmon, Event ID 13, <SYSMON-13-UTC>, RecordId <SYSMON-13-RECORD-ID>.**
  - `EventType` is `SetValue`. `ProcessGuid` is <ENCODED-PROCESS-GUID> and `ProcessId` is <ENCODED-PROCESS-ID>.
  - `Image` is `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`.
  - `TargetObject` is `HKU\<LAB-USER-SID>\Software\Microsoft\Windows\CurrentVersion\Run\GloboManticsTelemetry`.
  - `Details` is `powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\GloboMantics\TelemetryCheck.ps1"`.
- **Security, Event ID 4698, <SECURITY-4698-UTC>, RecordId <SECURITY-4698-RECORD-ID>.**
  - `TaskName` is `\GloboMantics\Telemetry Updater`.
  - `SubjectUserSid` is <LAB-USER-SID>, `SubjectUserName` is <LAB-USER>, `SubjectDomainName` is <LAB-HOST>, and `SubjectLogonId` is <LOGON-ID>.
  - `ClientProcessId` is <TASK-CLIENT-PROCESS-ID> and `ParentProcessId` is <TASK-PARENT-PROCESS-ID>.
  - In `TaskContent`, `Triggers` holds a `LogonTrigger` with `Enabled` true.
  - In `TaskContent`, the `Principal` has `LogonType` `InteractiveToken` and `RunLevel` `LeastPrivilege`.
  - In `TaskContent`, the `Exec` action has `Command` `powershell.exe` and `Arguments` `-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\GloboMantics\TelemetryCheck.ps1"`. The XML shows the quotes as `&quot;`.
  - `Settings` has `Enabled` true, `DisallowStartIfOnBatteries` false and `StopIfGoingOnBatteries` false.
- **Package `ScopeNote`:** "Focused endpoint records only. Absence from this package is not proof that an event or behavior did not occur."

## 2. AI interpretation

Finding label: AI interpretation. None of this is Locally confirmed or Expected.

1. **The encoded PowerShell process is a one-time setup script that created both the task and the Run value. Confidence: high.**
   - Supporting observations:
     - The Sysmon 1 `ProcessId` is <ENCODED-PROCESS-ID>.
     - The 4104 `ProcessId` is <ENCODED-PROCESS-ID>.
     - The Sysmon 13 `ProcessId` and `ProcessGuid` are <ENCODED-PROCESS-ID> and <ENCODED-PROCESS-GUID>.
     - The decoded `-EncodedCommand` text matches the 4104 `ScriptBlockText`.
     - That text contains both the `Register-ScheduledTask` call and the Run value write.
   - The Security 4698 record independently shows the task being created, with `SubjectUserName` <LAB-USER>. The package does not show which process made that call beyond <TASK-CLIENT-PROCESS-ID>, so the link to the encoded process comes from the script text and the matching `TaskName`.

2. **The scheduled task and the Run value are two redundant logon-time triggers for the same script. Confidence: high.**
   - Supporting observations:
     - The 4698 `Arguments` and the Sysmon 13 `Details` use the same `powershell.exe` argument string.
     - Both target `C:\ProgramData\GloboMantics\TelemetryCheck.ps1`.
     - The task uses a `LogonTrigger`, and the Run key also runs at user logon.
   - Both entries run as the interactive user at limited privilege (`RunLevel` `LeastPrivilege`), not as SYSTEM.

3. **The payload content is a low-impact logging stub. Confidence: medium.**
   - Supporting observations: the file content written by the 4104 script is an `Add-Content` call that appends a UTC timestamp to `C:\ProgramData\GloboMantics\execution.log`. The script comment calls the purpose "create a logon task and Run value for the same script."
   - Confidence is medium because the package only shows what the setup script wrote. It does not show the file as it exists now.

4. **The hidden window, encoded command, and persistence are consistent with an automated or lab-testing deployment, but they do not establish intent. Confidence: low to medium.**
   - Supporting observations: the names `GloboMantics`, `Telemetry Updater`, `GloboManticsTelemetry` and `TelemetryCheck.ps1` are consistent and benign-sounding, and the 4104 comment carries a scenario ID.
   - The artifact is not called malicious here. Encoded, hidden, and persistent behavior also appears in legitimate administration and deployment tooling, and names alone prove nothing.

## 3. Missing evidence

The package cannot establish the following.

- **Whether the payload ever ran.** No record shows `TelemetryCheck.ps1` being executed. There is no Sysmon 1 with `-File "C:\ProgramData\GloboMantics\TelemetryCheck.ps1"` in the package. There is no Security 4688 or Task Scheduler Operational record, and no `execution.log` file or content. Absence from this package is not proof of non-occurrence.
- **Whether the task or Run value ever fired at a logon.** Only the creation events are present.
- **Whether any network connection occurred.** The package has no Sysmon Event ID 3 or DNS records. The decoded script text contains no network call, but this package alone cannot show what the encoded process or any later process did on the network.
- **Whether the payload file still exists, or what it contains now.** The package shows only what the script wrote.
- **Who authorized the activity.** `SubjectUserName` <LAB-USER> shows which account was involved, not who approved the work. The package has no change ticket, administrator statement, or deployment tool record. The parent of the encoded process is <PARENT-COMMAND-LINE>, and it is also `powershell.exe`, so the launch source is unknown.
- **Whether the artifacts are expected in this environment.** The package has no baseline, inventory, or software list showing these names as approved.
- **The current state of the task and Run value.** Both records are creation-time events, so later changes, deletions, or modifications are not covered.
- **The window of coverage.** Records fall between <WINDOW-START-UTC> and <WINDOW-END-UTC>. The package was built at <PACKAGE-BUILT-UTC>.

## 4. Local verification steps

Finding labels: nothing below is Locally confirmed until a person runs the commands and records the results. All commands are read-only. Do not run the decoded text or the payload.

**a. Decode the Base64 as UTF-16LE text (display only).** Copy the string after `-EncodedCommand` from the Sysmon 1 `CommandLine` field into `$b`.

```powershell
$b = '<paste Base64 from Sysmon 1 CommandLine>'
$bytes = [Convert]::FromBase64String($b)
$text = [Text.Encoding]::Unicode.GetString($bytes)
$text            # display only; do not pipe to Invoke-Expression or powershell.exe
```

**b. Inspect the scheduled task: action, trigger, principal, XML.**

```powershell
$t = Get-ScheduledTask -TaskPath '\GloboMantics\' -TaskName 'Telemetry Updater'
$t.Actions   | Format-List Execute, Arguments, WorkingDirectory
$t.Triggers  | Format-List *
$t.Principal | Format-List UserId, LogonType, RunLevel
$t.Settings  | Format-List Enabled
Get-ScheduledTaskInfo -TaskPath '\GloboMantics\' -TaskName 'Telemetry Updater' | Format-List LastRunTime, LastTaskResult, NextRunTime
Export-ScheduledTask -TaskPath '\GloboMantics\' -TaskName 'Telemetry Updater'
```

**c. Inspect the named Run value.**

```powershell
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'GloboManticsTelemetry' | Select-Object GloboManticsTelemetry
```

Run this as <LAB-USER>. To read it from another account, use the SID from the Sysmon 13 `TargetObject` under `HKU:\`.

**d. Check the named payload file and the log, without running them.**

```powershell
$p = 'C:\ProgramData\GloboMantics\TelemetryCheck.ps1'
Get-Item -LiteralPath $p | Format-List FullName, Length, CreationTimeUtc, LastWriteTimeUtc
Get-FileHash -LiteralPath $p -Algorithm SHA256
Get-Content -LiteralPath $p -Raw          # display only
Get-AuthenticodeSignature -LiteralPath $p | Format-List Status, SignerCertificate
Get-Acl -LiteralPath $p | Format-List Owner, AccessToString
Get-Item -LiteralPath 'C:\ProgramData\GloboMantics\execution.log' -ErrorAction SilentlyContinue | Format-List FullName, Length, LastWriteTimeUtc
```

Compare the file content with the content shown in the 4104 `ScriptBlockText`. If `execution.log` exists, its timestamps would indicate that the payload ran.

**e. Proposed fix (NOT executed; requires approval and verification first).** Applies only after the checks above confirm the artifacts are unauthorized or unneeded and the owner of this environment approves in writing.

1. Preserve recovery copies first:
   - Export the task XML with `Export-ScheduledTask`, and save it to an evidence folder.
   - Export the Run value, for example with `reg export` of the `Run` key, or save the value text from step c.
   - Copy `TelemetryCheck.ps1` and `execution.log`, if present, to the evidence folder, and record their SHA256 hashes.
2. Disable only the named task, `\GloboMantics\Telemetry Updater`, instead of deleting it. For example, `Disable-ScheduledTask -TaskPath '\GloboMantics\' -TaskName 'Telemetry Updater'`.
3. Remove only the named value, `GloboManticsTelemetry`, under the user's `Run` key. For example, `Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'GloboManticsTelemetry'`.
4. Verify after the change:
   - The task shows `State` Disabled and the XML still matches the export.
   - The Run value is absent, and the other `Run` values are unchanged.
   - The payload file and the rest of `C:\ProgramData\GloboMantics\` are untouched.
5. Do not delete the `GloboMantics` folder, other tasks, or other `Run` entries. Do not remove the payload file until the investigation is complete and the owner approves. To roll back, re-enable the task and restore the value from the saved export.
