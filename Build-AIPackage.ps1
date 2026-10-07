param(
    [string]$RawRoot = 'C:\Users\Public\Desktop\LAB_FILES\Evidence\learner-case\raw',
    [string]$AiRoot = 'C:\Users\Public\Desktop\LAB_FILES\Evidence\learner-case\ai-sanitized',
    [Parameter(Mandatory)][DateTime]$StartUtc,
    [Parameter(Mandatory)][DateTime]$EndUtc,
    [Parameter(Mandatory)][long]$Sysmon1RecordId,
    [Parameter(Mandatory)][long]$Sysmon13RecordId,
    [Parameter(Mandatory)][long]$PowerShell4104RecordId,
    [Parameter(Mandatory)][long]$Security4698RecordId
)

$ErrorActionPreference = 'Stop'

$identity = Get-Content 'C:\ProgramData\EndpointLabSetup\State\identity.json' -Raw | ConvertFrom-Json
$redactionRules = [ordered]@{
    UserSid = [ordered]@{ Category = 'Current user SID'; Source = [string]$identity.UserSid; Replacement = '<LAB-USER-SID>'; Replacements = 0 }
    Host = [ordered]@{ Category = 'Computer name'; Source = [string]$identity.ComputerName; Replacement = '<LAB-HOST>'; Replacements = 0 }
    Domain = [ordered]@{ Category = 'User domain'; Source = [string]$identity.UserDomain; Replacement = '<LAB-DOMAIN>'; Replacements = 0 }
    User = [ordered]@{ Category = 'Current user name'; Source = [string]$identity.UserName; Replacement = '<LAB-USER>'; Replacements = 0 }
}
function Protect-LabIdentity {
    param([string]$Value, [switch]$Xml)
    foreach ($rule in $redactionRules.Values) {
        $pattern = [regex]::new([regex]::Escape($rule.Source), 'IgnoreCase')
        $rule.Replacements += $pattern.Matches($Value).Count
        $replacement = if ($Xml) { [Security.SecurityElement]::Escape($rule.Replacement) } else { $rule.Replacement }
        $Value = $pattern.Replace($Value, $replacement)
    }
    $Value
}

$privateFields = @(
    'ProcessGuid', 'Image', 'CommandLine', 'ParentProcessGuid', 'ParentImage', 'ParentCommandLine',
    'User', 'ScriptBlockText', 'Path', 'TargetObject', 'Details', 'SubjectUserSid', 'SubjectUserName',
    'SubjectDomainName', 'TaskContent', 'FQDN'
)
$selections = @(
    @{ Source='Sysmon'; File='sysmon-operational.evtx'; Id=1; RecordId=$Sysmon1RecordId
       Fields='ProcessGuid ProcessId Image CommandLine ParentProcessGuid ParentProcessId ParentImage ParentCommandLine User Hashes' }
    @{ Source='PowerShell Operational'; File='powershell-operational.evtx'; Id=4104; RecordId=$PowerShell4104RecordId
       Fields='ProcessId ScriptBlockId MessageNumber MessageTotal ScriptBlockText Path' }
    @{ Source='Sysmon'; File='sysmon-operational.evtx'; Id=13; RecordId=$Sysmon13RecordId
       Fields='EventType ProcessGuid ProcessId Image TargetObject Details User' }
    @{ Source='Security'; File='security.evtx'; Id=4698; RecordId=$Security4698RecordId
       Fields='SubjectUserSid SubjectUserName SubjectDomainName SubjectLogonId TaskName TaskContent ClientProcessId ParentProcessId FQDN' }
)
$records = @(
    foreach ($selection in $selections) {
        $events = @(Get-WinEvent -Path (Join-Path $RawRoot $selection.File) -Oldest |
            Where-Object RecordId -eq $selection.RecordId)
        if ($events.Count -ne 1) { throw "$($selection.Source) RecordId $($selection.RecordId) matched $($events.Count) records." }
        $event = $events[0]
        if ($event.Id -ne $selection.Id) { throw "Event ID $($event.Id), not $($selection.Id)." }
        $utc = $event.TimeCreated.ToUniversalTime()
        if ($utc -lt $StartUtc -or $utc -gt $EndUtc) { throw 'Record is outside the selected UTC window.' }
        [xml]$xml = $event.ToXml()
        $data = @{}
        foreach ($item in $xml.Event.EventData.Data) { $data[$item.Name] = [string]$item.InnerText }
        if ($selection.Id -eq 4104) { $data.ProcessId = [string]$xml.Event.System.Execution.ProcessID }
        $record = [ordered]@{
            Label='Observed'; Source=$selection.Source; EventId=$event.Id
            TimeCreatedUtc=$utc.ToString('o'); RecordId=[string]$event.RecordId
        }
        foreach ($field in $selection.Fields.Split(' ')) {
            $value = [string]$data[$field]
            if ($field -in $privateFields) { $value = Protect-LabIdentity $value -Xml:($field -eq 'TaskContent') }
            $record[$field] = $value
        }
        [pscustomobject]$record
    }
)

$package = [ordered]@{
    SchemaVersion = 1
    ScenarioId = 'WIN-AI-001'
    Label = 'Observed'
    GeneratedUtc = [DateTime]::UtcNow.ToString('o')
    WindowUtc = [ordered]@{ Start = $StartUtc.ToString('o'); End = $EndUtc.ToString('o') }
    Sanitization = [ordered]@{ Host = '<LAB-HOST>'; Domain = '<LAB-DOMAIN>'; User = '<LAB-USER>'; Sid = '<LAB-USER-SID>' }
    Records = @($records | Sort-Object { $_.TimeCreatedUtc }, { $_.Source }, { $_.EventId })
}
$packagePath = Join-Path $AiRoot 'evidence-package.json'
$promptPath = Join-Path $AiRoot 'ai-prompt.txt'
$sourcePromptPath = 'C:\Users\Public\Desktop\LAB_FILES\Analysis\ai-prompt.txt'
$package | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $packagePath -Encoding UTF8
Copy-Item -LiteralPath $sourcePromptPath -Destination $promptPath -Force

$aiBoundaryPaths = @($packagePath, $promptPath)
$leaks = @(
    foreach ($path in $aiBoundaryPaths) {
        $content = Get-Content -LiteralPath $path -Raw
        foreach ($rule in $redactionRules.Values) {
            if ($content.IndexOf($rule.Source, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                [pscustomobject]@{ File = [IO.Path]::GetFileName($path); Category = 'Local identity value' }
            }
        }
    }
)

$rules = @($redactionRules.Values | ForEach-Object { [pscustomobject]$_ } | Select-Object Category, Replacement, Replacements)
$redactionReport = [ordered]@{
    Rules = $rules
    FieldsChecked = $privateFields
    RetainedFields = @(
        'Source', 'EventId', 'TimeCreatedUtc', 'RecordId', 'ProcessId', 'ParentProcessId',
        'ProcessGuid', 'ParentProcessGuid', 'Hashes', 'ScriptBlockId', 'MessageNumber',
        'MessageTotal', 'EventType', 'TargetObject', 'SubjectLogonId', 'TaskName', 'ClientProcessId'
    )
    Verification = [ordered]@{
        FilesChecked = @($aiBoundaryPaths | ForEach-Object { [IO.Path]::GetFileName($_) } | Sort-Object)
        OriginalIdentityLeakCount = $leaks.Count
        TotalReplacements = ($rules | Measure-Object Replacements -Sum).Sum
    }
}
$redactionReportPath = Join-Path $RawRoot 'redaction-report.json'
$redactionReport | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $redactionReportPath -Encoding UTF8
if ($leaks.Count -gt 0) {
    Remove-Item -LiteralPath $packagePath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $promptPath -Force -ErrorAction SilentlyContinue
    throw 'The AI output still contains a local host, domain, user, or SID value.'
}

[pscustomobject]@{
    PackagePath = $packagePath
    RedactionReportPath = $redactionReportPath
    RecordCount = $records.Count
}
