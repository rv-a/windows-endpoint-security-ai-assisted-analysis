#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
Start-Transcript -Path 'C:\Lab\setup.log' -Force

# Enable logging before creating the scenario.
$key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name EnableScriptBlockLogging -PropertyType DWord -Value 1 -Force | Out-Null
& auditpol.exe /set '/subcategory:{0CCE9227-69AE-11D9-BED3-505054503030}' /success:enable
if ($LASTEXITCODE -ne 0) { throw 'Could not enable task auditing.' }
& wevtutil.exe sl Microsoft-Windows-PowerShell/Operational /e:true
if ($LASTEXITCODE -ne 0) { throw 'Could not enable PowerShell logging.' }
$sysmonMode = if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) { '-c' } else { '-i' }
& 'C:\Lab\Sysmon\Sysmon64.exe' -accepteula $sysmonMode "$PSScriptRoot\sysmonconfig.xml"
if ($LASTEXITCODE -ne 0) { throw 'Could not configure Sysmon.' }

& "$PSScriptRoot\Seed-Scenario.ps1"
Start-Sleep -Seconds 5
& "$PSScriptRoot\Test-Lab.ps1"
Unregister-ScheduledTask -TaskName 'Endpoint lab setup' -Confirm:$false -ErrorAction SilentlyContinue
'Lab setup complete.'
Stop-Transcript
