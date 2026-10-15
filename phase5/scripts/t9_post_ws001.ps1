$ErrorActionPreference='Continue'
"=== POST-ACTIVITY SNAPSHOT (WS001) ==="
"TIME_LOCAL=$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Get-Service Sysmon64 | Format-List Name,Status,StartType
$g='{edcef402-fb54-6acf-ef04-000000000700}'
"=== Network (Sysmon Ev3) for the encoded process ProcessGuid over last 2h ==="
$n=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=3;StartTime=(Get-Date).AddHours(-2)} -EA SilentlyContinue | Where-Object { $_.ToXml() -match [regex]::Escape($g) })
"Ev3 for $g count = $($n.Count)"
"=== Local 4104 for the marker (still retained) ==="
$m=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=(Get-Date '2026-10-15 00:58:00')} -EA SilentlyContinue | Where-Object { $_.Message -match 'SOC002-PHASE5-ENCODED-POWERSHELL' })
"local 4104 marker events = $($m.Count)"
$m | ForEach-Object { "  RecId=$($_.RecordId) $($_.TimeCreated.ToString('HH:mm:ss.fff')) ExecPID=$((([xml]$_.ToXml()).Event.System).Execution.ProcessID)" }
"=== Services / autoruns sanity (no new service) ==="
"=== done ==="
