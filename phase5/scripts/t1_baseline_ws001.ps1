$ErrorActionPreference='Continue'
"=== SOC-002 PHASE5 TASK1 BASELINE (WS001) ==="
"HOST           = $env:COMPUTERNAME"
"TIME_LOCAL     = $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
"TIME_UTC       = $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')"
"TZ             = $((Get-TimeZone).Id)"
"=== Sysmon service ==="
Get-Service Sysmon64 -ErrorAction SilentlyContinue | Format-List Name,Status,StartType
"=== Sysmon operational log recency ==="
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 3 -ErrorAction SilentlyContinue |
  ForEach-Object { "  Id=$($_.Id) $($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) RecId=$($_.RecordId)" }
"=== Security log recency (4688/4624/4625) ==="
foreach ($id in 4688,4624,4625) {
  $e = Get-WinEvent -FilterHashtable @{LogName='Security';Id=$id} -MaxEvents 1 -ErrorAction SilentlyContinue
  if ($e) { "  ${id} latest: $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) RecId=$($e.RecordId)" } else { "  ${id}: NONE" }
}
"=== PowerShell Operational recency ==="
$p = Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 1 -ErrorAction SilentlyContinue
if ($p) { "  latest: Id=$($p.Id) $($p.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) RecId=$($p.RecordId)" }
"=== ScriptBlockLogging policy ==="
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue | Select-Object EnableScriptBlockLogging | Format-List
"=== 4688 CommandLine audit ==="
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ErrorAction SilentlyContinue | Select-Object ProcessCreationIncludeCmdLine_Enabled | Format-List
