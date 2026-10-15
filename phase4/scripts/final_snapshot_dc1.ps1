$ErrorActionPreference='Continue'
"########## DC1 ##########"
"NOW=" + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')
"--- WEF subscription ---"
wecutil gs SOC002-WS001-Security | Select-String -Pattern 'Subscription Id|Description|Enabled|DeliveryMode|Sysmon'
"--- WEF runtime ---"
wecutil gr SOC002-WS001-Security
"--- EventCollector/Operational non-Information since 2026-10-15 00:40 ---"
$errs = Get-WinEvent -LogName 'Microsoft-Windows-EventCollector/Operational' -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt (Get-Date '2026-10-15 00:40') -and $_.LevelDisplayName -ne 'Information' }
"count=$($errs.Count)"
$errs | ForEach-Object { "Id=$($_.Id) $($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) $($_.LevelDisplayName)" }
"--- Sysmon installed on DC1? ---"
$svc = Get-Service Sysmon64 -ErrorAction SilentlyContinue
if ($svc) { "Sysmon64: PRESENT" } else { "Sysmon64: ABSENT (as required)" }
"--- ForwardedEvents coverage ---"
$all = Get-WinEvent -LogName ForwardedEvents -ErrorAction SilentlyContinue
foreach ($pair in @(@('Microsoft-Windows-Security-Auditing',4624),@('Microsoft-Windows-Security-Auditing',4625),@('Microsoft-Windows-Security-Auditing',4688),@('Microsoft-Windows-PowerShell',4104),@('Microsoft-Windows-Sysmon',1),@('Microsoft-Windows-Sysmon',3))) {
  $p=$pair[0]; $i=[int]$pair[1]
  $set = $all | Where-Object { $_.ProviderName -eq $p -and $_.Id -eq $i }
  $n = $set | Select-Object -First 1
  $newest = '-'
  if ($n) { $newest = $n.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') }
  "{0,-40} {1,-5} count={2,-6} newest={3}" -f $p,$i,$set.Count,$newest
}
