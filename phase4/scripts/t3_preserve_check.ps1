$ErrorActionPreference='Continue'
$l = Get-WinEvent -ListLog ForwardedEvents
"ForwardedEvents RecordCount = $($l.RecordCount)"
$all = Get-WinEvent -LogName ForwardedEvents -ErrorAction SilentlyContinue
"newestRecordId=$($all[0].RecordId)  oldestRecordId=$($all[-1].RecordId)"
"maxRecordId=$((($all | Measure-Object RecordId -Maximum).Maximum))"
"=== Is EventRecordID the source's or the collector's own sequence? ==="
"RecordCount=$($l.RecordCount) vs maxRecordId=$((($all | Measure-Object RecordId -Maximum).Maximum))  -> if maxRecordId >> RecordCount then source IDs are preserved"
"=== Existing telemetry preserved after subscription change (by provider/id, newest timestamps) ==="
foreach ($pair in @(@('Microsoft-Windows-Security-Auditing',4688),@('Microsoft-Windows-Security-Auditing',4624),@('Microsoft-Windows-PowerShell',4104),@('Microsoft-Windows-Sysmon',1),@('Microsoft-Windows-Sysmon',3))) {
  $p=$pair[0]; $i=[int]$pair[1]
  $ev = $all | Where-Object { $_.ProviderName -eq $p -and $_.Id -eq $i } | Select-Object -First 1
  if ($ev) { "{0} {1}: newest TimeCreated={2} FwdRecId={3}" -f $p,$i,$ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'),$ev.RecordId } else { "{0} {1}: NONE" -f $p,$i }
}
"=== wecutil gr ==="
wecutil gr SOC002-WS001-Security
