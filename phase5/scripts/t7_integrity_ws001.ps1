$ErrorActionPreference='Continue'
$S=Get-Date '2026-10-15 00:59:40';$E=Get-Date '2026-10-15 00:59:58'
"=== POST-EXECUTION INTEGRITY CHECKS (WS001) window 00:59:40-58 local ==="
foreach($id in 4697,4698,4699,4700,4701,4702,4672,1102){
  $ev=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=$id;StartTime=$S;EndTime=$E} -EA SilentlyContinue)
  "Security $id count = $($ev.Count)"
}
$s=@(Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=$S;EndTime=$E} -EA SilentlyContinue)
"System   7045 (service install) count = $($s.Count)"
"=== TaskScheduler 106 (task created) in window ==="
$t=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational';Id=106;StartTime=$S;EndTime=$E} -EA SilentlyContinue)
"TaskScheduler 106 count = $($t.Count)"
"=== audit subcategories relevant to persistence ==="
auditpol /get /subcategory:"Security System Extension" | Select-String -Pattern 'Security System Extension|Success|Failure'
auditpol /get /subcategory:"Other Object Access Events" | Select-String -Pattern 'Other Object Access|Success|Failure'
"=== done ==="
