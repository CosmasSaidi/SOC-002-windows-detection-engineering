$ErrorActionPreference='Continue'
"=== POST-ACTIVITY SNAPSHOT (DC1) ==="
"TIME_LOCAL=$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
wecutil gr SOC002-WS001-Security
$S=Get-Date '2026-10-15 00:58:00';$E=Get-Date '2026-10-15 01:10:00'
foreach($id in 1,3,4624,4625,4688,4104){ $c=@(Get-WinEvent -FilterHashtable @{LogName='ForwardedEvents';Id=$id;StartTime=$S;EndTime=$E} -EA SilentlyContinue).Count; "ForwardedEvents Id=$id count=$c" }
"=== done ==="
