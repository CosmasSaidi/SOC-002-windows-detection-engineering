$ErrorActionPreference='Continue'
$S=Get-Date '2026-10-15 00:59:40';$E=Get-Date '2026-10-15 00:59:58'
"=== TaskScheduler 106 events in window ==="
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational';Id=106;StartTime=$S;EndTime=$E} -EA SilentlyContinue |
 ForEach-Object { $x=[xml]$_.ToXml(); $d=@{}; foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.'#text'}
  "$($_.TimeCreated.ToString('HH:mm:ss.fff'))  User=$($d['UserName'])  Task=$($d['TaskName'])  RecId=$($_.RecordId)" }
"=== same, wider 00:55-01:05 count ==="
$a=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational';Id=106;StartTime=(Get-Date '2026-10-15 00:55:00');EndTime=(Get-Date '2026-10-15 01:05:00')} -EA SilentlyContinue)
"count=$($a.Count)"
"=== cmd to powershell 4688 chain (creator) in window ==="
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688;StartTime=$S;EndTime=$E} -EA SilentlyContinue |
 ForEach-Object { $x=[xml]$_.ToXml(); $d=@{}; foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.'#text'}
  "$($_.TimeCreated.ToString('HH:mm:ss.fff')) New=$($d['NewProcessName'].Split('\')[-1]) NewPID=$($d['NewProcessId']) Creator=$($d['ParentProcessName'].Split('\')[-1]) CreatorPID=$($d['ProcessId'])" }
