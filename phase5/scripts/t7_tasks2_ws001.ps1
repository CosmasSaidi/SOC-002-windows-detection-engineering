$ErrorActionPreference='Continue'
"=== TaskScheduler operational log state ==="
Get-WinEvent -ListLog 'Microsoft-Windows-TaskScheduler/Operational' -EA SilentlyContinue | Format-List LogName,IsEnabled,RecordCount,LastWriteTime
"=== count Id=106 ALL time (MaxEvents 5) ==="
$a=@(Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' -MaxEvents 5 -EA SilentlyContinue)
"recent 5 ids: " + (($a | ForEach-Object { $_.Id }) -join ',')
"newest: " + (($a | Select-Object -First 1).TimeCreated)
"=== Id=106 in 00:55-01:05 ==="
$b=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational';Id=106;StartTime=(Get-Date '2026-10-15 00:55:00');EndTime=(Get-Date '2026-10-15 01:05:00')} -EA SilentlyContinue)
"count=$($b.Count)"
$b | Select-Object -First 12 | ForEach-Object { $x=[xml]$_.ToXml(); $d=@{}; foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.'#text'}; "$($_.TimeCreated.ToString('HH:mm:ss')) Task=$($d['TaskName']) User=$($d['UserName'])" }
