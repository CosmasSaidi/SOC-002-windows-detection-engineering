$ErrorActionPreference='Continue'
$S=Get-Date '2026-10-15 00:59:40';$E=Get-Date '2026-10-15 00:59:55'
function P($e){$x=[xml]$e.ToXml();$d=[ordered]@{};foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.'#text'};@{X=$x;D=$d}}
"=== SYSMON EVENT1 ancestry (sorted) 00:59:40-55 ==="
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1;StartTime=$S;EndTime=$E} -EA SilentlyContinue |
 Sort-Object TimeCreated | ForEach-Object { $p=P $_
 "RecId=$($_.RecordId) Utc=$($_.TimeCreated.ToUniversalTime().ToString('HH:mm:ss.fff')) PID=$($p.D['ProcessId']) PPID=$($p.D['ParentProcessId']) Img=$(Split-Path -Leaf $p.D['Image']) Parent=$(Split-Path -Leaf $p.D['ParentImage'])"
 }
