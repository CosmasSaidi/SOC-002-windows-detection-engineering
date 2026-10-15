$ErrorActionPreference='Continue'
$L='Microsoft-Windows-Sysmon/Operational'
$S=Get-Date '2026-10-15 00:58:00';$E=Get-Date '2026-10-15 01:08:00'
function P($e){$x=[xml]$e.ToXml();$d=[ordered]@{};foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.'#text'};@{X=$x;D=$d}}
"=== SYSMON EVENT 3 (all in window) ==="
$a=@(Get-WinEvent -FilterHashtable @{LogName=$L;Id=3;StartTime=$S;EndTime=$E} -EA SilentlyContinue)
"COUNT=$($a.Count)"
foreach($e in $a){$p=P $e
"--- RecId=$($e.RecordId) ---"
"TimeUtc=$($e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
foreach($k in @('ProcessGuid','Image','DestinationIp','DestinationPort','DestinationHostname','User')){"$k=$($p.D[$k])"}
"===RAWXML-BEGIN Sysmon3-Rec$($e.RecordId)==="
$e.ToXml()
"===RAWXML-END==="
}
