$ErrorActionPreference='Continue'
$L='ForwardedEvents'
$S=Get-Date '2026-10-15 00:59:40';$E=Get-Date '2026-10-15 00:59:58'
function P($e){$x=[xml]$e.ToXml();$d=[ordered]@{};foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.'#text'};@{X=$x;D=$d}}
"=== D. SYSMON EVENT 3 in tight window (network) ==="
$a=@(Get-WinEvent -FilterHashtable @{LogName=$L;Id=3;StartTime=$S;EndTime=$E} -EA SilentlyContinue)
"COUNT=$($a.Count)"
foreach($e in $a){$p=P $e
"--- RecId=$($e.RecordId) ---"
"TimeUtc=$($e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
foreach($k in @('ProcessGuid','ProcessId','Image','DestinationIp','DestinationPort','DestinationHostname','User')){"$k=$($p.D[$k])"}
}
