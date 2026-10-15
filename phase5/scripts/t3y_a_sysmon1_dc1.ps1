$ErrorActionPreference='Continue'
$L='ForwardedEvents'
$S=Get-Date '2026-10-15 00:59:40';$E=Get-Date '2026-10-15 00:59:58'
$PFX='IwAgAFMATwBDAC0A'
function P($e){$x=[xml]$e.ToXml();$d=[ordered]@{};foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.'#text'};@{X=$x;D=$d}}
"=== A. SYSMON EVENT 1 targeted ==="
$a=@(Get-WinEvent -FilterHashtable @{LogName=$L;Id=1;StartTime=$S;EndTime=$E} -EA SilentlyContinue|?{$_.ToXml() -match $PFX})
"COUNT=$($a.Count)"
foreach($e in $a){$p=P $e
"--- RecId=$($e.RecordId) ---"
"TimeLocal=$($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss.fff'))"
"TimeUtc=$($e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
"Computer=$($p.X.Event.System.Computer)"
"Provider=$($p.X.Event.System.Provider.Name)"
foreach($k in @('UtcTime','ProcessGuid','ProcessId','Image','CommandLine','User','LogonId','ParentImage','ParentProcessId','ParentCommandLine','Hashes','IntegrityLevel','CurrentDirectory')){"$k=$($p.D[$k])"}
"===RAWXML-BEGIN Sysmon1-Rec$($e.RecordId)==="
$e.ToXml()
"===RAWXML-END==="
}
