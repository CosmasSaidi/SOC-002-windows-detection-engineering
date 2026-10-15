$ErrorActionPreference='Continue'
$L='ForwardedEvents'
$S=Get-Date '2026-10-15 00:59:40';$E=Get-Date '2026-10-15 00:59:58'
$PFX='IwAgAFMATwBDAC0A'
function P($e){$x=[xml]$e.ToXml();$d=[ordered]@{};foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.'#text'};@{X=$x;D=$d}}
"=== B. SECURITY 4688 targeted ==="
$a=@(Get-WinEvent -FilterHashtable @{LogName=$L;Id=4688;StartTime=$S;EndTime=$E} -EA SilentlyContinue|?{$_.ToXml() -match $PFX})
"COUNT=$($a.Count)"
foreach($e in $a){$p=P $e
"--- RecId=$($e.RecordId) ---"
"TimeLocal=$($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss.fff'))"
"TimeUtc=$($e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
"Computer=$($p.X.Event.System.Computer)"
foreach($k in @('NewProcessId','NewProcessName','CommandLine','ParentProcessName','ProcessId','SubjectUserSid','SubjectDomainName','SubjectUserName','SubjectLogonId','TokenElevationType','MandatoryLabel')){"$k=$($p.D[$k])"}
"===RAWXML-BEGIN Security4688-Rec$($e.RecordId)==="
$e.ToXml()
"===RAWXML-END==="
}
