$ErrorActionPreference='Continue'
$L='Microsoft-Windows-PowerShell/Operational'
$S=Get-Date '2026-10-15 00:58:00';$E=Get-Date '2026-10-15 01:08:00'
$M='SOC002-PHASE5-ENCODED-POWERSHELL'
function P($e){$x=[xml]$e.ToXml();$d=[ordered]@{};foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.'#text'};@{X=$x;D=$d}}
"=== POWERSHELL 4104 (marker) ==="
$a=@(Get-WinEvent -FilterHashtable @{LogName=$L;Id=4104;StartTime=$S;EndTime=$E} -EA SilentlyContinue|?{$_.Message -match [regex]::Escape($M)})
"COUNT=$($a.Count)"
foreach($e in $a){$p=P $e
"--- RecId=$($e.RecordId) ---"
"TimeLocal=$($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss.fff'))"
"TimeUtc=$($e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
"Computer=$($p.X.Event.System.Computer)"
"ExecProcessId=$($p.X.Event.System.ExecutionProcessID)"
foreach($k in @('MessageNumber','MessageTotal','ScriptBlockId','Path','ScriptBlockText')){"$k=<<<$($p.D[$k])>>>"}
"===RAWXML-BEGIN PowerShell4104-Rec$($e.RecordId)==="
$e.ToXml()
"===RAWXML-END==="
}
