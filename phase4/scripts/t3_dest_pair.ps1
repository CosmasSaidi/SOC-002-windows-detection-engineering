$ErrorActionPreference='Continue'
"QUERY_TIME_LOCAL=" + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
$f1 = Get-WinEvent -LogName ForwardedEvents -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 1 -and $_.ProviderName -like '*Sysmon*' -and $_.Message -match 'SOC002-PHASE4-T3-WEFPROOF' } | Select-Object -First 1
$f3 = Get-WinEvent -LogName ForwardedEvents -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 3 -and $_.ProviderName -like '*Sysmon*' -and $_.Message -match 'SourcePort: 49925' } | Select-Object -First 1
"=== CENTRALIZED (DC1 ForwardedEvents) Event 1 ==="
if ($f1) { $x=[xml]$f1.ToXml(); $d=@{}; foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.'#text'}
  "FwdCollectionRecordId=$($f1.RecordId)"; "Channel=$($x.Event.System.Channel)"
  "SystemTimeUTC=$($f1.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
  "Computer=$($x.Event.System.Computer)"
  foreach($k in @('ProcessGuid','ProcessId','Image','CommandLine','User','Hashes','ParentImage','UtcTime')){ "{0}={1}" -f $k,$d[$k] } } else { "NOT FOUND YET" }
"=== CENTRALIZED (DC1 ForwardedEvents) Event 3 ==="
if ($f3) { $x=[xml]$f3.ToXml(); $d=@{}; foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.'#text'}
  "FwdCollectionRecordId=$($f3.RecordId)"; "Channel=$($x.Event.System.Channel)"
  "SystemTimeUTC=$($f3.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
  "Computer=$($x.Event.System.Computer)"
  foreach($k in @('ProcessGuid','ProcessId','Image','User','Protocol','Initiated','SourceIp','SourcePort','DestinationIp','DestinationPort','DestinationHostname','UtcTime')){ "{0}={1}" -f $k,$d[$k] } } else { "NOT FOUND YET" }
