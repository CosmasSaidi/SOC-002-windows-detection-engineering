$ErrorActionPreference='Continue'
"NOW=" + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
$all = Get-WinEvent -LogName ForwardedEvents -ErrorAction SilentlyContinue | Where-Object Id -eq 4625
"centralized4625Count=$($all.Count)"
$hit = $all | Where-Object { $_.Message -match 'soc002-ph4-failauth' -or ([xml]$_.ToXml()).Event.EventData.Data -match 'soc002-ph4-failauth' }
$hit = $all | Where-Object { $x=[xml]$_.ToXml(); ($x.Event.EventData.Data | Where-Object Name -eq 'TargetUserName').'#text' -eq 'soc002-ph4-failauth' }
if ($hit) {
  foreach ($e in $hit) {
    $x=[xml]$e.ToXml(); $d=@{}; foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.'#text'}
    "--- CENTRALIZED 4625 ---"
    "Provider      = $($e.ProviderName)"
    "FwdRecordId   = $($e.RecordId)"
    "SysEventRecordID_xml = $($x.Event.System.EventRecordID)"
    "SystemTimeUTC = $($e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
    "Computer      = $($x.Event.System.Computer)"
    "Channel_in_xml= $($x.Event.System.Channel)"
    foreach($k in @('TargetUserName','TargetDomainName','TargetUserSid','LogonType','Status','SubStatus','FailureReason','LogonProcessName','AuthenticationPackageName','WorkstationName','IpAddress','IpPort','SubjectUserName')){ if($d.ContainsKey($k)){ "{0,-24}= {1}" -f $k,$d[$k] } }
  }
} else { "NOT ARRIVED YET (centralized 4625 count=$($all.Count))" }
