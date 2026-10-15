$ErrorActionPreference='Continue'
"=== BEFORE: 4625 baseline on WS001 ==="
$before = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -ErrorAction SilentlyContinue
"count=$($before.Count)"
if ($before.Count) { "newestBeforeRecId=$($before[0].RecordId) newestBeforeTime=$($before[0].TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))" }
"=== Performing exactly ONE controlled failed authentication ==="
$u = 'SOC002\soc002-ph4-failauth'
$out = & cmd.exe /c "net use \\192.168.56.102\IPC$ `"BadPass!2026x`" /user:$u /persistent:no 2>&1"
"net use output: $out"
Start-Sleep -Seconds 6
"=== AFTER: new 4625 events on WS001 ==="
$after = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -ErrorAction SilentlyContinue
$baseline = if ($before.Count) { $before[0].RecordId } else { 0 }
$new = $after | Where-Object { $_.RecordId -gt $baseline }
"newCount=$($new.Count)"
foreach ($e in $new) {
  $x=[xml]$e.ToXml(); $d=@{}; foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.'#text'}
  "--- NEW 4625 ---"
  "EventRecordID = $($e.RecordId)"
  "SystemTimeUTC = $($e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
  "Computer      = $($x.Event.System.Computer)"
  "Channel       = $($x.Event.System.Channel)"
  foreach($k in @('TargetUserName','TargetDomainName','TargetUserSid','LogonType','Status','SubStatus','FailureReason','SubjectUserName','SubjectDomainName','LogonProcessName','AuthenticationPackageName','WorkstationName','IpAddress','IpPort','ProcessName','ProcessId','TransmittedServices','LmPackageName','KeyLength')){ if($d.ContainsKey($k)){ "{0,-24}= {1}" -f $k,$d[$k] } }
}
