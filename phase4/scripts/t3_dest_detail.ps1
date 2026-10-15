$ErrorActionPreference='Continue'
function Detail($e) {
  $x=[xml]$e.ToXml(); $d=@{}
  foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.'#text'}
  "FwdCollectionRecordId = $($e.RecordId)"
  "SysEventRecordID_xml  = $($x.Event.System.EventRecordID)"
  "Provider              = $($e.ProviderName)"
  "Channel_in_xml        = $($x.Event.System.Channel)"
  "SystemTimeUTC         = $($e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
  "Computer              = $($x.Event.System.Computer)"
  "Message_is_null/empty = $([string]::IsNullOrWhiteSpace($e.Message))"
  "Message_len           = $(if($e.Message){$e.Message.Length}else{0})"
  foreach($k in ($d.Keys | Sort-Object)){ if("$($d[$k])".Length){ "{0,-22}= {1}" -f $k, $d[$k] } }
}
"########## CENTRALIZED Event 1 (FwdRecId 3423) ##########"
Detail (Get-WinEvent -LogName ForwardedEvents -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -like '*Sysmon*' -and $_.RecordId -eq 3423 })
""
"########## CENTRALIZED Event 3 (FwdRecId 3428) ##########"
Detail (Get-WinEvent -LogName ForwardedEvents -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -like '*Sysmon*' -and $_.RecordId -eq 3428 })
""
"########## raw XML of centralized Event 3 (3428), first 1400 chars ##########"
$e3 = Get-WinEvent -LogName ForwardedEvents -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -like '*Sysmon*' -and $_.RecordId -eq 3428 }
$e3.ToXml().Substring(0,[Math]::Min(1400,$e3.ToXml().Length))
