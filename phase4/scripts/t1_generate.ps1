$ErrorActionPreference='Continue'
$marker = "SOC002-PHASE4-T1-4688-VALIDATION"
"=== Generating harmless process ==="
& cmd.exe /c "echo $marker"
Start-Sleep -Seconds 4
"=== Fresh 4688 for marker ==="
$evts = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 40 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'SOC002-PHASE4-T1-4688-VALIDATION' }
if (-not $evts) { "NO MATCHING 4688 FOUND"; exit 0 }
foreach ($e in $evts) {
  $x=[xml]$e.ToXml(); $d=@{}
  foreach ($n in $x.Event.EventData.Data) { $d[$n.Name]=$n.'#text' }
  "--- NEW 4688 (CommandLine-bearing) ---"
  "EventID        = $($e.Id)"
  "EventRecordID  = $($e.RecordId)"
  "System TimeUTC = $($e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
  "System Local   = $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))"
  "Computer       = $($x.Event.System.Computer)"
  "Channel        = $($x.Event.System.Channel)"
  "Provider       = $($x.Event.System.Provider.Name)"
  "NewProcessId   = $($d['NewProcessId'])"
  "NewProcessName = $($d['NewProcessName'])"
  "CommandLine    = $($d['CommandLine'])"
  "ParentProcess  = $($d['ParentProcessName'])"
  "CreatorProcessId(ProcessId) = $($d['ProcessId'])"
  "SubjectUserSid = $($d['SubjectUserSid'])"
  "SubjectUser    = $($d['SubjectDomainName'])\$($d['SubjectUserName'])"
  "SubjectLogonId = $($d['SubjectLogonId'])"
  "TokenElevationType = $($d['TokenElevationType'])"
  "MandatoryLabel = $($d['MandatoryLabel'])"
  ""
}
