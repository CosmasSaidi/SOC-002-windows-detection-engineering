$ErrorActionPreference='Continue'
function Dump($e) {
  $x=[xml]$e.ToXml(); $d=@{}
  foreach ($n in $x.Event.EventData.Data) { $d[$n.Name]=$n.'#text' }
  "EventID       = $($e.Id)"
  "EventRecordID = $($e.RecordId)"
  "SystemTimeUTC = $($e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
  "Computer      = $($x.Event.System.Computer)"
  "Channel       = $($x.Event.System.Channel)"
  "Provider      = $($x.Event.System.Provider.Name)"
  foreach ($k in @('RuleName','UtcTime','ProcessGuid','ProcessId','Image','CommandLine','CurrentDirectory','User','LogonId','IntegrityLevel','Hashes','ParentImage','ParentCommandLine','ParentProcessGuid','Protocol','Initiated','SourceIsIpv6','SourceIp','SourceHostname','SourcePort','DestinationIsIpv6','DestinationIp','DestinationHostname','DestinationPort','DestinationPortName')) {
    if ($d.ContainsKey($k) -and "$($d[$k])".Length) { "{0,-20}= {1}" -f $k, $d[$k] }
  }
  ""
}
"=== MARKER $(Get-Date -Format o) ==="
& cmd.exe /c "echo SOC002-PHASE4-T2-EVIDENCE"
& C:\Windows\System32\curl.exe -s -m 8 -o NUL "http://192.168.56.10:5985/wsman"; "curl=$LASTEXITCODE"
Start-Sleep -Seconds 7
"=== Event 1 (ProcessCreate) - marker process ==="
$e1 = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 1 -and $_.Message -match 'SOC002-PHASE4-T2-EVIDENCE' } | Select-Object -First 1
if ($e1) { Dump $e1 } else { "no matching Event 1" }
"=== Event 3 (NetworkConnect) - curl to DC1:5985 ==="
$e3 = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 3 -and $_.Message -match '192.168.56.10' -and $_.Message -match '5985' } | Select-Object -First 1
if ($e3) { Dump $e3 } else { "no matching Event 3" }
