$ErrorActionPreference='Continue'
$marker = "SOC002-PHASE4-T3-WEFPROOF"
"MARKER=$marker"
"GEN_TIME_LOCAL=" + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
& cmd.exe /c "echo $marker" | Out-Null
$c = New-Object System.Net.Sockets.TcpClient
$c.Connect('192.168.56.10', 5985)
$sport = $c.Client.LocalEndPoint.Port
"SOURCE_PORT=$sport"
Start-Sleep -Seconds 6
$c.Close()
Start-Sleep -Seconds 4
$ev1 = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 1 -and $_.Message -match $marker } | Select-Object -First 1
$ev3 = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 3 -and $_.Message -match "SourcePort: $sport" } | Select-Object -First 1
"=== SOURCE (WS001) Event 1 ==="
if ($ev1) { $x=[xml]$ev1.ToXml(); $d=@{}; foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.'#text'}
  "SourceEventRecordID=$($ev1.RecordId)"
  "SystemTimeUTC=$($ev1.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
  "Computer=$($x.Event.System.Computer)"
  foreach($k in @('ProcessGuid','ProcessId','Image','CommandLine','User','Hashes','ParentImage')){ "{0}={1}" -f $k,$d[$k] } }
"=== SOURCE (WS001) Event 3 ==="
if ($ev3) { $x=[xml]$ev3.ToXml(); $d=@{}; foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.'#text'}
  "SourceEventRecordID=$($ev3.RecordId)"
  "SystemTimeUTC=$($ev3.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
  "Computer=$($x.Event.System.Computer)"
  foreach($k in @('ProcessGuid','ProcessId','Image','User','Protocol','Initiated','SourceIp','SourcePort','DestinationIp','DestinationPort','DestinationHostname')){ "{0}={1}" -f $k,$d[$k] } }
