$ErrorActionPreference='Continue'
"=== Held TCP connection WS001 -> DC1:5985 (harmless) ==="
$c = New-Object System.Net.Sockets.TcpClient
$c.Connect('192.168.56.10', 5985)
"Connected=$($c.Connected)  LocalEndpoint=$($c.Client.LocalEndPoint)  RemoteEndpoint=$($c.Client.RemoteEndPoint)"
Start-Sleep -Seconds 8
$c.Close()
Start-Sleep -Seconds 4
$e3 = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue |
      Where-Object { $_.Id -eq 3 -and $_.Message -match '192.168.56.10' -and $_.Message -match '5985' } | Select-Object -First 2
foreach ($e in $e3) {
  $x=[xml]$e.ToXml(); $d=@{}; foreach ($n in $x.Event.EventData.Data) { $d[$n.Name]=$n.'#text' }
  "--- Sysmon Event 3 ---"
  "EventRecordID       = $($e.RecordId)"
  "SystemTimeUTC       = $($e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
  foreach ($k in @('RuleName','UtcTime','ProcessGuid','ProcessId','Image','User','Protocol','Initiated','SourceIp','SourcePort','DestinationIp','DestinationPort','DestinationHostname')) { if ($d.ContainsKey($k)) { "{0,-20}= {1}" -f $k, $d[$k] } }
  ""
}
