$ErrorActionPreference='Continue'
"=== Effective time ==="
Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
"=== Generating ONE harmless network connection (curl -> DC1:5985) ==="
& C:\Windows\System32\curl.exe -s -m 8 -o NUL "http://192.168.56.10:5985/wsman"
"curl exit=$LASTEXITCODE"
Start-Sleep -Seconds 5
function Dump($e, $idname) {
  $x=[xml]$e.ToXml(); $d=@{}
  foreach ($n in $x.Event.EventData.Data) { $d[$n.Name]=$n.'#text' }
  "--- $idname ---"
  "EventID       = $($e.Id)"
  "EventRecordID = $($e.RecordId)"
  "SystemTimeUTC = $($e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
  "Computer      = $($x.Event.System.Computer)"
  "Channel       = $($x.Event.System.Channel)"
  "Provider      = $($x.Event.System.Provider.Name)"
  foreach ($k in ($d.Keys)) { if ($d[$k] -ne $null -and "$($d[$k])".Length) { "{0,-16}= {1}" -f $k, $d[$k] } }
  ""
}
"=== NEWEST Sysmon Event 1 ==="
$e1 = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue | Where-Object Id -eq 1 | Select-Object -First 1
Dump $e1 'Sysmon Event 1 (ProcessCreate)'
"=== NEWEST Sysmon Event 3 ==="
$e3 = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue | Where-Object Id -eq 3 | Select-Object -First 1
if ($e3) { Dump $e3 'Sysmon Event 3 (NetworkConnect)' } else { "NO EVENT 3 FOUND YET" }
"=== Sysmon log event-id counts now ==="
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5000 -ErrorAction SilentlyContinue |
  Group-Object Id | Sort-Object {[int]$_.Name} | Select-Object Name, Count | Format-Table -AutoSize | Out-String
