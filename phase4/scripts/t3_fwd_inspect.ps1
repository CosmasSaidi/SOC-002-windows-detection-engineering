$ErrorActionPreference='Continue'
"=== ForwardedEvents: provider/ID summary ==="
Get-WinEvent -LogName ForwardedEvents -MaxEvents 400 -ErrorAction SilentlyContinue |
  Group-Object ProviderName,Id | Sort-Object Count -Descending | Select-Object -First 15 Name,Count | Format-Table -AutoSize | Out-String
"=== Sample centralized 4688 (raw XML) ==="
$e = Get-WinEvent -LogName ForwardedEvents -ErrorAction SilentlyContinue | Where-Object Id -eq 4688 | Select-Object -First 1
if ($e) {
  "ProviderName=$($e.ProviderName)  RecordId=$($e.RecordId)  TimeCreated=$($e.TimeCreated)"
  $x=[xml]$e.ToXml()
  "--- System.Computer = " + $x.Event.System.Computer
  "--- EventData field names present ---"
  ($x.Event.EventData.Data | ForEach-Object { $_.Name }) -join ', '
  "--- CommandLine value ---"
  ($x.Event.EventData.Data | Where-Object Name -eq 'CommandLine').'#text'
  "--- UserData? ---"
  if ($x.Event.UserData) { $x.Event.UserData.OuterXml.Substring(0, [Math]::Min(600, $x.Event.UserData.OuterXml.Length)) } else { "none" }
  "--- first 1200 chars of raw XML ---"
  $e.ToXml().Substring(0, [Math]::Min(1200, $e.ToXml().Length))
} else { "no 4688 in ForwardedEvents" }
