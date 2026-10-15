$ErrorActionPreference='Continue'
"=== C:\Temp\sysmon_after_utf16.txt (previous session artifact) ==="
Get-Content 'C:\Temp\sysmon_after_utf16.txt' -Raw -ErrorAction SilentlyContinue
"=== END ==="
"=== Recent Sysmon Event 4 (config change) & 16 (service state) messages ==="
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue |
  Where-Object { $_.Id -in 4,16 } | Select-Object -First 6 |
  ForEach-Object { "--- Id=$($_.Id) RecId=$($_.RecordId) Time=$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) ---"; $_.Message; "" }
"=== Sysmon Operational log oldest/newest ==="
$all = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue
"count=$($all.Count) oldest=$($all[-1].TimeCreated) newest=$($all[0].TimeCreated)"
