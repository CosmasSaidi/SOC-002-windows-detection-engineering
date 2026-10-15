$ErrorActionPreference='Continue'
"=== now ==="
Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
"=== last 6 EventID 1 (ProcessCreate) ==="
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue | Where-Object Id -eq 1 | Select-Object -First 6 | ForEach-Object { "RecId=$($_.RecordId)  $($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))  $((( [xml]$_.ToXml()).Event.EventData.Data | Where-Object Name -eq 'Image').'#text')" }
"=== first 6 EventID 5 after 2026-10-15 00:00 local ==="
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 5 -and $_.TimeCreated -gt (Get-Date '2026-10-15 00:00') } | Select-Object -First 6 | ForEach-Object { "RecId=$($_.RecordId)  $($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))" }
"=== counts by ID in LAST 15 MINUTES ==="
$since = (Get-Date).AddMinutes(-15)
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt $since } | Group-Object Id | Sort-Object Name | Select-Object Name,Count | Format-Table -AutoSize | Out-String
"=== last 5 records overall ==="
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5 -ErrorAction SilentlyContinue | ForEach-Object { "RecId=$($_.RecordId) Id=$($_.Id) $($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))" }
"=== Driver / service process ==="
Get-CimInstance Win32_Service -Filter "Name='Sysmon64'" | Select-Object State, ProcessId | Format-List | Out-String
Get-Service SysmonDrv,Sysmon64 | Select-Object Name,Status | Format-Table -AutoSize | Out-String
