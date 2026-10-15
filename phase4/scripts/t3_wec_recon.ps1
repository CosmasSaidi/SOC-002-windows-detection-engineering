$ErrorActionPreference='Continue'
"=== wecutil gs SOC002-WS001-Security ==="
wecutil gs SOC002-WS001-Security
"=== wecutil gr (runtime status) ==="
wecutil gr SOC002-WS001-Security
"=== wecutil gs /format:xml ==="
wecutil gs SOC002-WS001-Security /format:xml
"=== WEC service ==="
Get-Service Wecsvc | Select-Object Name,Status,StartType | Format-List | Out-String
"=== ForwardedEvents log info ==="
$l = Get-WinEvent -ListLog ForwardedEvents
"IsEnabled=$($l.IsEnabled) LogMode=$($l.LogMode) MaxKB=$([math]::Round($l.MaximumSizeInBytes/1KB)) RecordCount=$($l.RecordCount)"
"=== EventCollector/Operational recent ==="
Get-WinEvent -LogName 'Microsoft-Windows-EventCollector/Operational' -MaxEvents 8 -ErrorAction SilentlyContinue | ForEach-Object { "Id=$($_.Id) $($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) :: $($_.Message -replace "`r`n"," | ")" }
