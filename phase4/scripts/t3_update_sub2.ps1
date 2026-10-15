$ErrorActionPreference='Continue'
$cfg = 'C:\Temp\wef_subscription.phase4.xml'
"=== wecutil ss /c:$cfg ==="
wecutil ss /c:$cfg 2>&1 | Out-String
"ExitCode=$LASTEXITCODE"
Start-Sleep -Seconds 8
"=== VERIFY wecutil gs (query) ==="
wecutil gs SOC002-WS001-Security | Select-String -Pattern 'Description|Query|Enabled|DeliveryMode'
"=== VERIFY wecutil gr ==="
wecutil gr SOC002-WS001-Security
"=== EventCollector/Operational last 5 ==="
Get-WinEvent -LogName 'Microsoft-Windows-EventCollector/Operational' -MaxEvents 5 -ErrorAction SilentlyContinue | ForEach-Object { "Id=$($_.Id) $($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) :: $($_.Message -replace "`r`n"," | ")" }
