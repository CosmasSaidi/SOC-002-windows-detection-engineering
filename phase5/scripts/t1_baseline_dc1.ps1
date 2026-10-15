$ErrorActionPreference='Continue'
"=== SOC-002 PHASE5 TASK1 BASELINE (DC1) ==="
"HOST           = $env:COMPUTERNAME"
"TIME_LOCAL     = $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
"TIME_UTC       = $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')"
"TZ             = $((Get-TimeZone).Id)"
"=== WEF subscription runtime status (wecutil gr) ==="
wecutil gr SOC002-WS001-Security
"=== Subscription config summary (wecutil gs) ==="
wecutil gs SOC002-WS001-Security | Select-String -Pattern 'Subscription Id|Enabled|LogFile|DeliveryMode|Query'
"=== ForwardedEvents accessibility ==="
$newest = Get-WinEvent -LogName ForwardedEvents -MaxEvents 1 -ErrorAction SilentlyContinue
if ($newest) {
  "ForwardedEvents ACCESSIBLE"
  "  newest: Id=$($newest.Id) RecId=$($newest.RecordId) Time=$($newest.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) Prov=$($newest.ProviderName)"
  "  newest Computer=$((([xml]$newest.ToXml()).Event.System.Computer))"
} else { "ForwardedEvents EMPTY/INACCESSIBLE" }
"=== Windows Event Collector service ==="
Get-Service Wecsvc -ErrorAction SilentlyContinue | Format-List Name,Status,StartType
