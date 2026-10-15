$ErrorActionPreference='Continue'
"=== wecutil ss /? ==="
wecutil ss /?
"=== Backup subscription config to file ==="
$bk = 'C:\Temp\soc002_phase4_backup'
New-Item -ItemType Directory -Force -Path $bk | Out-Null
wecutil gs SOC002-WS001-Security /format:xml > "$bk\wef_subscription.pre-phase4.xml"
"Written: " + ((Get-Item "$bk\wef_subscription.pre-phase4.xml").Length) + " bytes"
Get-Content "$bk\wef_subscription.pre-phase4.xml" -Raw
