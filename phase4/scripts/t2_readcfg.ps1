$ErrorActionPreference='Continue'
"=== CONFIG FILE EXISTS? ==="
Test-Path 'C:\Temp\soc002_sysmon_minimal.xml'
"=== FILE INFO ==="
Get-Item 'C:\Temp\soc002_sysmon_minimal.xml' | Select-Object FullName, Length, LastWriteTime, CreationTime | Format-List | Out-String
"=== FILE HASH (SHA256) ==="
(Get-FileHash 'C:\Temp\soc002_sysmon_minimal.xml' -Algorithm SHA256).Hash
"=== FILE CONTENT ==="
Get-Content 'C:\Temp\soc002_sysmon_minimal.xml' -Raw
"=== END FILE ==="
"=== Rules registry blob hex (first 200 bytes) ==="
$p = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters'
($p.Rules | ForEach-Object { $_.ToString('X2') }) -join '' | ForEach-Object { $_.Substring(0, [Math]::Min(400,$_.Length)) }
"=== C:\Temp listing ==="
Get-ChildItem 'C:\Temp' -Force -ErrorAction SilentlyContinue | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize | Out-String
