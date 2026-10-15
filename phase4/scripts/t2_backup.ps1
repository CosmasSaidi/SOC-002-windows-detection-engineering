$ErrorActionPreference='Continue'
$bk = 'C:\Temp\soc002_phase4_backup'
New-Item -ItemType Directory -Force -Path $bk | Out-Null
$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
"=== Backing up to $bk (ts=$ts) ==="
Copy-Item 'C:\Temp\soc002_sysmon_minimal.xml' -Destination "$bk\soc002_sysmon_minimal.$ts.xml" -Force
"Copied config file:"
Get-Item "$bk\soc002_sysmon_minimal.$ts.xml" | Select-Object FullName, Length, LastWriteTime | Format-List | Out-String
"=== Save running config text (-c) ==="
$enc = [System.Text.Encoding]::Unicode.GetBytes((& 'C:\Windows\Sysmon64.exe' -c | Out-String))
[System.IO.File]::WriteAllBytes("$bk\sysmon_running_config.$ts.txt", $enc)
"=== Export SysmonDrv registry key ==="
reg export "HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv" "$bk\SysmonDrv.$ts.reg" /y
"=== Export Sysmon64 registry key ==="
reg export "HKLM\SYSTEM\CurrentControlSet\Services\Sysmon64" "$bk\Sysmon64.$ts.reg" /y
"=== Backup dir listing ==="
Get-ChildItem $bk | Select-Object Name, Length | Format-Table -AutoSize | Out-String
"=== Record current ConfigHash ==="
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters').ConfigHash
