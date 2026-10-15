$ErrorActionPreference='Continue'
"=== SERVICES ==="
Get-CimInstance Win32_Service -Filter "Name='Sysmon64' or Name='Sysmon' or Name='SysmonDrv'" |
  Select-Object Name, DisplayName, State, StartMode, ProcessId, PathName | Format-List | Out-String
"=== SERVICE REG KEYS ==="
foreach ($s in 'Sysmon64','Sysmon','SysmonDrv') {
  $k = "HKLM:\SYSTEM\CurrentControlSet\Services\$s"
  if (Test-Path $k) {
    "--- $k ---"
    (Get-ItemProperty $k | Select-Object ImagePath, Start, Type, Description, DisplayName | Format-List | Out-String)
    "  SubKeys: " + ((Get-ChildItem $k -ErrorAction SilentlyContinue).PSChildName -join ', ')
    if (Test-Path "$k\Parameters") { "  Parameters values: " + ((Get-ItemProperty "$k\Parameters").PSObject.Properties.Name -join ', ') }
  } else { "MISSING: $k" }
}
"=== BINARY SEARCH ==="
foreach ($p in 'C:\Windows\Sysmon64.exe','C:\Windows\Sysmon.exe','C:\Sysmon\Sysmon64.exe','C:\Tools\Sysmon64.exe','C:\ProgramData\Sysmon\Sysmon64.exe') { if (Test-Path $p) { "$p EXISTS  ver=" + (Get-Item $p).VersionInfo.FileVersion } }
Get-ChildItem -Path C:\ -Filter 'Sysmon*.exe' -Recurse -ErrorAction SilentlyContinue -Force | Select-Object -First 10 FullName, Length | Format-Table -AutoSize | Out-String
"=== CONFIG FILE SEARCH ==="
Get-ChildItem -Path 'C:\','C:\ProgramData','C:\Windows\Temp','C:\Tools' -Include 'sysmon*.xml','*sysmon*config*' -Recurse -ErrorAction SilentlyContinue -Force | Select-Object -First 20 FullName, Length, LastWriteTime | Format-Table -AutoSize | Out-String
"=== SYSmon LOG ==="
$l = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue
"IsEnabled=$($l.IsEnabled)  LogMode=$($l.LogMode)  MaxKB=$([math]::Round($l.MaximumSizeInBytes/1KB))  RecordCount=$($l.RecordCount)  FileKB=$([math]::Round($l.FileSizeInBytes/1KB))"
"=== Sysmon event ID counts (last 20000) ==="
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 20000 -ErrorAction SilentlyContinue |
  Group-Object Id | Sort-Object Count -Descending | Select-Object Name, Count | Format-Table -AutoSize | Out-String
