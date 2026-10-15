$ErrorActionPreference='Continue'
"########## WS001 ##########"
"NOW=" + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')
"--- 4688 CommandLine setting ---"
"ProcessCreationIncludeCmdLine_Enabled = " + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit').ProcessCreationIncludeCmdLine_Enabled
$s = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 1 -ErrorAction SilentlyContinue
"newest4688 RecId=$($s.RecordId) Time=$($s.TimeCreated.ToString('HH:mm:ss')) HasCmdLine=$((([xml]$s.ToXml()).Event.EventData.Data | Where-Object Name -eq 'CommandLine').'#text'.Length -gt 0)"
"--- Sysmon ---"
Get-Service Sysmon64,SysmonDrv | Select-Object Name,Status | Format-Table -AutoSize | Out-String
"SysmonConfigFile = " + (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters').ConfigFile
"SysmonConfigHash = " + (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters').ConfigHash
$sy = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue
"sysmonLogCount=$($sy.Count)"
"newestEvent1 = " + (($sy | Where-Object Id -eq 1 | Select-Object -First 1).TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))
"newestEvent3 = " + (($sy | Where-Object Id -eq 3 | Select-Object -First 1).TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))
"--- Log retention ---"
$sec = Get-WinEvent -ListLog Security; "Security: mode=$($sec.LogMode) maxKB=$([math]::Round($sec.MaximumSizeInBytes/1KB)) count=$($sec.RecordCount)"
$syl = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational'; "Sysmon: mode=$($syl.LogMode) maxKB=$([math]::Round($syl.MaximumSizeInBytes/1KB)) count=$($syl.RecordCount)"
