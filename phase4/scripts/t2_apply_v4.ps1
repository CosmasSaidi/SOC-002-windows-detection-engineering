$ErrorActionPreference='Continue'
$cfgPath = 'C:\Temp\soc002_sysmon_phase4_v4.xml'
$xml = @'
<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <Image condition="is">*</Image>
    </ProcessCreate>
    <NetworkConnect onmatch="include">
      <DestinationPort condition="is">1-65535</DestinationPort>
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
'@
[System.IO.File]::WriteAllText($cfgPath, $xml, (New-Object System.Text.UTF8Encoding($false)))
"=== v4 hash: " + (Get-FileHash $cfgPath -Algorithm SHA256).Hash
"=== APPLY v4 ==="
& 'C:\Windows\Sysmon64.exe' -c $cfgPath 2>&1 | Out-Null
Start-Sleep -Seconds 2
$out = (& 'C:\Windows\Sysmon64.exe' -c | Out-String) -replace "`0",""
$out
"=== RESTART Sysmon64 ==="
Restart-Service Sysmon64 -Force
Start-Sleep -Seconds 5
Get-Service Sysmon64,SysmonDrv | Select-Object Name,Status | Format-Table -AutoSize | Out-String
"=== config after restart ==="
(& 'C:\Windows\Sysmon64.exe' -c | Out-String) -replace "`0","" | Select-String -Pattern 'Config file|Config hash|Network connection|ProcessCreate|NetworkConnect|Image  |DestinationPort' 
"=== GENERATE ==="
& cmd.exe /c "echo SOC002-PHASE4-T2-V4"
& C:\Windows\System32\curl.exe -s -m 8 -o NUL "http://192.168.56.10:5985/wsman"; "curl=$LASTEXITCODE"
Start-Sleep -Seconds 8
$applied = (Get-Date).AddMinutes(-4)
"=== NEW Event 1 ==="
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 1 -and $_.TimeCreated -gt $applied } | Select-Object -First 3 | ForEach-Object { $d=@{}; foreach($n in ([xml]$_.ToXml()).Event.EventData.Data){$d[$n.Name]=$n.'#text'}; "RecId=$($_.RecordId) $($_.TimeCreated.ToString('HH:mm:ss')) Image=$($d['Image']) CL=$($d['CommandLine'])" }
"=== NEW Event 3 ==="
$e3 = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 3 -and $_.TimeCreated -gt $applied }
if ($e3) { $e3 | Select-Object -First 3 | ForEach-Object { $d=@{}; foreach($n in ([xml]$_.ToXml()).Event.EventData.Data){$d[$n.Name]=$n.'#text'}; "RecId=$($_.RecordId) $($_.TimeCreated.ToString('HH:mm:ss')) Img=$($d['Image']) Dst=$($d['DestinationIp']):$($d['DestinationPort']) Proto=$($d['Protocol'])" } } else { "NO EVENT 3" }
"=== counts last 6 min ==="
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-6) } | Group-Object Id | Sort-Object Name | Select-Object Name,Count | Format-Table -AutoSize | Out-String
