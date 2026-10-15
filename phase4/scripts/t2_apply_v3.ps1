$ErrorActionPreference='Continue'
$cfgPath = 'C:\Temp\soc002_sysmon_phase4_v3.xml'
$xml = @'
<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <EventFiltering>
    <ProcessCreate onmatch="include">
    </ProcessCreate>
    <NetworkConnect onmatch="include">
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
'@
[System.IO.File]::WriteAllText($cfgPath, $xml, (New-Object System.Text.UTF8Encoding($false)))
"=== v3 written, hash: " + (Get-FileHash $cfgPath -Algorithm SHA256).Hash
"=== APPLY ==="
& 'C:\Windows\Sysmon64.exe' -c $cfgPath 2>&1 | Out-Null
"=== EFFECTIVE (readable) ==="
$out = (& 'C:\Windows\Sysmon64.exe' -c | Out-String)
$out -replace "`0",""
Start-Sleep -Seconds 3
"=== GENERATE test process + connection ==="
& cmd.exe /c "echo SOC002-PHASE4-T2-PROCCHECK"
& C:\Windows\System32\curl.exe -s -m 8 -o NUL "http://192.168.56.10:5985/wsman"
"curl exit=$LASTEXITCODE"
Start-Sleep -Seconds 6
"=== NEW Event 1 since config apply? ==="
$applied = (Get-Date).AddMinutes(-3)
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue |
  Where-Object { $_.Id -eq 1 -and $_.TimeCreated -gt $applied } | Select-Object -First 3 |
  ForEach-Object { $d=@{}; foreach($n in ([xml]$_.ToXml()).Event.EventData.Data){$d[$n.Name]=$n.'#text'}; "RecId=$($_.RecordId) $($_.TimeCreated.ToString('HH:mm:ss')) Image=$($d['Image'])" }
"=== NEW Event 3 since config apply? ==="
$e3 = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 3 -and $_.TimeCreated -gt $applied } | Select-Object -First 3
if ($e3) { $e3 | ForEach-Object { $d=@{}; foreach($n in ([xml]$_.ToXml()).Event.EventData.Data){$d[$n.Name]=$n.'#text'}; "RecId=$($_.RecordId) $($_.TimeCreated.ToString('HH:mm:ss')) Image=$($d['Image']) DstIp=$($d['DestinationIp']):$($d['DestinationPort']) Proto=$($d['Protocol'])" } } else { "STILL NO EVENT 3" }
"=== counts last 5 min ==="
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-5) } | Group-Object Id | Sort-Object Name | Select-Object Name,Count | Format-Table -AutoSize | Out-String
