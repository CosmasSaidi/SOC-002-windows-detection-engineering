$ErrorActionPreference='Continue'
$cfgPath = 'C:\Temp\soc002_sysmon_phase4_v5.xml'
$xml = @'
<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <EventFiltering>
    <RuleGroup name="SOC002-Phase4-ProcessCreate" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="contains">\</Image>
      </ProcessCreate>
    </RuleGroup>
    <RuleGroup name="SOC002-Phase4-NetworkConnect" groupRelation="or">
      <NetworkConnect onmatch="include">
        <DestinationPort condition="more than">0</DestinationPort>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
'@
[System.IO.File]::WriteAllText($cfgPath, $xml, (New-Object System.Text.UTF8Encoding($false)))
"=== v5 hash: " + (Get-FileHash $cfgPath -Algorithm SHA256).Hash
& 'C:\Windows\Sysmon64.exe' -c $cfgPath 2>&1 | Out-Null
Start-Sleep -Seconds 2
(& 'C:\Windows\Sysmon64.exe' -c | Out-String) -replace "`0","" | Select-String -Pattern 'Config hash|Network connection|ProcessCreate|NetworkConnect|filter:'
"=== GENERATE ==="
& cmd.exe /c "echo SOC002-PHASE4-T2-V5"
& C:\Windows\System32\curl.exe -s -m 8 -o NUL "http://192.168.56.10:5985/wsman"; "curl=$LASTEXITCODE"
Start-Sleep -Seconds 8
$since = (Get-Date).AddMinutes(-2)
"=== NEW Event 1 ==="
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 1 -and $_.TimeCreated -gt $since } | Select-Object -First 3 | ForEach-Object { $d=@{}; foreach($n in ([xml]$_.ToXml()).Event.EventData.Data){$d[$n.Name]=$n.'#text'}; "RecId=$($_.RecordId) $($_.TimeCreated.ToString('HH:mm:ss')) Image=$($d['Image'])" }
"=== NEW Event 3 ==="
$e3 = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 3 -and $_.TimeCreated -gt $since }
if ($e3) { $e3 | Select-Object -First 3 | ForEach-Object { $d=@{}; foreach($n in ([xml]$_.ToXml()).Event.EventData.Data){$d[$n.Name]=$n.'#text'}; "RecId=$($_.RecordId) $($_.TimeCreated.ToString('HH:mm:ss')) Img=$($d['Image']) Dst=$($d['DestinationIp']):$($d['DestinationPort'])" } } else { "NO EVENT 3" }
"=== counts last 3 min ==="
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-3) } | Group-Object Id | Sort-Object Name | Select-Object Name,Count | Format-Table -AutoSize | Out-String
