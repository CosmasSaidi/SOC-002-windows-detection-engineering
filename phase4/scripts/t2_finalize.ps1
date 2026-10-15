$ErrorActionPreference='Continue'
$cfgPath = 'C:\Temp\soc002_sysmon_phase4.xml'
$xml = @'
<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <EventFiltering>
    <!-- SOC-002 Phase 4: focused collection - process creation + network connections only -->
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
"Canonical config hash: " + (Get-FileHash $cfgPath -Algorithm SHA256).Hash
& 'C:\Windows\Sysmon64.exe' -c $cfgPath 2>&1 | Out-Null
Start-Sleep -Seconds 2
(& 'C:\Windows\Sysmon64.exe' -c | Out-String) -replace "`0","" | Select-String -Pattern 'Config file|Config hash|Network connection|Image loading|CRL|DNS|ProcessCreate|NetworkConnect|filter:'
"=== cleanup intermediates ==="
Remove-Item 'C:\Temp\soc002_sysmon_phase4_v2.xml','C:\Temp\soc002_sysmon_phase4_v3.xml','C:\Temp\soc002_sysmon_phase4_v4.xml','C:\Temp\soc002_sysmon_phase4_v5.xml' -Force -ErrorAction SilentlyContinue
Get-ChildItem 'C:\Temp' | Select-Object Name, Length | Format-Table -AutoSize | Out-String
