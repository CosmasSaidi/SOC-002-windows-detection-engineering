$ErrorActionPreference='Continue'
$cfgPath = 'C:\Temp\soc002_sysmon_phase4_v2.xml'
$xml = @'
<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <EventFiltering>
    <RuleGroup name="SOC002-Phase4-Minimal" groupRelation="or">
      <ProcessCreate onmatch="include">
      </ProcessCreate>
      <NetworkConnect onmatch="include">
        <DestinationPort name="SOC002-AllDestinationPorts" condition="is">1-65535</DestinationPort>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
'@
[System.IO.File]::WriteAllText($cfgPath, $xml, (New-Object System.Text.UTF8Encoding($false)))
"=== New config file written ==="
Get-Item $cfgPath | Select-Object FullName, Length, LastWriteTime | Format-List | Out-String
(Get-FileHash $cfgPath -Algorithm SHA256).Hash
"=== APPLYING config ==="
& 'C:\Windows\Sysmon64.exe' -c $cfgPath 2>&1 | Out-String
"ExitCode=$LASTEXITCODE"
Start-Sleep -Seconds 3
"=== EFFECTIVE CONFIG AFTER APPLY ==="
$bytes = [System.Text.Encoding]::Unicode.GetBytes((& 'C:\Windows\Sysmon64.exe' -c | Out-String))
[System.Text.Encoding]::Unicode.GetString($bytes) -replace "`0",""
