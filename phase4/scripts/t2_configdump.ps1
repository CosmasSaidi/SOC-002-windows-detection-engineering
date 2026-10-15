$ErrorActionPreference='Continue'
"=== SysmonDrv\Parameters ==="
$p = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters'
"ConfigFile   = " + $p.ConfigFile
"ConfigHash   = " + $p.ConfigHash
"HashingAlg   = " + $p.HashingAlgorithm
"CheckRevoke  = " + $p.CheckRevocation
"DnsLookup    = " + $p.DnsLookup
"Rules length = " + ($p.Rules.Length)
"=== ACTIVE CONFIG (Sysmon64.exe -c) ==="
& 'C:\Windows\Sysmon64.exe' -c
"=== END CONFIG ==="
