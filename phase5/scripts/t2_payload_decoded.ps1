# SOC-002 PHASE 5 - CONTROLLED BENIGN TEST
# Marker: SOC002-PHASE5-ENCODED-POWERSHELL
# Purpose: harmless observable output only. No persistence, no network, no modification.
$marker = 'SOC002-PHASE5-ENCODED-POWERSHELL'
Write-Output $marker
Write-Output ('HOST=' + $env:COMPUTERNAME)
Write-Output ('USER=' + [System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
Write-Output ('START_UTC=' + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))
Start-Sleep -Seconds 3
Write-Output ('END_UTC=' + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))
Write-Output 'BENIGN_CONTROLLED_TEST_COMPLETE'
