<#
  SOC-002 | PHASE 7 | CONTROLLED BLIND-SPOT VALIDATION RUNNER  (BENIGN)
  =====================================================================
  Executed EXACTLY ONCE on SOC002-WS001 through the authorised lab
  administrator WinRM channel.

  What this runner does
   1. Starts a NEW PowerShell process NORMALLY (powershell.exe -NoProfile).
   2. The child command line does NOT contain -EncodedCommand / -enc / -e / -en.
      It uses  -Command "<script>"  with [Convert]::FromBase64String(...) inside.
   3. The base64 blob decodes to harmless PLAIN TEXT only (the phase marker plus
      a fixed purpose line). It is NEVER executed, invoked, piped or evaluated.
   4. Prints the reconstructed marker and host/user/time evidence.
   5. Exits normally.

  What this runner deliberately does NOT do
   - No persistence, no scheduled task, no registry write.
   - No configuration change, no execution-policy change.
   - No network contact of any kind.
   - No file writes (it only prints to stdout).
   - No second decode layer, no Invoke-Expression / IEX, no stager.

  The exact child process command line is emitted by the child itself and is
  captured by Sysmon Event 1, Security 4688 and PowerShell 4104.
#>
$ErrorActionPreference = 'Stop'

$marker = 'SOC002-PHASE7-BLINDSPOT-TEST'
$b64    = 'U09DMDAyLVBIQVNFNy1CTElORFNQT1QtVEVTVApTT0MwMDIgUEhBU0UgNyBDT05UUk9MTEVEIEJMSU5ELVNQT1QgVkFMSURBVElPTgpNYXJrZXI6IFNPQzAwMi1QSEFTRTctQkxJTkRTUE9ULVRFU1QKUHVycG9zZTogaGFybWxlc3MgbWFya2VyIHJlY29uc3RydWN0aW9uIG9ubHkuIE5vIHBlcnNpc3RlbmNlLCBubyBuZXR3b3JrLApubyBjb25maWd1cmF0aW9uIGNoYW5nZSwgbm8gYXJiaXRyYXJ5IGNvZGUgZXhlY3V0aW9uLgo='

# Child command template. Placeholder @@B64@@ is substituted with the blob.
# Kept in a single-quoted here-string so nothing is expanded by this runner.
$tmpl = @'
$b='@@B64@@';$t=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b));Write-Output $t;Write-Output ('HOST='+$env:COMPUTERNAME);Write-Output ('USER='+[System.Security.Principal.WindowsIdentity]::GetCurrent().Name);Write-Output ('CHILD_PID='+$PID);Write-Output ('UTC='+(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))
'@
$childCmd = (($tmpl -split "\r?\n") | Where-Object { $_.Trim() -ne '' }) -join ' '
$childCmd = $childCmd.Replace('@@B64@@', $b64)

"=== SOC-002 PHASE7 CONTROLLED BLIND-SPOT VALIDATION ==="
"MARKER           = $marker"
"RUNNER_HOST      = $env:COMPUTERNAME"
"RUNNER_ACCT      = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
"RUNNER_PID       = $PID"
"PRE_UTC          = $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
"PAYLOAD_B64_LEN  = $($b64.Length)"
"USES_ENCODED_SWITCH = $([bool]($childCmd -match '(?i)\s-(e|en|enc|encodedcommand)(\s|$)'))"
"CHILD_CMD        = $childCmd"
"--- executing (SINGLE run; -Command + FromBase64String; no -EncodedCommand) ---"
$sw = [Diagnostics.Stopwatch]::StartNew()
$out = & powershell.exe -NoProfile -NonInteractive -Command $childCmd 2>&1
$rc  = $LASTEXITCODE
$sw.Stop()
"CHILD_RC         = $rc"
"CHILD_DUR_MS     = $($sw.ElapsedMilliseconds)"
"POST_UTC         = $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
"--- child stdout ---"
$out | ForEach-Object { "$_" }
"--- end child stdout ---"
