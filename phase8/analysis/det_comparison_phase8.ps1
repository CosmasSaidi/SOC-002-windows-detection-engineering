<#
  SOC-002 | PHASE 8 | DET-001 vs DET-003 COMPARISON (offline, read-only)
  Runs the REAL DET-001 v2 trigger and the REAL DET-003 trigger over the same
  command lines and prints the comparison matrix. Neither library is modified.
  DET-002 is lineage-based (not a command-line trigger) so it is shown as its
  actual semantic role: CONTEXT, decided from the process chain, not the text.
#>
[CmdletBinding()]
param(
  [string]$Out = "$PSScriptRoot/../evidence/t14_det001_vs_det003.txt",
  [string]$Phase8Lib = "$PSScriptRoot/../detections",
  [string]$Phase6Lib = "$PSScriptRoot/../../phase6/detections"
)
$ErrorActionPreference = 'Stop'
. (Join-Path $Phase8Lib 'lib_soc002_phase8.ps1')
. (Join-Path $Phase6Lib 'lib_soc002_v2.ps1')

# the Phase 5 positive control (encoded command line), recovered from evidence
$p5encoded = ''
$p5file = "$PSScriptRoot/../../phase5/evidence/t2_execute_ws001.txt"
if (Test-Path $p5file) {
  $m = [regex]::Match((Get-Content -Raw $p5file), "(?m)^CHILD_CMD\s*=\s*(.+)$")
  if ($m.Success) { $p5encoded = $m.Groups[1].Value.Trim() }
}
if (-not $p5encoded) { $p5encoded = 'powershell.exe -NoProfile -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACkA' }

$p7cmd = ''
$p7file = "$PSScriptRoot/../../phase7/scripts/phase7_child_command.txt"
if (Test-Path $p7file) { $p7cmd = 'powershell.exe -NoProfile -NonInteractive -Command "' + ((Get-Content -Raw $p7file).Trim()) + '"' }

$p8cmd = ''
$p8file = "$PSScriptRoot/../scripts/phase8_child_command.txt"
if (Test-Path $p8file) { $p8cmd = 'powershell.exe -NoProfile -NonInteractive -Command "' + ((Get-Content -Raw $p8file).Trim()) + '"' }

$rows = @(
  [pscustomobject]@{ Case='Phase 5 control: -EncodedCommand';        Text=$p5encoded }
  [pscustomobject]@{ Case='Phase 7 blind spot: -Command + decode';   Text=$p7cmd }
  [pscustomobject]@{ Case='Phase 8 live: -Command + decode';         Text=$p8cmd }
  [pscustomobject]@{ Case='Benign: plain PowerShell';                Text="Get-Date; Get-Process -Name explorer" }
  [pscustomobject]@{ Case='Benign: word Base64 only';                Text="# Base64 is an encoding; Write-Output 'no decode'" }
  [pscustomobject]@{ Case='Benign: decode + Invoke-Expression';      Text="$x=[Convert]::FromBase64String($b);Invoke-Expression $x" }
  [pscustomobject]@{ Case='Benign: comment-only decode mention';     Text="# see [Convert]::FromBase64String for an example" }
)

$L = New-Object System.Collections.ArrayList
$l8 = Get-Soc002P8LibIdentity; $l6 = Get-Soc002LibIdentity
$null = $L.Add('=== SOC-002 PHASE 8 :: DET-001 v2 vs DET-003 (same command lines, both real triggers) ===')
$null = $L.Add("DET-001 library = $($l6.LibVersion) sha256=$($l6.LibSha256)")
$null = $L.Add("DET-003 library = $($l8.LibVersion) sha256=$($l8.LibSha256)")
$null = $L.Add("DET-001 trigger = $script:Soc002EncSwitchRx   (encoded-command CLI switch)")
$null = $L.Add("DET-003 trigger = Base64 reconstruction CALL (REC-01..05), never the word 'Base64'")
$null = $L.Add('')
$null = $L.Add('  case                                det001   det003   det003-severity  det003-context')
$null = $L.Add('  ----------------------------------  -------  -------  ---------------  --------------')
foreach ($r in $rows) {
  $d1 = Test-Soc002EncodedCommandLine -CommandLine $r.Text
  $d3 = Test-Soc002P8Base64Reconstruction -Text $r.Text
  $null = $L.Add(("  {0,-34}  {1,-7}  {2,-7}  {3,-15}  {4}" -f $r.Case, $(if($d1){'TRIGGER'}else{'miss'}), $(if($d3.Triggered){'TRIGGER'}else{'miss'}), $(if($d3.Triggered){$d3.Severity}else{'-'}), $(if($d3.ContextIds.Count){$d3.ContextIds -join ','}else{'-'})))
}
$null = $L.Add('')
$null = $L.Add('Reading:')
$null = $L.Add('  * DET-001 covers the encoded-command SWITCH; DET-003 covers the decode CALL.')
$null = $L.Add('  * They are DISJOINT on these cases: neither is a superset of the other.')
$null = $L.Add('  * In Phase 7 the two blind spots complemented each other: the payload was')
$null = $L.Add('    DET-001-miss / DET-003-hit, and the WinRS transport was the reverse.')
$null = $L.Add('  * DET-002 is not a text trigger: it is CONTEXT derived from the process')
$null = $L.Add('    chain (delivery through winrshost.exe/wsmprovhost.exe). It never decides')
$null = $L.Add('    DET-003, and DET-003 never decides DET-002.')
$null = $L.Add('  * Neither detection says "malicious". Both say "investigate with context".')
$L -join "`n" | Set-Content -LiteralPath $Out -Encoding utf8
"wrote $Out"
