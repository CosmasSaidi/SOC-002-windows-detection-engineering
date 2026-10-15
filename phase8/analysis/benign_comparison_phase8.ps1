<#
  SOC-002 | PHASE 8 | BENIGN COMPARISON SUITE  (offline, read-only)
  =====================================================================
  Runs the REAL DET-003 trigger over a small, deliberately NON-EXECUTED set of
  strings, and compares it with a naive keyword rule (match 'Base64'). Nothing
  here is executed or decoded-and-run; every case is a literal string.

  Purpose: show DET-003 is more useful than a keyword rule - i.e. it does NOT
  alert on the word "Base64", it DOES alert on a reconstruction CALL, and it
  suppresses a call that only appears inside a comment.

  These are BENIGN TEST CASES, not a false-positive rate. A handful of synthetic
  strings cannot establish a rate; they can only demonstrate OBSERVED behaviour.
#>
[CmdletBinding()]
param(
  [string]$Out = "$PSScriptRoot/../evidence/t05_benign_comparison.txt",
  [string]$Phase8Lib = "$PSScriptRoot/../detections",
  [string]$Phase7Evidence = "$PSScriptRoot/../../phase7/evidence"
)
$ErrorActionPreference = 'Stop'
. (Join-Path $Phase8Lib 'lib_soc002_phase8.ps1')

# the real Phase 7 payload command body (preserved) becomes case B04
$p7body = ''
$p7file = Join-Path $Phase7Evidence 'phase7_payload_decoded.txt'
$p7cmd  = ''
$childCmd = "$PSScriptRoot/../../phase7/scripts/phase7_child_command.txt"
if (Test-Path $childCmd) { $p7cmd = 'powershell.exe -NoProfile -NonInteractive -Command "' + ((Get-Content -Raw $childCmd).Trim()) + '"' }

$plumbing = '$b=[IO.File]::ReadAllText(''C:\Windows\Temp\soc002-phase6\collect_phase6_telemetry.ps1.b64'');[IO.File]::WriteAllBytes(''C:\Windows\Temp\soc002-phase6\collect_phase6_telemetry.ps1'',[Convert]::FromBase64String($b));Remove-Item -Force ''C:\Windows\Temp\soc002-phase6\collect_phase6_telemetry.ps1.b64'''

$cases = @(
  [pscustomobject]@{ Id='B01'; Desc='plain PowerShell, no base64 at all';                       Text="Get-Process | Where-Object { `$_.Name -like 'po*' } | Select-Object -First 5" }
  [pscustomobject]@{ Id='B02'; Desc='word "Base64" in harmless commentary / help text';        Text="@'`n# Base64 is a standard encoding. This script does not decode anything.`nWrite-Output 'Base64 help text only'`n'@" }
  [pscustomobject]@{ Id='B03'; Desc='explicit FromBase64String reconstruction (decode only)';  Text="`$b='VGVzdA==';`$t=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(`$b));Write-Output `$t" }
  [pscustomobject]@{ Id='B04'; Desc='the real Phase 7 blind-spot payload command line (preserved evidence)'; Text=$p7cmd }
  [pscustomobject]@{ Id='B05'; Desc='reconstruction call that appears ONLY inside a comment';  Text="# example only: [Convert]::FromBase64String(`$b) - never run here`nWrite-Output 'no decode'" }
  [pscustomobject]@{ Id='B06'; Desc='decode followed by an execution primitive (context contrast)'; Text="`$x=[Convert]::FromBase64String(`$b);Invoke-Expression `$x" }
  [pscustomobject]@{ Id='B07'; Desc='the lab operator''s own WinRM file-transfer plumbing';    Text=$plumbing }
)

$lines = New-Object System.Collections.ArrayList
$null = $lines.Add('=== SOC-002 PHASE 8 :: DET-003 BENIGN COMPARISON SUITE ===')
$libId = Get-Soc002P8LibIdentity
$null = $lines.Add("Library         = $($libId.LibVersion) sha256=$($libId.LibSha256)")
$null = $lines.Add("Trigger         = Base64 RECONSTRUCTION CALL (REC-01..05); the literal word 'Base64' never triggers.")
$null = $lines.Add('Naive keyword   = a simple `text -match "Base64"` rule, shown only for comparison.')
$null = $lines.Add('Nothing below is executed, decoded-and-run, or sent anywhere. Every case is a literal string.')
$null = $lines.Add('These are BENIGN TEST CASES, not a measured false-positive rate.')
$null = $lines.Add('-------------------------------------------------------------------')
$null = $lines.Add('')
$null = $lines.Add('  case  keyword-rule  det003  severity  class/comment')
$null = $lines.Add('  ----  ------------  ------  --------  -------------')

$rows = New-Object System.Collections.ArrayList
foreach ($c in $cases) {
  $kw = ([string]$c.Text -match '(?i)base64')
  $s3 = Test-Soc002P8Base64Reconstruction -Text $c.Text
  $note = ''
  if ($s3.Triggered) { $note = ($s3.IndicatorIds -join ',') + '  ctx=' + (($s3.ContextIds) -join ',') }
  elseif ($s3.CommentMention) { $note = 'comment-only mention -> SUPPRESSED (recorded, not alerted)' }
  elseif ($s3.WordOnlyMention) { $note = 'word ''Base64'' present, no decode call -> NOT triggered' }
  else { $note = 'no base64 content' }
  $null = $lines.Add(("  {0}   {1,-12}  {2,-6}  {3,-8}  {4}" -f $c.Id, $(if($kw){'FIRE'}else{'clear'}), $(if($s3.Triggered){'FIRE'}else{'clear'}), $(if($s3.Triggered){$s3.Severity}else{'-'}), $note))
  $null = $rows.Add([pscustomobject]@{ Case=$c.Id; Desc=$c.Desc; KeywordFires=$kw; Det003Fires=$s3.Triggered; Severity=$(if($s3.Triggered){$s3.Severity}else{''}); Indicators=@($s3.IndicatorIds); Contexts=@($s3.ContextIds); CommentSuppressed=$s3.CommentMention; WordOnly=$s3.WordOnlyMention })
}
$null = $lines.Add('')
$null = $lines.Add('--- per-case detail -------------------------------------------------')
foreach ($c in $cases) {
  $s3 = Test-Soc002P8Base64Reconstruction -Text $c.Text
  $null = $lines.Add('')
  $null = $lines.Add(("  [{0}] {1}" -f $c.Id, $c.Desc))
  $null = $lines.Add(("       triggered   = {0}" -f $s3.Triggered))
  $null = $lines.Add(("       indicators  = {0}" -f $(if($s3.IndicatorIds.Count){$s3.IndicatorIds -join ','}else{'(none)'})))
  $null = $lines.Add(("       contexts    = {0}" -f $(if($s3.ContextIds.Count){$s3.ContextIds -join ','}else{'(none)'})))
  $null = $lines.Add(("       severity    = {0}   class = {1}" -f $(if($s3.Triggered){$s3.Severity}else{'-'}), $(if($s3.Triggered){$s3.Class}else{'-'})))
  $null = $lines.Add(("       word-only   = {0}   comment-suppressed = {1}" -f $s3.WordOnlyMention, $s3.CommentMention))
  $null = $lines.Add(("       keyword-rule would fire = {0}   DET-003 fires = {1}" -f ([string]$c.Text -match '(?i)base64'), $s3.Triggered))
}
$null = $lines.Add('')
$null = $lines.Add('--- reading ---------------------------------------------------------')
$null = $lines.Add('  * B02/B05 contain the word "Base64" but are NOT triggered by DET-003, while a')
$null = $lines.Add('    naive keyword rule WOULD fire on them. That is the precision gain.')
$null = $lines.Add('  * B04 is the exact Phase 7 blind spot: DET-003 triggers on it (REC-01).')
$null = $lines.Add('  * B06 shows the context model: an execution primitive alongside the decode')
$null = $lines.Add('    raises severity to MEDIUM. It is STILL not a verdict - the text is only read.')
$null = $lines.Add('  * B07 shows the DOCUMENTED false-positive source: the operator''s own file')
$null = $lines.Add('    transfer uses FromBase64String, so DET-003 flags it (LOW, CTX-PLUMBING).')
$null = $lines.Add('  * Sample size is a handful of synthetic cases: this demonstrates behaviour,')
$null = $lines.Add('    it does NOT establish a false-positive rate.')
$lines -join "`n" | Set-Content -LiteralPath $Out -Encoding utf8
($rows | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath ($Out -replace '\.txt$','.json') -Encoding utf8
"wrote $Out"
