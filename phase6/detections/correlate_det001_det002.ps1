<#
  SOC-002 | Phase 6 | CORRELATION LAYER (SOC002-CORR-001)
  =====================================================================
  Joins SOC002-DET-001 v2 (encoded PowerShell execution) with SOC002-DET-002
  (PowerShell delivered through a WinRM host process) on host + process id.

  Purpose
    Show that one signal + its process context beats either alone:
      DET-001 alone  -> "encoded PowerShell ran; investigate"
      DET-002 alone  -> "a WinRM-host lineage existed"  (very common here)
      CORR-001       -> "this encoded command was delivered through the WinRM
                         administration path; here is the chain, the decoded
                         payload, the user and the payload screen result"

  What it is NOT
    Not a verdict and not an automatic compromise. Correlation raises or lowers
    CONFIDENCE and points at the next question to ask (was the operator
    authorised? does the payload do anything?). A correlation hit where DET-002
    is absent is reported as an EXPLANATION GAP, because an encoded execution
    with no resolvable lineage is weaker evidence, not stronger.

  Usage
    .\correlate_det001_det002.ps1 -Since '2026-10-15 00:04:46' -Until '2026-10-15 01:05:46'
#>
[CmdletBinding()]
param(
  [string]$LogName   = 'ForwardedEvents',
  [int]$Minutes      = 1440,
  [string]$Since     = '',
  [string]$Until     = '',
  [int]$IndexMinutes = 120,
  [string]$Marker    = 'SOC002-PHASE5-ENCODED-POWERSHELL',
  [switch]$Include4688Fallback,
  [switch]$SummaryOnly,
  [string]$LibPath   = ''
)
$ErrorActionPreference = 'SilentlyContinue'
if (-not $LibPath) { $LibPath = $PSScriptRoot }
. (Join-Path $LibPath 'lib_soc002_v2.ps1')
. (Join-Path $LibPath 'lib_soc002_windows.ps1')

$now   = Get-Date
$start = if ($Since) { Get-Date $Since } else { $now.AddMinutes(-$Minutes) }
$end   = if ($Until) { Get-Date $Until } else { $now.AddMinutes(1) }
$idxStart = $start.AddMinutes(-$IndexMinutes)

$idxRecords = Read-Soc002ProcessRecords -LogName $LogName -Start $idxStart -End $end -Include4688:$Include4688Fallback
$index      = New-Soc002ProcessIndex -Records $idxRecords
$candidates = Get-Soc002EncodedCandidates -LogName $LogName -Start $start -End $end -Include4688Fallback:$Include4688Fallback
$assessed   = Invoke-Soc002Assessment -Candidates $candidates -ProcessIndex $index
$lib        = Get-Soc002LibIdentity

$d1 = 0; $d2 = 0; $joined = 0; $gap = 0; $esc = 0
$body = New-Object System.Collections.ArrayList
$i = 0
foreach ($a in $assessed) {
  $d1++
  if ($a.Det002) { $d2++ } else { $gap++ }
  if (@($a.Escalations).Count -gt 0) { $esc++ }
  if ($a.Corr.Det002Present) { $joined++ }
  $i++
  if (-not $SummaryOnly) { $null = $body.Add((Format-Soc002Correlation -Corr $a.Corr -Index $i)) }
}

$out = New-Object System.Collections.ArrayList
$null = $out.Add('=== SOC002-CORR-001 :: DET-001 x DET-002 correlation ===')
$null = $out.Add("Library=$($lib.LibVersion) sha256=$($lib.LibSha256)")
$null = $out.Add("Log=$LogName  Window=$($start.ToString('yyyy-MM-dd HH:mm:ss')) .. $($end.ToString('yyyy-MM-dd HH:mm:ss')) (collector local)")
$null = $out.Add('Purpose: one encoded-PowerShell signal + process lineage context = better investigation context.')
$null = $out.Add('Correlation is CONTEXT, not a compromise verdict.')
$null = $out.Add('-------------------------------------------------------------------')
$null = $out.AddRange($body)
$null = $out.Add('')
$null = $out.Add('--- SOC002-CORR-001 summary -----------------------------------------')
$null = $out.Add("DET-001 signals in window                     = $d1")
$null = $out.Add("DET-001 signals with a DET-002 lineage record = $joined")
$null = $out.Add("DET-001 signals with NO lineage (explanation gap) = $gap")
$null = $out.Add("DET-001 signals escalated by the payload screen   = $esc")
$null = $out.Add("Correlation records produced                  = $i")
$null = $out.Add('No correlation record here is a verdict: the analyst still has to check authorisation and payload intent.')
$null = $out.Add('')
$out -join "`n"
