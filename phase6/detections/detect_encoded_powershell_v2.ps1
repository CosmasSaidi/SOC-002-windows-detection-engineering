<#
  SOC-002 | Phase 6 | DETECTION 001 v2
  =====================================================================
  Title      : Encoded PowerShell Execution Observed - Investigation Required
  Supersedes : phase5/detections/detect_encoded_powershell.ps1 (preserved as-is)
  Data source: Windows Event Forwarding collector (SOC002-DC1) - ForwardedEvents

  What changed from Phase 5 (trigger unchanged, classification added)
   1. The trigger is IDENTICAL to Phase 5: Sysmon Event 1 where Image is
      powershell.exe/pwsh.exe AND the command line carries an encoded switch.
      Detection coverage is therefore not silently reduced.
   2. Candidates are CLASSIFIED instead of merely listed:
        INVESTIGATION                 retained, full alert block, severity MEDIUM
        BASELINE-TRANSPORT-CONFIRMED  INFO - narrow WinRS transport baseline met
                                      and the WinRM hop is resolved
        BASELINE-TRANSPORT-PATTERN    LOW  - same narrow pattern, but the WinRM
                                      hop is NOT resolved from telemetry
   3. The baseline is narrow (BASE-01): parent is cmd.exe running the WinRS
      wrapper "cmd.exe /C powershell -encodedcommand <b64>". There is NO
      "allow powershell.exe" rule and NO "allow -EncodedCommand" rule.
   4. The decoded payload is screened for high-risk constructs (ESC-01..08). Any
      hit overrides the baseline and re-opens the event as a candidate.
   5. Lineage enrichment resolves the parent chain from surviving process-create
      events. If it cannot be resolved, the event is only baselined at the
      weaker tier and the gap is printed.
   6. Optional -Include4688Fallback for when Sysmon Event 1 is missing. Without
      the parent command line the baseline cannot be evaluated, so those events
      stay investigation candidates (fail-open, never over-suppress).

  This detection says "investigate" or "baseline". It never says "malicious".
#>
[CmdletBinding()]
param(
  [string]$LogName   = 'ForwardedEvents',
  [int]$Minutes      = 1440,
  [string]$Since     = '',
  [string]$Until     = '',
  [int]$IndexMinutes = 120,
  [int]$MaxText      = 1200,
  [int]$MaxAlerts    = 200,
  [string]$Marker    = 'SOC002-PHASE5-ENCODED-POWERSHELL',
  [switch]$Include4688Fallback,
  [switch]$HideBaseline,
  [switch]$NoDet002,
  [switch]$NoCorrelation,
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

$assessed = Invoke-Soc002Assessment -Candidates $candidates -ProcessIndex $index
$stats = New-Soc002Stats
foreach ($a in $assessed) {
  $stats.Candidates++
  switch ($a.Verdict.Tier) {
    'BASELINE-TRANSPORT-CONFIRMED' { $stats.BaselineConfirmed++ ; $stats.BaselineRetainedForCorr++ }
    'BASELINE-TRANSPORT-PATTERN'   { $stats.BaselinePatternUnconfirmed++; $stats.BaselineRetainedForCorr++ }
    default                        { $stats.InvestigationRetained++ }
  }
  if ($a.Verdict.Rule -eq 'BASE-01 overridden') { $stats.EscalatedByPayload++ }
}
$s   = Get-Soc002StatSummary -Stats $stats
$lib = Get-Soc002LibIdentity

$lines = New-Object System.Collections.ArrayList
$null = $lines.Add('=== SOC002-DET-001 v2 :: Encoded PowerShell Execution - classified ===')
$null = $lines.Add("Library=$($lib.LibVersion) sha256=$($lib.LibSha256)")
$null = $lines.Add("Log=$LogName  Window=$($start.ToString('yyyy-MM-dd HH:mm:ss')) .. $($end.ToString('yyyy-MM-dd HH:mm:ss')) (collector local)")
$null = $lines.Add("IndexFrom=$($idxStart.ToString('yyyy-MM-dd HH:mm:ss'))  index records=$($idxRecords.Count)")
$null = $lines.Add("Baseline=BASE-01 (narrow WinRS transport wrapper)   Payload screen=ESC-01..08   Trigger=unchanged from Phase 5")
$null = $lines.Add('-------------------------------------------------------------------')

$alertNo = 0; $baseNo = 0
foreach ($a in $assessed) {
  if ($a.Verdict.Tier -eq 'INVESTIGATION') {
    if ($alertNo -ge $MaxAlerts) { continue }
    $alertNo++
    $rec = $a.Record
    if ($MaxText -gt 0) {
      foreach ($f in 'CommandLine','ParentCommandLine','DecodedText') {
        $v = [string]$rec.$f
        if ($v.Length -gt $MaxText) { $rec.$f = $v.Substring(0,$MaxText) + '...[cut]' }
      }
    }
    $corr = Get-Soc0024104Corroboration -LogName $LogName -Record $a.Record -Marker $Marker
    $null = $lines.Add((Format-Soc002Det001Alert -Record $rec -Verdict $a.Verdict -Corroboration $corr -Index $alertNo -MaxText $MaxText))
  } elseif (-not $HideBaseline) {
    $baseNo++
    $null = $lines.Add((Format-Soc002Det001Baseline -Record $a.Record -Verdict $a.Verdict -Index $baseNo))
  }
}

$null = $lines.Add('')
$null = $lines.Add('--- SOC002-DET-001 v2 summary ---------------------------------------')
$null = $lines.Add("Candidate alerts (encoded PowerShell matched)  = $($s.Candidates)")
$null = $lines.Add("Retained investigation candidates              = $($s.RetainedInvestigationCandidates)")
$null = $lines.Add("Suppressed by narrow baseline (BASE-01)        = $($s.SuppressedByNarrowBaseline)")
$null = $lines.Add("   - baseline + WinRM ancestry resolved       = $($s.BaselineConfirmedWinRMAncestry)   (INFO)")
$null = $lines.Add("   - baseline pattern, ancestry NOT resolved  = $($s.BaselinePatternLineageMissing)   (LOW)")
$null = $lines.Add("Escalated back by payload screen (ESC-*)       = $($s.EscalatedByPayloadScreen)")
$null = $lines.Add("Suppressed by a general 'powershell' rule      = 0 (no such rule exists)")
$null = $lines.Add("Suppressed by a general '-EncodedCommand' rule = 0 (no such rule exists)")
$null = $lines.Add("Security 4688 fallback                         = $(if ($Include4688Fallback) { 'ENABLED (only when Sysmon Event 1 is absent)' } else { 'disabled' })")
$null = $lines.Add('')
$lines -join "`n"

if (-not $NoDet002) {
  $d2 = @('=== SOC002-DET-002 :: PowerShell delivered through a WinRM host process (CONTEXT ONLY) ===')
  $i = 0
  foreach ($a in $assessed) { if ($a.Det002) { $i++; $d2 += (Format-Soc002Det002 -LineageRecord $a.Det002 -Index $i) } }
  $d2 += @('', "DET-002 lineage records = $i", '')
  $d2 -join "`n"
}
if (-not $NoCorrelation) {
  $c = @('=== SOC002-CORR-001 :: DET-001 x DET-002 correlation ===',
         'Purpose: one encoded-PowerShell signal + process lineage context = better investigation context.',
         'Correlation is CONTEXT, not a compromise verdict.',
         '-------------------------------------------------------------------')
  $i = 0
  foreach ($a in $assessed) { $i++; $c += (Format-Soc002Correlation -Corr $a.Corr -Index $i) }
  $c += @('', "Correlation records = $i", '')
  $c -join "`n"
}
