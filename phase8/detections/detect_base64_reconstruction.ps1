<#
  SOC-002 | PHASE 8 | DETECTION 003
  =====================================================================
  Title      : PowerShell Base64 Reconstruction / Decode Behaviour
  Data source: Windows Event Forwarding collector (SOC002-DC1) - ForwardedEvents
               (Sysmon Event 1, Security 4688, PowerShell 4104) or any local log
  Companion  : SOC002-DET-001 v2 (encoded-command CLI switch) - DIFFERENT question.
               SOC002-DET-002   (PowerShell lineage / WinRM context) - CONTEXT only.

  This detection is SEPARATE from DET-001 v2. It does NOT read, extend or modify
  DET-001's trigger. DET-001 keys on the encoded-command CLI switch; DET-003 keys
  on a .NET Base64 reconstruction CALL that can appear with no such switch. The
  two coverage claims are therefore independently auditable.

  See lib_soc002_phase8.ps1 for the exact trigger conditions, why each indicator
  was chosen, the comment-suppression rule, the context flags and the severity
  model. The detection never executes or decodes-and-runs anything: it matches
  text and reports context only.
#>
[CmdletBinding()]
param(
  [string]$LogName   = 'ForwardedEvents',
  [int]$Minutes      = 1440,
  [string]$Since     = '',
  [string]$Until     = '',
  [int]$IndexMinutes = 120,
  [int]$MaxText      = 400,
  [int]$MaxRecords   = 200,
  [switch]$NoCorrelation,
  [switch]$NoDet002,
  [string]$LibPath   = '',
  [string]$LegacyLibPath = ''
)
$ErrorActionPreference = 'SilentlyContinue'
if (-not $LibPath)       { $LibPath = $PSScriptRoot }
if (-not $LegacyLibPath) { $LegacyLibPath = Join-Path (Split-Path $PSScriptRoot -Parent) '../phase6/detections' }
. (Join-Path $LibPath 'lib_soc002_phase8.ps1')
# Phase 6 library is used READ-ONLY for process-index / lineage / DET-002 context.
# It does not contain, and is not changed by, any Phase 8 logic.
. (Join-Path $LegacyLibPath 'lib_soc002_v2.ps1')
. (Join-Path $LegacyLibPath 'lib_soc002_windows.ps1')

$now   = Get-Date
$start = if ($Since) { Get-Date $Since } else { $now.AddMinutes(-$Minutes) }
$end   = if ($Until) { Get-Date $Until } else { $now.AddMinutes(1) }
$idxStart = $start.AddMinutes(-$IndexMinutes)
$startUtc = $start.ToUniversalTime(); $endUtc = $end.ToUniversalTime()

# ---- collect the three telemetry sources -------------------------------
$procRecords = @(Read-Soc002ProcessRecords -LogName $LogName -Start $idxStart -End $end -Include4688)
$index = New-Soc002ProcessIndex -Records $procRecords

$input_ = New-Object System.Collections.ArrayList
foreach ($r in $procRecords) {
  if (-not ([string]$r.Image -match '(?i)(powershell|pwsh)\.exe')) { continue }
  $t = [datetime]$r.TimeUtc
  if ($t -lt $startUtc -or $t -gt $endUtc) { continue }
  $rec = [ordered]@{
    Computer=$r.Computer; TimeUtc=$r.TimeUtc; Source=$r.Source; RecordId=$r.RecordId
    Pid=$r.Pid; Ppid=$r.Ppid; ProcessGuid=$r.ProcessGuid; ParentGuid=$r.ParentGuid
    Image=$r.Image; CommandLine=$r.CommandLine; ParentImage=$r.ParentImage
    ParentCommandLine=$r.ParentCommandLine; User=$r.User; LogonId=$r.LogonId; Hashes=$r.Hashes
    Text=$r.CommandLine
  }
  $null = $input_.Add([pscustomobject]$rec)
}
# PowerShell 4104 script blocks
foreach ($e in @(Get-WinEvent -FilterHashtable @{LogName=$LogName; Id=4104; StartTime=$start; EndTime=$end} -EA SilentlyContinue)) {
  $x = [xml]$e.ToXml()
  $d = @{}; foreach ($n in @($x.Event.EventData.Data)) { if ($n.Name) { $d[$n.Name] = [string]$n.'#text' } }
  $rec = [ordered]@{
    Computer=[string]$x.Event.System.Computer; TimeUtc=$e.TimeCreated.ToUniversalTime()
    Source='PowerShell-4104'; RecordId=[string]$x.Event.System.EventRecordID
    ExecPid=[string]$x.Event.System.Execution.ProcessID
    ScriptBlockId=$d['ScriptBlockId']; MessageNumber=$d['MessageNumber']; MessageTotal=$d['MessageTotal']
    CommandLine=''; Text=[string]$d['ScriptBlockText']
  }
  $null = $input_.Add([pscustomobject]$rec)
}

$assessment = Invoke-Soc002P8Assessment -Records @($input_) -ProcessIndex $index
$lib  = Get-Soc002P8LibIdentity
$lib6 = Get-Soc002LibIdentity

$lines = New-Object System.Collections.ArrayList
$null = $lines.Add('=== SOC002-DET-003 :: PowerShell Base64 reconstruction / decode behaviour ===')
$null = $lines.Add("Library        = $($lib.LibVersion) sha256=$($lib.LibSha256)")
$null = $lines.Add("Legacy library = $($lib6.LibVersion) sha256=$($lib6.LibSha256)  (read-only, for lineage/DET-002 context)")
$null = $lines.Add("Log=$LogName  Window=$($start.ToString('yyyy-MM-dd HH:mm:ss')) .. ($($end.ToString('yyyy-MM-dd HH:mm:ss'))) (collector local)")
$null = $lines.Add("IndexFrom=$($idxStart.ToString('yyyy-MM-dd HH:mm:ss'))  process records=$($procRecords.Count)")
$null = $lines.Add('Trigger = Base64 RECONSTRUCTION CALL (REC-01..05), never the literal word "Base64".')
$null = $lines.Add('CONTEXT ONLY for the analyst: reconstruction alone is NOT a verdict.')
$null = $lines.Add('-------------------------------------------------------------------')

$i = 0
foreach ($a in $assessment.Results) {
  if ($i -ge $MaxRecords) { break }
  $i++
  $null = $lines.Add((Format-Soc002P8Det003 -Det $a.Det003 -Index $i -MaxText $MaxText))
}
$st = $assessment.Stats
$null = $lines.Add('')
$null = $lines.Add('--- SOC002-DET-003 summary -----------------------------------------')
$null = $lines.Add("Telemetry records examined                    = $($st.RecordsExamined)")
$null = $lines.Add("DET-003 candidates (reconstruction call seen) = $($st.Candidates)")
$null = $lines.Add("   severity LOW  (decode only)                = $($st.Low)")
$null = $lines.Add("   severity MEDIUM (exec/retrieval adjacent)  = $($st.Medium)")
$null = $lines.Add("Non-triggers where only the WORD 'Base64' appeared = $($st.WordOnlyNonTriggers)")
$null = $lines.Add("Non-triggers suppressed as comment-only mentions   = $($st.CommentSuppressed)")
$null = $lines.Add('')

if (-not $NoCorrelation) {
  $null = $lines.Add('=== SOC002-CORR-002 :: DET-003 x process telemetry x DET-002 ===')
  $null = $lines.Add('Purpose: tie a reconstruction observation to the process, the 4688, the 4104 block and the WinRM context.')
  $null = $lines.Add('-------------------------------------------------------------------')
  $c = 0
  foreach ($a in $assessment.Results) { $c++; $null = $lines.Add((Format-Soc002P8Correlation -Corr $a.Corr -Index $c)) }
  $null = $lines.Add('')
  $null = $lines.Add("Correlation records = $c")
  $null = $lines.Add('Correlation is CONTEXT, not a compromise verdict.')
  $null = $lines.Add('')
}

if (-not $NoDet002) {
  $null = $lines.Add('=== DET-002 lineage context (from the unmodified Phase 6 detection) ===')
  $d2 = 0
  foreach ($a in $assessment.Results) {
    if (-not $a.Det002) { continue }
    $d2++; $null = $lines.Add((Format-Soc002Det002 -LineageRecord $a.Det002 -Index $d2))
  }
  $null = $lines.Add("DET-002 lineage records linked to DET-003 = $d2")
  $null = $lines.Add('')
}
$lines -join "`n"
