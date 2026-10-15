<#
  SOC-002 | Phase 6 | DETECTION 002
  =====================================================================
  Title      : PowerShell Process Lineage - WinRM-administered chain (CONTEXT)
  Data source: WEF collector (SOC002-DC1) - ForwardedEvents (Sysmon Event 1,
               optionally Security 4688)
  Companion  : SOC002-DET-001 v2 (encoded PowerShell) - different question.

  What this detection answers
    DET-001 asks "was an encoded PowerShell command executed?".
    DET-002 asks "HOW was this PowerShell process created, and does the chain
    match a delivery path we have OBSERVED in this environment?".

  What it fires on
    A PowerShell process whose resolved ancestry contains a WinRM host process
    (winrshost.exe / wsmprovhost.exe), i.e. the Phase 5 observed shape
        winrshost.exe -> cmd.exe -> powershell.exe
    reported as LIN-01 MATCHED when the immediate parent is cmd.exe and the
    grandparent is the WinRM host.

  What it does NOT do
    It does not treat that lineage as malicious. winrshost.exe is the
    SANCTIONED administration channel in this lab, so the lineage is delivered
    as CONTEXT for the analyst: it tells you the execution came in through the
    remote-management path, not that the execution was hostile. Severity is
    CONTEXT, and no verdict is emitted.

  Guard rails on the lineage walk
    - ParentProcessGuid is used when present (no PID ambiguity).
    - The PID fallback only accepts a candidate process-create record whose
      image name matches the ParentImage recorded by the child, because Phase 5
      evidence contains a PID that is a winrshost.exe early and a cmd.exe later
      (PID reuse).
    - A hop that cannot be resolved is reported as NOT-RESOLVED rather than
      silently truncated.
#>
[CmdletBinding()]
param(
  [string]$LogName   = 'ForwardedEvents',
  [int]$Minutes      = 1440,
  [string]$Since     = '',
  [string]$Until     = '',
  [int]$IndexMinutes = 120,
  [int]$MaxRecords   = 200,
  [string]$ImageRx   = '(?i)(powershell|pwsh)\.exe',
  [switch]$OnlyEncoded,
  [switch]$Include4688,
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

$idxRecords = Read-Soc002ProcessRecords -LogName $LogName -Start $idxStart -End $end -Include4688:$Include4688
$index      = New-Soc002ProcessIndex -Records $idxRecords
# NOTE: the window parameters are collector-local while record timestamps are
# UTC, and DateTime comparison in PowerShell ignores Kind - so both bounds are
# converted explicitly before the filter.
$startUtc   = $start.ToUniversalTime()
$endUtc     = $end.ToUniversalTime()
$window     = @($idxRecords | Where-Object { $_.TimeUtc -ge $startUtc -and $_.TimeUtc -le $endUtc -and $_.Image -match $ImageRx })
$lib        = Get-Soc002LibIdentity

$out = New-Object System.Collections.ArrayList
$null = $out.Add('=== SOC002-DET-002 :: PowerShell lineage - delivery through a WinRM host process ===')
$null = $out.Add("Library=$($lib.LibVersion) sha256=$($lib.LibSha256)")
$null = $out.Add("Log=$LogName  Window=$($start.ToString('yyyy-MM-dd HH:mm:ss')) .. $($end.ToString('yyyy-MM-dd HH:mm:ss')) (collector local)")
$null = $out.Add("IndexFrom=$($idxStart.ToString('yyyy-MM-dd HH:mm:ss'))  index records=$($idxRecords.Count)  powershell/pwsh create records in window=$($window.Count)")
$null = $out.Add("Pattern LIN-01 = winrshost.exe -> cmd.exe -> powershell.exe (OBSERVED in Phase 5, authorised management channel)")
$null = $out.Add('CONTEXT ONLY - this detection never asserts maliciousness.')
$null = $out.Add('-------------------------------------------------------------------')

$i = 0; $matched = 0; $unresolved = 0
foreach ($rec in $window) {
  if ($OnlyEncoded -and -not (Test-Soc002EncodedCommandLine -CommandLine $rec.CommandLine)) { continue }
  $lin = Resolve-Soc002Lineage -Record $rec -ProcessIndex $index
  if (-not $lin.HasWinRmHost) {
    if (-not $lin.FullChainResolved) { $unresolved++ }
    continue
  }
  $matched++
  $d = Get-Soc002Det002LineageRecord -Record $rec -Lineage $lin
  if ($i -lt $MaxRecords) { $i++; $null = $out.Add((Format-Soc002Det002 -LineageRecord $d -Index $i)) }
}
$null = $out.Add('')
$null = $out.Add('--- SOC002-DET-002 summary ------------------------------------------')
$null = $out.Add("PowerShell process-create records examined    = $($window.Count)")
$null = $out.Add("Lineages with a WinRM host in the ancestry    = $matched")
$null = $out.Add("   of which LIN-01 exact shape (winrshost->cmd->powershell) = $(@($out | Select-String 'Shape LIN-01     = MATCHED').Count)")
$null = $out.Add("PowerShell creates whose ancestry did NOT resolve = $unresolved  (context gap, reported not hidden)")
$null = $out.Add('CONTEXT, NOT ACCUSATION: a winrshost.exe-rooted lineage is expected for every remote administration call in this lab, including the SOC team''s own collection runs.')
$null = $out.Add('')
$out -join "`n"
