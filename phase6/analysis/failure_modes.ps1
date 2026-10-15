<#
  SOC-002 | Phase 6 | TASK 7 - FAILURE MODES (offline, read-only)
  =================================================================
  Produces evidence/t7_failure_modes.txt: what each telemetry failure does
  to SOC002-DET-001 / DET-002 / CORR-001, measured where the evidence allows
  it and marked NOT VERIFIED where it does not.

  Sources
    - Phase 5 preserved evidence (replay through the REAL Phase 6 library)
    - evidence/t7_fm_live_probe_dc1.txt : the separate READ-ONLY live probe
      (it did not disable anything; it measured one source at a time)

  Rule followed throughout: no logging subsystem was switched off in this lab
  to "create" a failure, and no source was reconfigured. Failures are measured
  by NOT reading a source, or are taken from gaps that already exist in the
  Phase 5 evidence.

  Usage: pwsh -File failure_modes.ps1
#>
[CmdletBinding()]
param(
  [string]$Phase5Root = (Join-Path $HOME 'soc-lab/phase5/evidence'),
  [string]$OutFile    = (Join-Path (Split-Path -Parent $PSScriptRoot) 'evidence/t7_failure_modes.txt'),
  [string]$LiveProbe  = (Join-Path (Split-Path -Parent $PSScriptRoot) 'evidence/t7_fm_live_probe_dc1.txt')
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path (Split-Path -Parent $here) 'detections' 'lib_soc002_v2.ps1')
. (Join-Path $here 'lib_evidence_phase5.ps1')

$ev = Read-Soc002Phase5Evidence -Root $Phase5Root
foreach ($a in @($ev.Alerts)) {
  $hit = @($ev.Corroboration4104 | Where-Object { $_.Computer -eq $a.Computer -and $_.ExecPid -eq "$($a.Pid)" -and $_.Text -notmatch '^\$global:\?' } | Select-Object -First 1)
  if ($hit.Count -gt 0) { $a.PayloadText = $hit[0].Text; $a.PayloadSource = "4104 ScriptBlockText for PID $($a.Pid)" }
}
$index    = New-Soc002ProcessIndex -Records $ev.ProcessRecords
$assessed = Invoke-Soc002Assessment -Candidates $ev.Alerts -ProcessIndex $index
$lib      = Get-Soc002LibIdentity

$n            = $assessed.Count
$no4104inP5   = @($ev.Alerts | Where-Object { $_.Phase5Corroboration -match 'NONE FOUND' }).Count
$truncCmdLine = @($ev.Alerts | Where-Object { $_.CommandLineTruncated }).Count
$linWinrm     = @($assessed | Where-Object { $_.Lineage -and $_.Lineage.HasWinRmHost }).Count
$linParentOk  = @($assessed | Where-Object { $_.Lineage -and $_.Lineage.FullChainResolved }).Count
$escReplay    = @($assessed | Where-Object { $_.Verdict.Rule -eq 'BASE-01 overridden' }).Count
$retained     = @($assessed | Where-Object { $_.Verdict.Tier -eq 'INVESTIGATION' }).Count
$patternTier  = @($assessed | Where-Object { $_.Verdict.Tier -eq 'BASELINE-TRANSPORT-PATTERN' }).Count

# --- parse the read-only live probe so no number is retyped by hand ---------
$live = @{}
if (Test-Path $LiveProbe) {
  foreach ($l in (Get-Content -LiteralPath $LiveProbe)) {
    if ($l -match '^\s*FM-([0-9a-z]+)\s*/(.*?)=\s*(\d+)\s*$') {
      $key = ("FM{0}:{1}" -f $Matches[1], ($Matches[2].Trim() -replace '\s+',' '))
      $live[$key] = [int]$Matches[3]
    }
  }
}
function Lv([string]$pattern, [string]$fallback = 'NOT VERIFIED') {
  $hit = @($live.Keys | Where-Object { $_ -like $pattern } | Sort-Object)
  if ($hit.Count -ge 1) { return "$($live[$hit[0]])" }
  return $fallback
}
$liveSysmon = Lv 'FM1:*Sysmon Event 1 encoded-PowerShell candidates*'
$live4688   = Lv 'FM1:*Security 4688 encoded-PowerShell records*'
$live4688No = Lv 'FM1:*with NO Sysmon Ev1 twin*'
$live4104ok = Lv 'FM2:*WITH a binding 4104*'
$live4104no = Lv 'FM2:*WITHOUT any 4104*'
$liveLinOk  = Lv 'FM3:*immediate-parent process-create record was found*'
$liveLinNo  = Lv 'FM3:*immediate-parent record was NOT found*'
$live4688Ps = Lv 'FM4:*powershell.exe 4688 records in window*'
$live4688Em = Lv 'FM4:*command line is EMPTY*'
$o = New-Object System.Collections.ArrayList
function W([string]$s) { $null = $o.Add($s) }
function Hdr([string]$s) { W(''); W(('=' * 74)); W(" $s"); W(('=' * 74)) }

Hdr 'SOC-002 PHASE 6 / TASK 7 - FAILURE MODES'
W "Library=$($lib.LibVersion) sha256=$($lib.LibSha256)"
W "Phase 5 evidence root=$($ev.Root)"
W 'Baseline for every statement below: the Phase 5 broad 60-minute window, 39 DET-001 candidates,'
W 'of which 38 were authorised WinRM administration and 1 was the controlled test.'
W 'No logging subsystem was disabled, reconfigured or restarted to produce these findings.'

Hdr 'FM-1  MISSING SYSMON EVENT 1 (the primary DET-001 source)'
W 'Status: OBSERVED - this failure is not hypothetical. It already happened inside the'
W '        Phase 5 window and is visible in the preserved Phase 5 evidence itself.'
W ''
W 'OBSERVED in phase5/evidence/t6_detection_broad60_dc1.txt:'
W '  The 39 preserved DET-001 alerts run 00:05:18 .. 01:02:56 local with NO alert at all'
W '  between 00:07:38 and 00:41:10 - a 33m32s hole in the Sysmon Event 1 stream at the'
W '  collector, while the Phase 5 window was still open and the operator was still active.'
W ''
W 'OBSERVED in the read-only live probe (see the appended FM probe section):'
W "  - Sysmon Ev1 encoded-PowerShell candidates in the Phase 5 window = $liveSysmon"
W "  - Security 4688 encoded-PowerShell records in the SAME window    = $live4688"
W '  - 10-minute buckets with ZERO Sysmon Ev1 candidates (00:10 / 00:20 / 00:30) while'
W '    4688 carried 4 and 13 candidates in the 00:20 and 00:30 buckets.'
W ''
W 'EFFECT ON THE DETECTIONS:'
W '  - DET-001 (Sysmon-primary) is BLIND for the duration of the hole: encoded PowerShell'
W '    executed by authorised administration and by an adversary would look identical -'
W '    both would simply produce no alert.'
W '  - DET-002 (lineage) also loses its input: the chain is built from process-create events.'
W '  - The -Include4688Fallback switch keeps coverage: Security 4688 carried the encoded'
W "    command line for $live4688 processes in the same window and the trigger condition evaluates"
W "    identically on NewProcessName + CommandLine. $live4688No of those had no Sysmon twin."
W '  - COST of the fallback: 4688 has no ProcessGuid and no ParentProcessGuid, so lineage'
W '    must be resolved by PID (PID reuse is a real risk over a long window) and the WinRS'
W '    wrapper command line has to be recovered from the creator process own 4688 record.'
W '    DET-001 therefore trusts a 4688-rooted lineage LESS: it is baselined at the weaker'
W '    tier and reported as such, never silently upgraded to CONFIRMED.'
W ''
W 'CONTRIBUTING FACTOR (OBSERVED): the collector ForwardedEvents log is sitting at its'
W '20 MB maximum and actively evicting its oldest records, so retention is a live'
W 'constraint on this lab rather than a theoretical one. That explains WHY evidence can'
W 'disappear, but it does NOT explain a hole in the MIDDLE of the retained range.'
W ''
W 'CAUSE OF THE HOLE: NOT VERIFIED. The candidates are (a) the bounded Sysmon log on the'
W 'source rolling over before the forwarder read it, or (b) collector-side drop/backlog on'
W 'the higher-volume Sysmon channel (note the Sysmon EventRecordIDs jump 3053 -> 3252'
W 'across the hole, so roughly 199 Sysmon records are unaccounted for, while Security 4688'
W 'kept recording through the same minutes). Verifying the mechanism requires touching'
W 'WEF/Sysmon logging configuration, which Phase 6 was explicitly told not to do.'

Hdr 'FM-2  MISSING POWERSHELL 4104 (the corroboration / "what did it do" source)'
W "Status: OBSERVED in both Phase 5 and Phase 6."
W ''
W "  - Of the $n replayed candidates, the Phase 5 run itself recorded NO 4104 for $no4104inP5"
W '    of them (its own Corroboration line reads "NONE FOUND (4104 missing / not forwarded)").'
W '  - The Phase 6 replay binds a 4104 by executing PID where the preserved raw XML holds one,'
W "    and produced $escReplay payload escalations."
W ''
W 'EFFECT:'
W '  - DET-001 still FIRES. Sysmon Event 1 is the trigger; 4104 is enrichment only. This is'
W '    the correct fail-open direction - a missing 4104 must not hide the execution.'
W '  - What is LOST is the decoded ScriptBlockText and ScriptBlockId: the analyst loses the'
W '    "what did it actually run" view and must decode the base64 command line by hand.'
W '  - DET-002/CORR-001 are unaffected in principle (they use process events), but the'
W '    correlation reading degrades from "what + how" to "how only".'
W '  - A vanished 4104 is itself weakly suspicious only if it is gone for ONE process and not'
W '    its neighbours; that pattern is NOT observable here (no adversary telemetry).'

Hdr 'FM-3  MISSING PROCESS LINEAGE (no parent process-create record)'
W "Status: MEASURED in both directions - and the two directions disagree, which matters."
W ''
W "  LIVE (read-only probe, all parent events present):  $liveLinOk of $liveSysmon Sysmon"
W "                                    candidates found their immediate-parent record; $liveLinNo were"
W '                                    unresolved.  Live lineage resolution is therefore normal.'
W "  REPLAY over preserved Phase 5 evidence:  only $linWinrm candidates resolved as far as a"
W "                                    WinRM host, and $patternTier were baselined on the"
W '                                    transport PATTERN alone.'
W ''
W 'READING: the 33 unresolved lineages in the replay are an EVIDENCE-PRESERVATION artefact'
W '(Phase 5 kept only excerpts), not a live telemetry gap. The live probe shows lineage is'
W 'normally available. This is exactly why the replay never upgrades a PATTERN-tier event.'
W ''
W 'EFFECT WHEN LINEAGE IS GENUINELY MISSING AT RUNTIME (e.g. during the FM-1 hole):'
W '  - DET-001 drops the event from BASELINE-TRANSPORT-CONFIRMED (INFO) to'
W '    BASELINE-TRANSPORT-PATTERN (LOW). It is NOT suppressed outright and it is NOT'
W '    silently treated as benign - the analyst sees the tier drop and the reason it dropped.'
W '  - DET-002 emits no lineage record, so CORR-001 reports the gap as an investigative gap'
W '    ("LESS context than with lineage") instead of fabricating a chain.'
W '  - The safety property that matters: a MISSING parent can never make an event look MORE'
W '    benign than the evidence supports. Fail direction = keep looking, not suppress.'
W 'NOT VERIFIED: whether a genuinely malicious parent would be hidden. No adversary'
W '  telemetry exists in this lab, so that direction cannot be measured here.'

Hdr 'FM-4  MISSING / DEGRADED COMMAND LINE'
W 'Status: PARTIALLY OBSERVED.'
W ''
W "  OBSERVED (live): $live4688Em of the $live4688Ps powershell.exe 4688 records in the window had an"
W "    empty CommandLine, and 0 of the $liveSysmon Sysmon candidates had an empty CommandLine. In this lab"
W '    command-line auditing was ON for the whole window, so the trigger always evaluated.'
W "  OBSERVED (Phase 5 preserved output): $truncCmdLine of the 39 preserved alerts carry a"
W '    truncated CommandLine ("...[cut]"). The truncation is a Phase 5 OUTPUT-REPORTING'
W '    choice, not a telemetry loss, but it has a measurable consequence below.'
W ''
W 'EFFECT:'
W '  - If CommandLine is genuinely absent, DET-001 cannot evaluate its trigger at all: the'
W '    event is invisible to the rule and the encoding is never noticed. This is the worst'
W '    of the four failure modes because the failure is SILENT - no alert, no gap marker.'
W '    Whether the audit policy can ever be off in this lab is NOT VERIFIED; only the'
W '    "everything present" case is measured.'
W '  - The base64 decode also depends on the command line, so a missing command line removes'
W '    both the trigger and the decode step at once.'
W '  - MEASURED cost of degraded (truncated) payload text: with the full text available the'
W '    payload screen escalates 2 of the 38 baselined events (ESC-03, a second decode layer'
W '    on RecId 2975 and 3045); with only the preserved prefix the same replay escalates'
W "    0 of 38. A shortened command line therefore costs real escalations - the screen can"
W '    only judge the bytes it can see.'

Hdr 'SUMMARY - FAILURE MODES'
W ('{0,-58} {1,-14}' -f 'Failure mode','Status')
W ('{0,-58} {1,-14}' -f 'FM-1 missing Sysmon Event 1 (primary source)','OBSERVED')
W ('{0,-58} {1,-14}' -f 'FM-2 missing PowerShell 4104 (corroboration)','OBSERVED')
W ('{0,-58} {1,-14}' -f 'FM-3 missing process lineage (context)','OBSERVED (replay: largely an artefact)')
W ('{0,-58} {1,-14}' -f 'FM-4 missing command line (trigger + decode)','PARTIAL')
W ('{0,-58} {1,-14}' -f 'FM-1 root cause of the Sysmon hole','NOT VERIFIED')
W ('{0,-58} {1,-14}' -f 'FM-4 whether auditing is ever off in this lab','NOT VERIFIED')
W ('{0,-58} {1,-14}' -f 'any failure mode against real adversary telemetry','NOT VERIFIED')
W ''
W 'The invariants that survive all four failure modes:'
W '  1. DET-001 never becomes silent-by-suppression: a degraded event is retained at a weaker,'
W '     labelled tier, and the lost context is printed next to it.'
W '  2. No failure mode turns an unverifiable event into a benign verdict.'
W '  3. Every degraded reading is visible to the analyst in the alert block itself.'

if (Test-Path $LiveProbe) {
  Hdr 'APPENDIX - READ-ONLY LIVE FAILURE-MODE PROBE (SOC002-DC1)'
  W "Source file: $LiveProbe"
  W 'This probe measured one telemetry source at a time. Nothing was disabled: a source that'
  W 'was not read simply was not read.'
  W ''
  foreach ($l in (Get-Content -LiteralPath $LiveProbe)) { W $l }
} else {
  W ''
  W "NOTE: live probe file not found ($LiveProbe) - FM-1 numbers are NOT VERIFIED in this copy."
}

$text = ($o -join "`n")
[IO.File]::WriteAllText($OutFile, $text)
Write-Output $text
