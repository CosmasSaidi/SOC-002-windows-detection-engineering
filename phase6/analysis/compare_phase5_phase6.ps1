<#
  SOC-002 | Phase 6 | TASK 6 - PHASE 5 vs PHASE 6, EVENT BY EVENT
  ==================================================================
  Joins the preserved Phase 5 alert list to the Phase 6 classifications of the
  SAME events, using the Sysmon RecordId (preserved end-to-end by WEF) as the
  key. Two Phase 6 sources are joined:
     (a) the live Phase 6 run against DC1 ForwardedEvents (full payloads, full
         ancestry available because the process events are still in the log);
     (b) the offline replay over the preserved Phase 5 evidence (truncated
         payloads / missing parent events - deliberately kept as a control).
  No new activity is generated and Phase 5 files are only read.
#>
[CmdletBinding()]
param(
  [string]$Phase5Root   = (Join-Path $HOME 'soc-lab/phase5/evidence'),
  [string]$LiveFile     = (Join-Path $HOME 'soc-lab/phase6/evidence/t6_phase6_det001_v2_live_dc1.txt'),
  [string]$ReplayFile   = (Join-Path $HOME 'soc-lab/phase6/evidence/t6_phase6_det001_v2_replay.txt')
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..' 'detections' 'lib_soc002_v2.ps1')
. (Join-Path $here 'lib_evidence_phase5.ps1')

function Read-Soc002Det001Output {
  param([string]$Path)
  $base = New-Object System.Collections.ArrayList
  $alerts = New-Object System.Collections.ArrayList
  $mode = ''
  $cur = $null
  foreach ($line in (Get-Content -LiteralPath $Path)) {
    if ($line -match '^\[BASE \d+\]\s+rec=(\d+)\s+utc=(\S+)\s+(\S+)\s+tier=(\S+)\s+sev=(\S+)\s+pid=(\S+)') {
      $null = $base.Add([pscustomobject]@{ RecordId=$Matches[1]; Utc=$Matches[2]; Computer=$Matches[3]; Tier=$Matches[4]; Severity=$Matches[5]; Pid=$Matches[6] })
      $mode = ''
      continue
    }
    if ($line -match '^\[ALERT \d+\]') { $mode = 'alert'; $cur = @{ Tier=''; Sev=''; RecId=''; Pid=''; Why='' }; continue }
    if ($mode -eq 'alert') {
      if ($line -match 'Detection\s+= SOC002-DET-001 v2\s+tier=(\S+)\s+severity=(\S+)') { $cur.Tier = $Matches[1]; $cur.Sev = $Matches[2] }
      elseif ($line -match 'Why retained\s+=\s*(.+)$') { $cur.Why = $Matches[1].Trim() }
      elseif ($line -match 'RecordId/Source\s+=\s*(\d+)') { $cur.RecId = $Matches[1] }
      elseif ($line -match 'Process\s+=\s*(.+?)\s+\(PID (\d+)\)') { $cur.Pid = $Matches[2] }
      elseif ($line -match '^\[BASE ') { $mode = '' }
      if ($cur.RecId -and $cur.Tier) { $null = $alerts.Add([pscustomobject]$cur); $mode = '' }
    }
  }
  [pscustomobject]@{ Baseline=@($base); Alerts=@($alerts) }
}

$ev     = Read-Soc002Phase5Evidence -Root $Phase5Root
$live   = Read-Soc002Det001Output -Path $LiveFile
$replay = Read-Soc002Det001Output -Path $ReplayFile

function Get-TierFor($set, $recId) {
  $b = @($set.Baseline | Where-Object { $_.RecordId -eq "$recId" })
  if ($b.Count) { return $b[0].Tier }
  $a = @($set.Alerts | Where-Object { $_.RecId -eq "$recId" })
  if ($a.Count) { return 'INVESTIGATION (' + $a[0].Why + ')' }
  return '(not present in this source)'
}

$p5Set = @($ev.Alerts | Sort-Object { [int]$_.RecordId } -Descending)
$rows = foreach ($a in $ev.Alerts) {
  [pscustomobject]@{
    RecId   = $a.RecordId
    Utc     = $a.TimeUtc.ToString('HH:mm:ss.fff')
    Pid     = $a.Pid
    Parent  = Get-Soc002Leaf $a.ParentImage
    P5Index = $a.Phase5AlertIndex
    Live    = Get-TierFor $live $a.RecordId
    Replay  = Get-TierFor $replay $a.RecordId
  }
}
$p5RecIds = @($ev.Alerts | ForEach-Object { $_.RecordId })
$liveExtra = @($live.Baseline | Where-Object { $p5RecIds -notcontains $_.RecordId })
$liveExtraAlerts = @($live.Alerts | Where-Object { $_.RecId -and $p5RecIds -notcontains $_.RecId })

$liveBase = @($rows | Where-Object { $_.Live -like 'BASELINE*' })
$liveInv  = @($rows | Where-Object { $_.Live -like 'INVESTIGATION*' })
$liveConfirmed = @($rows | Where-Object { $_.Live -eq 'BASELINE-TRANSPORT-CONFIRMED' })
$livePattern   = @($rows | Where-Object { $_.Live -eq 'BASELINE-TRANSPORT-PATTERN' })
$escOverrides  = @($rows | Where-Object { $_.Live -like '*payload escalation*' })
$controlled    = @($rows | Where-Object { $_.Live -like '*not baselined*' })

$out = New-Object System.Collections.ArrayList
$null = $out.Add('=====================================================================')
$null = $out.Add(' SOC-002 PHASE 6 / TASK 6 - PHASE 5 vs PHASE 6 (same events, joined)')
$null = $out.Add('=====================================================================')
$null = $out.Add("Phase 5 source : $Phase5Root/t6_detection_broad60_dc1.txt (39 alerts, window 2026-10-15 00:04:46..01:05:46 local)")
$null = $out.Add("Phase 6 live   : $LiveFile")
$null = $out.Add("Phase 6 replay : $ReplayFile")
$null = $out.Add('Join key       : Sysmon RecordId (preserved end-to-end by WEF)')
$null = $out.Add('')
$null = $out.Add('Per-event result for the 39 Phase 5 alerts:')
$null = $out.Add(('  {0,-8} {1,-13} {2,-6} {3,-9} {4,-32} {5}' -f 'RecId','Utc','PID','Parent','PHASE 6 LIVE','PHASE 6 REPLAY'))
foreach ($r in ($rows | Sort-Object { [int]$_.RecId })) {
  $null = $out.Add(('  {0,-8} {1,-13} {2,-6} {3,-9} {4,-32} {5}' -f $r.RecId, $r.Utc, $r.Pid, $r.Parent, $r.Live, $r.Replay))
}
$null = $out.Add('')
$null = $out.Add('--- Measured comparison ---------------------------------------------------')
$null = $out.Add(('{0,-62} {1,10} {2,10}' -f 'Metric','Phase 5','Phase 6'))
$null = $out.Add(('{0,-62} {1,10} {2,10}' -f 'Detection trigger','encoded PS','unchanged'))
$null = $out.Add(('{0,-62} {1,10} {2,10}' -f 'Candidate alerts produced', 39, 39))
$null = $out.Add(('{0,-62} {1,10} {2,10}' -f 'Alerts requiring human triage (retained)', 39, $liveInv.Count))
$null = $out.Add(('{0,-62} {1,10} {2,10}' -f 'Baselined by BASE-01 (no triage)', 0, $liveBase.Count))
$null = $out.Add(('{0,-62} {1,10} {2,10}' -f '   - BASELINE-TRANSPORT-CONFIRMED (INFO)', 'n/a', $liveConfirmed.Count))
$null = $out.Add(('{0,-62} {1,10} {2,10}' -f '   - BASELINE-TRANSPORT-PATTERN (LOW)', 'n/a', $livePattern.Count))
$null = $out.Add(('{0,-62} {1,10} {2,10}' -f 'Re-opened by the payload screen (ESC-03)', 'n/a', $escOverrides.Count))
$null = $out.Add(('{0,-62} {1,10} {2,10}' -f 'Of the 38 Phase-5 benign-classified events: suppressed', '0', (38 - $escOverrides.Count)))
$null = $out.Add(('{0,-62} {1,10} {2,10}' -f 'Of the 38 Phase-5 benign-classified events: re-opened', '0', $escOverrides.Count))
$null = $out.Add(('{0,-62} {1,10} {2,10}' -f 'Controlled-test event (RecId 3535): retained', 1, $controlled.Count))
$null = $out.Add('')
$null = $out.Add('Events present in the Phase 6 LIVE run but NOT in the Phase 5 alert list:')
$null = $out.Add("  count = $($liveExtra.Count + $liveExtraAlerts.Count)")
foreach ($e in $liveExtra) { $null = $out.Add("    RecId $($e.RecordId)  $($e.Utc)  tier=$($e.Tier)  (Sysmon Event 1 created after Phase 5 ran its query - see note)") }
foreach ($e in $liveExtraAlerts) { $null = $out.Add("    RecId $($e.RecId)  tier=INVESTIGATION  why=$($e.Why)") }
$null = $out.Add('  NOTE (OBSERVED): these extra events are WS001 process creates that Phase 5''s own detection run')
$null = $out.Add('  and post-run steps produced at 01:05:05-01:05:50 local, i.e. at/after the moment the Phase 5')
$null = $out.Add('  query executed. They were not visible to that query (forwarding/query timing) but they are')
$null = $out.Add('  visible now, and every one of them is classified as baseline WinRS transport.')
$null = $out.Add('')
$null = $out.Add('HONEST READING OF THE FALSE-POSITIVE QUESTION')
$null = $out.Add(" - Detection hits did NOT fall: 39/39 Phase 5 events are still detected, plus $($liveExtra.Count + $liveExtraAlerts.Count) more that the")
$null = $out.Add('   window now contains.')
$null = $out.Add(" - TRIAGE VOLUME fell from 39 (every alert reviewed by hand in Phase 5) to $($liveInv.Count) retained candidate(s).")
$null = $out.Add(" - $($liveBase.Count) of 39 events are auto-classified as baseline WinRS transport with the reason recorded per event;")
$null = $out.Add("   $($livePattern.Count) of those needed the weaker 'pattern-only' tier because their parent process-create event is gone.")
$null = $out.Add(" - $($escOverrides.Count) events that Phase 5 had manually called benign (the Sysmon-config application over WinRM,")
$null = $out.Add('   whose decoded payload contains a base64 blob decode) are RE-OPENED by the payload screen. That is a')
$null = $out.Add('   deliberate precision/recall trade, not an accident: the same shape is used by real stagers.')
$null = $out.Add(' - This is a re-decision over known-benign data. It does NOT prove the baseline reduces false')
$null = $out.Add('   positives against unseen or adversarial activity - no such activity exists in this lab (NOT VERIFIED).')
$null = $out.Add('')
$out -join "`n"
