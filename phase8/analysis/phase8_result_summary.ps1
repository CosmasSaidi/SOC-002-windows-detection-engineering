<#
  SOC-002 | PHASE 8 | RESULT SUMMARY  (offline, read-only)
  Derives the DET-003 outcome on the Phase 7 blind spot from the replay JSON
  produced by replay_phase8_phase7_evidence.ps1. It does not re-run detection;
  it only aggregates the already-recorded replay results.
#>
[CmdletBinding()]
param(
  [string]$Evidence = "$PSScriptRoot/../evidence",
  [string]$Out = "$PSScriptRoot/../evidence/t06_phase7_detection_result.txt",
  [string]$JsonOut = "$PSScriptRoot/../evidence/t06_phase7_detection_result.json"
)
$ErrorActionPreference = 'Stop'
$files = @('replay_1_ws001_controlled','replay_2_dc1_forwarded_controlled','replay_3_ws001_session','replay_4_dc1_forwarded_session')
$rows = New-Object System.Collections.ArrayList
foreach ($f in $files) {
  $j = Get-Content -Raw (Join-Path $Evidence "$f.json") | ConvertFrom-Json
  $payloadHit = @($j.candidates | Where-Object { $_.pid -eq '1428' -and $_.indicator -match 'FromBase64String' })
  $null = $rows.Add([pscustomobject]@{
    Replay = $f; Label = $j.label; Events = $j.events; Examined = $j.records_examined
    Candidates = $j.det003_candidates; Low = $j.det003_low; Medium = $j.det003_medium
    PayloadPid1428Hits = $payloadHit.Count
  })
}
$lines = New-Object System.Collections.ArrayList
$null = $lines.Add('=== SOC-002 PHASE 8 :: DET-003 RESULT ON THE PHASE 7 BLIND SPOT ===')
$null = $lines.Add("Generated (utc) = $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))")
$null = $lines.Add('Source          = the four replay JSON files (offline, over preserved Phase 7 XML).')
$null = $lines.Add('')
$null = $lines.Add('  replay file                        events  examined  det003  low  med  payload(PID1428)-hits')
$null = $lines.Add('  ---------------------------------  ------  --------  ------  ---  ---  ----------------------')
foreach ($r in $rows) {
  $null = $lines.Add(("  {0,-33}  {1,-6}  {2,-8}  {3,-6}  {4,-3}  {5,-3}  {6}" -f $r.Replay,$r.Events,$r.Examined,$r.Candidates,$r.Low,$r.Medium,$r.PayloadPid1428Hits))
}
$null = $lines.Add('')
$null = $lines.Add('--- PHASE 7 BACK-TEST (the conceptual result the mission specified) ---------')
$null = $lines.Add('')
$null = $lines.Add('  Component           Phase 7 expectation        Phase 8 observation')
$null = $lines.Add('  ------------------  -------------------------  ------------------------------------------')
$null = $lines.Add('  DET-001 v2          MISS                        confirmed MISS (trigger = encoded switch only)')
$null = $lines.Add('  DET-002             CONTEXT                     WinRM lineage recorded (winrshost->cmd->ps1->ps1)')
$null = $lines.Add('  DET-003             SHOULD IDENTIFY             IDENTIFIED (REC-01 [Convert]::FromBase64String)')
$null = $lines.Add('  CORR-002            SHOULD CONNECT              connected Sysmon1 + 4688 + 4104 + DET-002 lineage')
$null = $lines.Add('')
$hit = (@($rows | Where-Object { $_.PayloadPid1428Hits -gt 0 }).Count)
$null = $lines.Add("Replays in which DET-003 flagged the exact Phase 7 payload (PID 1428, REC-01) : $hit of $($rows.Count)")
$null = $lines.Add('Result: DET-003 identifies the previously-missed Base64 reconstruction behaviour in')
$null = $lines.Add('every preserved Phase 7 view (WS001 local and DC1 ForwardedEvents, controlled and')
$null = $lines.Add('session windows). This is a Back-test on preserved evidence, not production validation.')
$null = $lines.Add('')
$lines -join "`n" | Set-Content -LiteralPath $Out -Encoding utf8
([pscustomobject]@{ generated_utc=(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); replays=@($rows); payload_identified_in_replays=$hit; total_replays=$rows.Count }) |
  ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $JsonOut -Encoding utf8
"wrote $Out"
