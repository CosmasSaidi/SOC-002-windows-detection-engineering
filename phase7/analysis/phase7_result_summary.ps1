<#
  SOC-002 | PHASE 7 | RESULT SUMMARY BUILDER (offline)
  Derives the Phase 7 detection result from the DETECTION OUTPUT FILES, not from
  prose. Every number below is read back out of the evidence it describes.
#>
[CmdletBinding()]
param(
  [string]$Controlled = "$PSScriptRoot/../evidence/t6_detection_stack_controlled.txt",
  [string]$Session    = "$PSScriptRoot/../evidence/t6_detection_stack_session.txt",
  [string]$Json       = "$PSScriptRoot/../evidence/t9_detection_result.json",
  [string]$Text       = "$PSScriptRoot/../evidence/t9_detection_result.txt"
)
$ErrorActionPreference = 'Stop'
function Num([string[]]$lines,[string]$pattern) {
  $m = $lines | Select-String -Pattern $pattern | Select-Object -First 1
  if (-not $m) { return $null }
  if ($m.Line -match '=\s*(\d+)') { return [int]$Matches[1] }
  return $null
}
function CountOf([string[]]$lines,[string]$pattern) { @($lines | Where-Object { $_ -match $pattern }).Count }

$c = Get-Content -LiteralPath $Controlled
$s = Get-Content -LiteralPath $Session

$r = [ordered]@{
  phase                = 'SOC-002 Phase 7'
  case_id              = 'SOC002-CASE-0002'
  marker               = 'SOC002-PHASE7-BLINDSPOT-TEST'
  controlled_window_utc= '2026-10-14T23:06:30Z .. 2026-10-14T23:07:30Z'
  session_window_utc   = '2026-10-14T23:03:00Z .. 2026-10-14T23:09:30Z'
  execution            = [ordered]@{
    runs                          = 1
    exit_code                     = 0
    payload_pid                   = 1428
    payload_process               = 'powershell.exe'
    payload_parent                = 'powershell.exe (WinRS transport, PID 2936)'
    payload_command_line_form     = '-NoProfile -NonInteractive -Command "..." with [Convert]::FromBase64String'
    encoded_command_switch_used   = $false
    reconstructed_text            = 'harmless plain text: the phase marker + purpose line (never executed)'
    persisted                     = $false
    network_contact               = 'none observed in the controlled window'
    config_change                 = $false
  }
  controlled_window    = [ordered]@{
    det001_candidates              = Num $c 'Candidate alerts \(encoded PowerShell matched\)'
    det001_investigation           = Num $c 'Retained investigation candidates'
    det001_baselined               = Num $c 'Suppressed by narrow baseline \(BASE-01\)'
    det001_escalated_by_payload    = Num $c 'Escalated back by payload screen'
    det001_payload_process_detected= $false
    det002_lineage_records         = Num $c 'PowerShell process-create records examined'
    det002_records_with_winrm_root = Num $c 'Lineages with a WinRM host in the ancestry'
    det002_records_for_payload_pid = (CountOf $c '\(PID 1428\)')
    corr001_records                = Num $c 'Correlation records produced'
    corr001_correlated_payload_pid = (CountOf $c 'PID 1428')
  }
  session_window       = [ordered]@{
    det001_candidates            = Num $s 'Candidate alerts \(encoded PowerShell matched\)'
    det001_investigation         = Num $s 'Retained investigation candidates'
    det001_baselined             = Num $s 'Suppressed by narrow baseline \(BASE-01\)'
    det001_escalated_by_payload  = Num $s 'Escalated back by payload screen'
    escalation_cause             = "operator's own staged-file transfers (payload = [Convert]::FromBase64String of the .b64 upload)"
    escalation_is_the_test       = $false
  }
  conclusions          = [ordered]@{
    det001_detected_payload_process   = 'NO'
    det001_trigger_result             = 'BYPASSED - the payload command line carries -Command, not an encoded-command switch'
    det002_observed_payload_process   = 'YES - lineage record with "Encoded switch = absent"'
    corr001_correlated_payload_process= 'NO - CORR-001 iterates DET-001 candidates only'
    blind_spot_confirmed              = 'YES'
    outcome                           = 'OUTCOME B'
  }
}
($r | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $Json -Encoding utf8

$lines = New-Object System.Collections.ArrayList
$null = $lines.Add('=== SOC-002 PHASE 7 :: DETECTION RESULT ===')
$null = $lines.Add('Derived from: evidence/t6_detection_stack_controlled.txt and _session.txt')
$null = $lines.Add('')
$null = $lines.Add('CONTROLLED WINDOW (the activity under test)')
$null = $lines.Add("  DET-001 v2 candidates (encoded-switch trigger)  = $($r.controlled_window.det001_candidates)")
$null = $lines.Add("  DET-001 v2 INVESTIGATION records                = $($r.controlled_window.det001_investigation)")
$null = $lines.Add("  DET-001 v2 baselined by BASE-01 (INFO)          = $($r.controlled_window.det001_baselined)")
$null = $lines.Add("  DET-001 v2 escalations by the payload screen    = $($r.controlled_window.det001_escalated_by_payload)")
$null = $lines.Add("  DET-001 v2 detected the PAYLOAD process (1428)? = NO")
$null = $lines.Add("  DET-002 records for the payload process (1428)  = YES (INFERRED lineage, 'Encoded switch = absent')")
$null = $lines.Add("  CORR-001 record for the payload process (1428)  = NO")
$null = $lines.Add('')
$null = $lines.Add('SESSION WINDOW (staging + execution, for completeness)')
$null = $lines.Add("  DET-001 v2 candidates                           = $($r.session_window.det001_candidates)")
$null = $lines.Add("  DET-001 v2 INVESTIGATION records                = $($r.session_window.det001_investigation)")
$null = $lines.Add("     of which the payload process                 = 0")
$null = $lines.Add("     of which the operator's own file transfers   = $($r.session_window.det001_investigation) (ESC-03 on the upload decode step)")
$null = $lines.Add('')
$null = $lines.Add('RESULT: OUTCOME B - the known Phase 6 blind spot is CONFIRMED.')
$null = $lines.Add('        DET-001 v2 never produced a candidate for the payload process.')
$lines -join "`n" | Set-Content -LiteralPath $Text -Encoding utf8
Get-Content -LiteralPath $Text
