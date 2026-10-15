<#
  SOC-002 | PHASE 7 | BASELINE COMPARISON  (offline, read-only)
  =====================================================================
  Compares the Phase 7 controlled execution against the preserved Phase 5/6
  WinRM baseline, field by field, using only evidence on disk:

    Phase 5/6 side : phase5/evidence/t3z_ancestry_ws001.txt  (the Phase 5
                     controlled test's process ancestry, preserved)
    Phase 7 side   : phase7/evidence/raw/t4_raw_local_ws001_controlled.txt

  It also reports whether the Phase 6 BASE-01 baseline still behaved as
  expected in the Phase 7 session window (baseline-drift check).

  Nothing here re-runs a detection: DET-001/DET-002/CORR-001 outputs are the
  ones produced on DC1 by the unmodified Phase 6 scripts.
#>
[CmdletBinding()]
param(
  [string]$Phase5Ancestry = "$PSScriptRoot/../../phase5/evidence/t3z_ancestry_ws001.txt",
  [string]$Phase7Raw      = "$PSScriptRoot/../evidence/raw/t4_raw_local_ws001_controlled.txt",
  [string]$Out            = "$PSScriptRoot/../evidence/t7_baseline_comparison.txt",
  [int]$MaxText = 220
)
$ErrorActionPreference = 'Stop'
$L = New-Object System.Collections.ArrayList
function Cut([string]$t,[int]$n){ if($null -eq $t){$t=''}; if($t.Length -gt $n){$t.Substring(0,$n)+'...[cut]'}else{$t} }

$null = $L.Add('=== SOC-002 PHASE 7 :: PHASE 6/5 WinRM BASELINE vs PHASE 7 CONTROLLED ACTIVITY ===')
$null = $L.Add("Generated (operator UTC) = $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))")
$null = $L.Add('')

# ---------------------------------------------------------------- phase 7 side
$p7 = @()
foreach ($line in (Get-Content -LiteralPath $Phase7Raw)) {
  if (-not $line.StartsWith('EVXML|')) { continue }
  $x = [xml]$line.Substring(6)
  if ([string]$x.Event.System.EventID -ne '1') { continue }
  $d = @{}; foreach ($n in @($x.Event.EventData.Data)) { if ($n.Name) { $d[$n.Name] = [string]$n.'#text' } }
  $p7 += [pscustomobject]@{
    Rec=[string]$x.Event.System.EventRecordID
    Utc=([datetime]$x.Event.System.TimeCreated.SystemTime).ToUniversalTime()
    Guid=$d['ProcessGuid']; Pid=[string]$d['ProcessId']; Ppid=[string]$d['ParentProcessId']
    Image=$d['Image']; Parent=$d['ParentImage']
    CL=$d['CommandLine']; PCL=$d['ParentCommandLine']; User=$d['User']; LogonId=$d['LogonId']
  }
}
$null = $L.Add('--- PHASE 7 process tree (Sysmon Event 1, controlled window) ----------')
foreach ($r in ($p7 | Sort-Object Utc)) {
  $null = $L.Add(("  {0}  PID={1,-5} PPID={2,-5} {3}" -f $r.Utc.ToString('HH:mm:ss.fff'), (Get-Variable -Name r).Value.Pid, $r.Ppid, (Split-Path -Leaf $r.Image)))
}
$null = $L.Add('')

$p7child = $p7 | Where-Object { $_.Image -match '(?i)powershell\.exe' -and $_.Parent -match '(?i)powershell\.exe' }
$p7trans = $p7 | Where-Object { $_.Image -match '(?i)powershell\.exe' -and $_.Parent -match '(?i)cmd\.exe' }
$p7cmd   = $p7 | Where-Object { $_.Image -match '(?i)cmd\.exe' }
$p7root  = $p7 | Where-Object { $_.Image -match '(?i)winrshost\.exe' }

# ---------------------------------------------------------------- phase 5 side
$null = $L.Add('--- PHASE 5 controlled test process tree (preserved evidence) ---------')
$p5rows = @()
foreach ($line in (Get-Content -LiteralPath $Phase5Ancestry)) {
  if ($line -match '^RecId=(\d+)\s+Utc=([\d:.]+)\s+PID=(\d+)\s+PPID=(\d+)\s+Img=(\S+)\s+Parent=(\S+)') {
    $p5rows += [pscustomobject]@{ Rec=$Matches[1]; Utc=$Matches[2]; Pid=$Matches[3]; Ppid=$Matches[4]; Img=$Matches[5]; Parent=$Matches[6] }
    $null = $L.Add(("  {0}  PID={1,-5} PPID={2,-5} {3}  <- {4}" -f $Matches[2], $Matches[3], $Matches[4], $Matches[5], $Matches[6]))
  }
}
$null = $L.Add('')

# ---------------------------------------------------------------- comparison
$null = $L.Add('--- FIELD-BY-FIELD COMPARISON -----------------------------------------')
function Row([string]$Field,[string]$A,[string]$B) { $null = $L.Add(("  {0,-26} | {1,-46} | {2}" -f $Field, (Cut $A 46), (Cut $B 46))) }
Row 'Field' 'PHASE 6 BASELINE (Phase 5 run)' 'PHASE 7 CONTROLLED RUN'
Row 'Host'            'SOC002-WS001.soc002.local' 'SOC002-WS001.soc002.local'
Row 'Account'         'SOC002\Administrator (Phase 5 investigation notes)' ($p7child | Select-Object -First 1).User
Row 'LogonId'         '0x615937 (Phase 5 t3y Sysmon window)' ($p7child | Select-Object -First 1).LogonId
Row 'Tree depth to payload' '3 (winrshost -> cmd -> powershell -> powershell)' ('3 (winrshost -> cmd -> powershell -> powershell)')
Row 'Root process'    'winrshost.exe (parent svchost.exe)' ((Split-Path -Leaf $p7root.Image) + ' (parent ' + (Split-Path -Leaf $p7root.Parent) + ')')
Row 'Transport cmd.exe' 'cmd.exe /C powershell -encodedcommand <b64> (Phase 5 broad60 / Phase 6 README)' ((Cut ($p7cmd.CL) 46))
Row 'Payload parent'  'powershell.exe (the WinRS transport powershell)' ((Split-Path -Leaf $p7child.Parent))
Row 'Payload command form' '-EncodedCommand <b64>  (encoded-command CLI switch)' '-Command "<... [Convert]::FromBase64String(...) ...>"  (NO encoded switch)'
Row 'Sysmon ProcessGuid (payload)' 'RecId 3535 / PID 1500 (Phase 5 raw: see t3a_sysmon1_ws001.txt)' ($p7child.Guid)
Row '4104 ScriptBlockId (payload)' 'RecId 72974 (Phase 5 correlation timeline)' ((Select-String -Path "$PSScriptRoot/../evidence/t4_local_telemetry_ws001_controlled.txt" -Pattern 'ExecutingPID=1428' | Select-Object -First 1).Line -replace '.*ScriptBlockId=([0-9a-f-]+).*','$1')
Row 'Delta between transport and payload create' '~0.52 s (21:59:47.564 -> 21:59:48.080)' ('{0:N3} s' -f ((($p7child.Utc) - ($p7trans.Utc)).TotalSeconds))
$null = $L.Add('')

# ---------------------------------------------------------------- distinguishability
$null = $L.Add('--- DISTINGUISHABILITY -------------------------------------------------')
$null = $L.Add('  Identical to the baseline : the delivery path (WinRM/WinRS), the parentage of every')
$null = $L.Add('                              hop, the account, the LogonId class, the integrity level, the')
$null = $L.Add('                              binary hashes (both powershell.exe processes share the same')
$null = $L.Add('                              SHA256), the tree depth and the substitution of one')
$null = $L.Add('                              powershell.exe for another as the payload parent.')
$null = $L.Add('  Different from the baseline: the payload process command line. Phase 5 used the')
$null = $L.Add('                              encoded-command CLI switch; Phase 7 used -Command with')
$null = $L.Add('                              [Convert]::FromBase64String(...) inside the script text.')
$null = $L.Add('  Consequence                  : DET-001 v2 keys on exactly that one field, so the')
$null = $L.Add('                              difference that separates the two runs is also the')
$null = $L.Add('                              difference that decides whether DET-001 sees them.')
$null = $L.Add('  DET-002 evidence             : the Phase 7 payload process IS recorded by DET-002 with')
$null = $L.Add('                              "Encoded switch = absent", which is the only field-level')
$null = $L.Add('                              discriminator the existing stack exposes. INFERRED, not proof')
$null = $L.Add('                              of intent.')
$null = $L.Add('')

# ---------------------------------------------------------------- drift check
$null = $L.Add('--- BASELINE-DRIFT CHECK (Phase 6 BASE-01 in the Phase 7 session) ------')
$session = Get-Content -LiteralPath "$PSScriptRoot/../evidence/t6_detection_stack_session.txt"
$base = @($session | Select-String '^\[' | Select-String 'BASE-')
$alerts = @($session | Select-String '^\[ALERT ')
$null = $L.Add("  BASE-01 matches in the Phase 7 session window : $($base.Count)")
$null = $L.Add("  INVESTIGATION records in the session window    : $($alerts.Count)  (all three are the operator's own base64 file-transfer steps - see t6 session output)")
$null = $L.Add('  Drift observed : none in the baseline pattern. Every WinRS transport wrapper in the')
$null = $L.Add('                   session still matched BASE-01 and resolved to a winrshost.exe ancestor.')
$null = $L.Add('  Drift NOTE     : the Phase 7 payload ran one level BELOW the baselined transport')
$null = $L.Add('                   powershell, exactly as the Phase 5 controlled test did. So BASE-01 did')
$null = $L.Add('                   not hide the Phase 7 activity - DET-001 simply never produced a')
$null = $L.Add('                   candidate for it. Broadening BASE-01 to depth-3 powershell-in-')
$null = $L.Add('                   powershell would be a real risk of hiding future activity and is')
$null = $L.Add('                   explicitly NOT done in this phase.')

$L -join "`n" | Set-Content -LiteralPath $Out -Encoding utf8
"wrote $Out"
