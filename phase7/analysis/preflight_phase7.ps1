<#
  SOC-002 | PHASE 7 | PRE-FLIGHT CHECK  (offline, read-only)
  =====================================================================
  Runs the REAL Phase 6 decision library (lib_soc002_v2.ps1, unmodified)
  against two command lines, BEFORE any lab activity happens:

     POSITIVE CONTROL  - the Phase 5 controlled child command line
                         (powershell.exe -NoProfile -EncodedCommand <b64>)
     PHASE 7 SUBJECT   - the Phase 7 blind-spot child command line
                         (powershell.exe -NoProfile -NonInteractive -Command
                          "$b='<b64>';...[Convert]::FromBase64String($b)...")

  Expected: control = TRIGGER MATCH; subject = TRIGGER NOT MATCH.
  This is a logic check on the detector, not a lab event.
#>
[CmdletBinding()]
param(
  [string]$LibPath = "$PSScriptRoot/../../phase6/detections",
  [string]$RunScript = "$PSScriptRoot/../scripts/phase7_run_ws001.ps1"
)
$ErrorActionPreference = 'Stop'
. (Join-Path $LibPath 'lib_soc002_v2.ps1')

$lib = Get-Soc002LibIdentity
"### PHASE 7 PRE-FLIGHT :: DET-001 v2 trigger check (offline) ###"
"Library file    = $($lib.LibFile)"
"Library version = $($lib.LibVersion)"
"Library sha256  = $($lib.LibSha256)"
"Trigger regex   = $script:Soc002EncSwitchRx"
''

# ---- positive control: the Phase 5 encoded command line -------------------
$p5 = Get-Content -Raw (Join-Path $PSScriptRoot '../../phase5/evidence/t2_execute_ws001.txt')
$ctrl = [regex]::Match($p5, "(?m)^CHILD_CMD\s*=\s*(.+)$").Groups[1].Value.Trim()
if (-not $ctrl) { throw 'could not recover the Phase 5 CHILD_CMD from preserved evidence' }
"POSITIVE CONTROL (Phase 5 controlled child command line, from preserved evidence):"
"  CMD    = $($ctrl.Substring(0, [Math]::Min(120,$ctrl.Length)))...[cut]"
"  image  = $($ctrl -match $script:Soc002ImageRx)"
"  TRIGGER= $(Test-Soc002EncodedCommandLine -CommandLine $ctrl)"
''

# ---- phase 7 subject: the real child command body ------------------------
$childBody = (Get-Content -Raw (Join-Path $PSScriptRoot '../scripts/phase7_child_command.txt')).Trim()
$b64       = [regex]::Match($childBody, "\`$b='([^']+)'").Groups[1].Value
if (-not $childBody -or -not $b64) { throw 'could not parse scripts/phase7_child_command.txt' }
$full = "powershell.exe -NoProfile -NonInteractive -Command `"$childBody`""

"PHASE 7 SUBJECT (blind-spot child command line - never -EncodedCommand):"
"  CMD    = $full"
"  image  = $($full -match $script:Soc002ImageRx)"
"  TRIGGER= $(Test-Soc002EncodedCommandLine -CommandLine $full)"
''
# ---- and the loader line that will actually be sent over WinRM -----------
$loader = "`$c=[IO.File]::ReadAllText('C:\Windows\Temp\soc002-phase7\phase7_child_command.txt'); powershell.exe -NoProfile -NonInteractive -Command `$c"
"TRANSPORT LOADER LINE (sent over WinRM/WinRS - must stay clean):"
"  CMD    = $loader"
"  TRIGGER= $(Test-Soc002EncodedCommandLine -CommandLine $loader)"
"  ESC    = $((@(Get-Soc002EscalationHits -DecodedText $loader) | ForEach-Object { $_.Id }) -join ',')"
''
# ---- what the base64 blob actually decodes to ----------------------------
$bytes = [Convert]::FromBase64String($b64)
$text  = [Text.Encoding]::UTF8.GetString($bytes)
$esc   = Get-Soc002EscalationHits -DecodedText $text
"DECODED BLOB (what [Convert]::FromBase64String reconstructs):"
"  bytes  = $($bytes.Length)   utf8_chars = $($text.Length)"
"  text   = $($text -replace '\r?\n',' | ')"
"  contains marker                     = $($text -match 'SOC002-PHASE7-BLINDSPOT-TEST')"
"  contains arbitrary-code constructs  = $([bool]($text -match '(?i)(invoke-expression|\biex\b|frombase64|start-process|new-item)'))"
"  ESC payload-screen hits on the blob = $(@($esc).Count)"
''
'--- VERDICT --------------------------------------------------------'
"POSITIVE CONTROL trigger match : $(Test-Soc002EncodedCommandLine -CommandLine $ctrl)"
"PHASE 7 SUBJECT  trigger match : $(Test-Soc002EncodedCommandLine -CommandLine $full)"
'Expectation: control True, subject False -> the Phase 6 blind spot is real and'
'the Phase 7 payload is benign text.'
'### END PRE-FLIGHT ###'
