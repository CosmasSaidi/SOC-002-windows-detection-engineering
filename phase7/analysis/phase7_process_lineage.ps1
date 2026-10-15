<#
  SOC-002 | PHASE 7 | PROCESS LINEAGE BUILDER  (offline, read-only)
  Joins the raw Phase 7 events for the controlled window into one lineage view:
  Sysmon Event 1 (ProcessGuid / ParentProcessGuid), Security 4688 (creator PID
  chain) and PowerShell 4104 (ScriptBlockId per executing PID). For each hop it
  also records whether the EXISTING DET-001 v2 trigger could see it, by calling
  the unmodified Phase 6 library function on that process's own command line.
#>
[CmdletBinding()]
param(
  [string]$Raw  = "$PSScriptRoot/../evidence/raw/t4_raw_local_ws001_controlled.txt",
  [string]$LibPath = "$PSScriptRoot/../../phase6/detections",
  [string]$Out  = "$PSScriptRoot/../evidence/t8_process_lineage.txt"
)
$ErrorActionPreference = 'Stop'
. (Join-Path $LibPath 'lib_soc002_v2.ps1')
$lib = Get-Soc002LibIdentity
$L = New-Object System.Collections.ArrayList

$sy = @(); $sec = @(); $ps4 = @()
foreach ($line in (Get-Content -LiteralPath $Raw)) {
  if (-not $line.StartsWith('EVXML|')) { continue }
  $x = [xml]$line.Substring(6)
  $id = [string]$x.Event.System.EventID
  $d = @{}; foreach ($n in @($x.Event.EventData.Data)) { if ($n.Name) { $d[$n.Name] = [string]$n.'#text' } }
  $t = ([datetime]$x.Event.System.TimeCreated.SystemTime).ToUniversalTime()
  switch ($id) {
    '1'    { $sy += [pscustomobject]@{Utc=$t;Rec=[string]$x.Event.System.EventRecordID;D=$d} }
    '4688' { $sec += [pscustomobject]@{Utc=$t;Rec=[string]$x.Event.System.EventRecordID;D=$d} }
    '4104' { $ps4 += [pscustomobject]@{Utc=$t;Rec=[string]$x.Event.System.EventRecordID;ExecPid=[string]$x.Event.System.Execution.ProcessID;D=$d} }
  }
}
function H2D([string]$v){ if(!$v){return ''}; if($v -match '^0x[0-9a-fA-F]+$'){return ([Convert]::ToInt64($v.Substring(2),16)).ToString()}; return $v }

$null = $L.Add('=== SOC-002 PHASE 7 :: PROCESS LINEAGE (controlled window) ===')
$null = $L.Add("Library = $($lib.LibVersion) sha256=$($lib.LibSha256)")
$null = $L.Add("Source  = $Raw")
$null = $L.Add('')

# depth of each process relative to the WinRM root (winrshost.exe), by walking
# the ParentProcessId links inside this window only.
function Get-Depth($rec, $all) {
  $depth = 0; $cur = $rec; $guard = 0
  while ($guard -lt 20) {
    $guard++
    $par = $all | Where-Object { $_.D['ProcessId'] -eq $cur.D['ParentProcessId'] } | Select-Object -First 1
    if (-not $par) { break }
    $depth++; $cur = $par
  }
  return $depth
}
$null = $L.Add('--- CHAIN (Sysmon Event 1) -------------------------------------------------')
foreach ($r in ($sy | Sort-Object Utc)) {
  $d = $r.D
  $enc = Test-Soc002EncodedCommandLine -CommandLine $d['CommandLine']
  $imgOk = ($d['Image'] -match $script:Soc002ImageRx)
  $null = $L.Add(("  depth={0}  {1}  {2}  PID={3} PPID={4}" -f (Get-Depth $r $sy), $r.Utc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'), $d['Image'], $d['ProcessId'], $d['ParentProcessId']))
  $null = $L.Add(("        ProcessGuid       = {0}" -f $d['ProcessGuid']))
  $null = $L.Add(("        ParentProcessGuid = {0}   ParentImage={1}" -f $d['ParentProcessGuid'], $d['ParentImage']))
  $null = $L.Add(("        User={0}  LogonId={1}  Integrity={2}  Hashes={3}" -f $d['User'], $d['LogonId'], $d['IntegrityLevel'], $d['Hashes']))
  $null = $L.Add(("        CommandLine       = {0}" -f $d['CommandLine']))
  $null = $L.Add(("        ParentCommandLine = {0}" -f $d['ParentCommandLine']))
  $null = $L.Add(("        image matches powershell/pwsh image filter : {0}" -f $imgOk))
  $null = $L.Add(("        encoded-command switch in command line      : {0}" -f $enc))
  $null = $L.Add(("        => DET-001 v2 candidate?                    : {0}" -f $(if ($imgOk -and $enc) { 'YES' } else { 'NO' })))
  $null = $L.Add('')
}

$null = $L.Add('--- CREATOR CHAIN (Security 4688) -----------------------------------------')
foreach ($r in ($sec | Sort-Object Utc)) {
  $d = $r.D
  $null = $L.Add(("  {0}  NewPID={1,-5} New={2}" -f $r.Utc.ToString('HH:mm:ss.fff'), (H2D $d['NewProcessId']), $d['NewProcessName']))
  $null = $L.Add(("        CreatorPID={0}  ParentProcessName={1}  Subject={2}\{3}  LogonId={4}" -f (H2D $d['ProcessId']), $d['ParentProcessName'], $d['SubjectDomainName'], $d['SubjectUserName'], $d['SubjectLogonId']))
  $null = $L.Add(("        CommandLine = {0}" -f $d['CommandLine']))
}
$null = $L.Add('')

$null = $L.Add('--- POWERSHELL 4104 (ScriptBlockId per executing PID) ---------------------')
foreach ($r in ($ps4 | Sort-Object Utc)) {
  $txt = [string]$r.D['ScriptBlockText']
  $null = $L.Add(("  {0}  RecId={1}  ExecutingPID={2}  ScriptBlockId={3}  Msg={4}/{5}  len={6}" -f $r.Utc.ToString('HH:mm:ss.fff'), $r.Rec, $r.ExecPid, $r.D['ScriptBlockId'], $r.D['MessageNumber'], $r.D['MessageTotal'], $txt.Length))
  if ($txt -match '(?i)FromBase64String') { $null = $L.Add('        ^ this is the blind-spot script block: it reconstructs text with [Convert]::FromBase64String') }
  $null = $L.Add(("        Text = {0}" -f $txt))
}
$null = $L.Add('')
$null = $L.Add('--- READING ---------------------------------------------------------------')
$null = $L.Add('  The payload process (the one that actually performed the base64 reconstruction) is')
$null = $L.Add('  the last powershell.exe, whose parent is the other powershell.exe. Its command line')
$null = $L.Add('  carries -Command and [Convert]::FromBase64String(...) and NO encoded-command switch,')
$null = $L.Add('  so the DET-001 v2 trigger returns no match for it. The process that DOES match the')
$null = $L.Add('  trigger is the WinRS transport powershell above it, which is the transport artefact')
$null = $L.Add('  present for every WinRM call in this lab and is baselined by BASE-01.')
$L -join "`n" | Set-Content -LiteralPath $Out -Encoding utf8
"wrote $Out"
