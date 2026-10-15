<#
  SOC-002 | PHASE 7 | TELEMETRY COLLECTOR  (READ-ONLY)
  =====================================================================
  Collects the exact events the Phase 7 validation depends on. It NEVER
  writes to a log, never changes configuration, and never executes anything.

  Sources
    -Source ws001-local      -> run ON SOC002-WS001, reads local Security,
                                Sysmon and PowerShell-Operational logs.
    -Source dc1-forwarded    -> run ON SOC002-DC1, reads ForwardedEvents
                                (the WEF-delivered copies of the same events).

  Bound handling
    Window bounds are supplied in UTC (e.g. 2026-10-14T22:10:00Z) and parsed
    invariant/AdjustToUniversal, then converted to the LOCAL time of whatever
    host this runs on before being handed to Get-WinEvent (which interprets
    StartTime/EndTime in host-local terms). Records are then filtered a second
    time on their UTC timestamp. This removes any timezone ambiguity between
    WS001 (UTC+2), DC1 (UTC+2) and the operator workstation (UTC+3).
#>
# Window + source are supplied by the caller as environment variables so that
# the same file can be executed identically on WS001 (inline, because WS001's
# effective execution policy is Restricted) and on DC1.
#   PHASE7_START_UTC  e.g. 2026-10-14T23:06:30Z
#   PHASE7_END_UTC    e.g. 2026-10-14T23:07:30Z
#   PHASE7_SOURCE     ws001-local | dc1-forwarded

$StartUtc = $env:PHASE7_START_UTC
$EndUtc   = $env:PHASE7_END_UTC
$Source   = if ($env:PHASE7_SOURCE) { $env:PHASE7_SOURCE } else { 'ws001-local' }
$MaxText  = if ($env:PHASE7_MAXTEXT) { [int]$env:PHASE7_MAXTEXT } else { 900 }
if (-not $StartUtc -or -not $EndUtc) { throw 'PHASE7_START_UTC / PHASE7_END_UTC not supplied' }
if ($Source -notin @('ws001-local','dc1-forwarded')) { throw "bad PHASE7_SOURCE '$Source'" }

$ErrorActionPreference = 'SilentlyContinue'

function ConvertTo-UtcDate([string]$s) {
  [datetime]::Parse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal)
}
$sU = ConvertTo-UtcDate $StartUtc
$eU = ConvertTo-UtcDate $EndUtc
$sL = $sU.AddMinutes(-5).ToLocalTime()
$eL = $eU.AddMinutes(5).ToLocalTime()

function Cut([string]$t, [int]$n) { if ($null -eq $t) { $t = '' }; if ($t.Length -gt $n) { $t.Substring(0,$n) + '...[cut]' } else { $t } }
function Expand-EventData($ev) {
  $x = [xml]$ev.ToXml(); $h = @{}
  foreach ($n in @($x.Event.EventData.Data)) { if ($n.Name) { $h[$n.Name] = [string]$n.'#text' } }
  $h
}
function Get-Records([string]$log, [int]$id) {
  @(Get-WinEvent -FilterHashtable @{LogName=$log; Id=$id; StartTime=$sL; EndTime=$eL} -EA SilentlyContinue |
    Where-Object { $_.TimeCreated.ToUniversalTime() -ge $sU -and $_.TimeCreated.ToUniversalTime() -le $eU } |
    Sort-Object TimeCreated)
}
function Get-Prop($h, [string[]]$names) {
  foreach ($n in $names) { if ($h.ContainsKey($n) -and "$($h[$n])" -ne '') { return $h[$n] } }
  return ''
}
function HexToDec([string]$v) {
  if ([string]::IsNullOrWhiteSpace($v)) { return '' }
  $v = $v.Trim()
  if ($v -match '^0x[0-9a-fA-F]+$') { return ([Convert]::ToInt64($v.Substring(2),16)).ToString() }
  return $v
}

$isLocal = ($Source -eq 'ws001-local')
$secLog  = if ($isLocal) { 'Security' } else { 'ForwardedEvents' }
$psLog   = if ($isLocal) { 'Microsoft-Windows-PowerShell/Operational' } else { 'ForwardedEvents' }
$sysLog  = if ($isLocal) { 'Microsoft-Windows-Sysmon/Operational' } else { 'ForwardedEvents' }

'### PHASE7 TELEMETRY COLLECT ==='
"Source        = $Source"
"CollectedOn   = $env:COMPUTERNAME"
"WindowUtc     = $($sU.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')) .. $($eU.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
"HostLocalTz   = $([TimeZoneInfo]::Local.Id)  offs=$([TimeZoneInfo]::Local.GetUtcOffset((Get-Date)))"
"CollectUtc    = $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
''

$sec4688 = Get-Records $secLog 4688
'--- A) Security 4688 (process creation, CommandLine audit) ---'
"count = $($sec4688.Count)"
$i = 0
foreach ($ev in $sec4688) {
  $h = Expand-EventData $ev; $i++
  "[A{0:D3}] Utc={1} RecId={2} Computer={3}" -f $i, $ev.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'), $ev.RecordId, $ev.MachineName
  "       NewProcessId=$((HexToDec (Get-Prop $h @('NewProcessId'))))  NewProcessName=$(Get-Prop $h @('NewProcessName'))"
  "       CreatorPID=$((HexToDec (Get-Prop $h @('ProcessId'))))  ParentProcessName=$(Get-Prop $h @('ParentProcessName'))"
  "       Subject=$(Get-Prop $h @('SubjectDomainName'))\$(Get-Prop $h @('SubjectUserName'))  LogonId=$(Get-Prop $h @('SubjectLogonId'))  Elevation=$(Get-Prop $h @('TokenElevationType'))  Integrity=$(Get-Prop $h @('MandatoryLabel'))"
  "       CommandLine=$(Cut (Get-Prop $h @('CommandLine')) $MaxText)"
}
''

$sys1 = @(Get-Records $sysLog 1 | Where-Object { $_.ProviderName -match 'Sysmon' -or (-not $isLocal) })
'--- B) Sysmon Event ID 1 (ProcessCreate) ---'
"count = $($sys1.Count)"
$i = 0
foreach ($ev in $sys1) {
  $h = Expand-EventData $ev
  if (-not $h.ContainsKey('Image')) { continue }
  $i++
  "[B{0:D3}] Utc={1} RecId={2} Computer={3}" -f $i, $ev.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'), $ev.RecordId, $ev.MachineName
  "       ProcessGuid=$(Get-Prop $h @('ProcessGuid'))  PID=$((HexToDec (Get-Prop $h @('ProcessId'))))"
  "       Image=$(Get-Prop $h @('Image'))"
  "       ParentProcessGuid=$(Get-Prop $h @('ParentProcessGuid'))  PPID=$((HexToDec (Get-Prop $h @('ParentProcessId'))))"
  "       ParentImage=$(Get-Prop $h @('ParentImage'))"
  "       User=$(Get-Prop $h @('User'))  LogonId=$(Get-Prop $h @('LogonId'))  Integrity=$(Get-Prop $h @('IntegrityLevel'))"
  "       Hashes=$(Get-Prop $h @('Hashes'))"
  "       CommandLine=$(Cut (Get-Prop $h @('CommandLine')) $MaxText)"
  "       ParentCommandLine=$(Cut (Get-Prop $h @('ParentCommandLine')) $MaxText)"
}
''

$ps4104 = Get-Records $psLog 4104
'--- C) PowerShell Event ID 4104 (ScriptBlockLogging) ---'
"count = $($ps4104.Count)"
$i = 0
foreach ($ev in $ps4104) {
  $h = Expand-EventData $ev; $i++
  $x = [xml]$ev.ToXml()
  $txt = [string](Get-Prop $h @('ScriptBlockText'))
  "[C{0:D3}] Utc={1} RecId={2} Computer={3}" -f $i, $ev.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'), $ev.RecordId, $ev.MachineName
  "       ExecutingPID=$([string]$x.Event.System.Execution.ProcessID)  ScriptBlockId=$(Get-Prop $h @('ScriptBlockId'))  Msg=$(Get-Prop $h @('MessageNumber'))/$(Get-Prop $h @('MessageTotal'))  Path=$(Get-Prop $h @('Path'))"
  "       Len=$($txt.Length)"
  "       Text=$(Cut ($txt -replace '\r?\n',' | ') $MaxText)"
}
''
'### END PHASE7 TELEMETRY COLLECT ###'
