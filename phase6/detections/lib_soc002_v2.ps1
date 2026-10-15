<#
  SOC-002 | Phase 6 | SHARED DETECTION LOGIC  (lib_soc002_v2.ps1)
  ======================================================================
  Phase 6 hardening library for SOC002-DET-001 (encoded PowerShell) and
  SOC002-DET-002 (PowerShell process lineage), plus the correlation layer.

  Design rule
  -----------
  This file contains the DECISION logic only. It has no Windows-only
  dependencies (no Get-WinEvent). The live detectors on SOC002-DC1 and the
  offline replay harness over the preserved Phase 5 evidence both dot-source
  this file and call the SAME functions, so the Phase 6 measurement measures
  the real detection logic and not a re-implementation of it.

  Evidence labels used throughout
  ------------------------------
    OBSERVED     read directly out of a telemetry field
    INFERRED     conclusion drawn from several observations
    NOT VERIFIED not tested / not auditable in this lab

  Classification vocabulary (SOC002-DET-001 v2 output tiers)
  ---------------------------------------------------------
    INVESTIGATION                  encoded PowerShell that is NOT explained by
                                   the narrow baseline. Severity MEDIUM.
                                   Human triage required.
    BASELINE-TRANSPORT-CONFIRMED   narrow baseline matched AND the ancestry was
                                   resolved up to a WinRM host (winrshost.exe /
                                   wsmprovhost.exe). Severity INFO.
    BASELINE-TRANSPORT-PATTERN     narrow baseline matched but the ancestry
                                   could not be resolved from retained
                                   telemetry. Severity LOW. Still recorded and
                                   still available to correlation - never
                                   silently dropped.

  The narrow baseline (BASE-01) is NOT "powershell" and NOT "-EncodedCommand".
  It is: the parent of the encoded PowerShell process is cmd.exe AND that
  cmd.exe command line is the WinRS transport wrapper
  "cmd.exe /C powershell -encodedcommand <b64>", AND the decoded payload
  contains none of the ESC-* high-risk constructs. See TUNING_RATIONALE.txt.
#>

$script:Soc002LibVersion   = 'phase6-v2.0'
$script:Soc002LibFile      = 'lib_soc002_v2.ps1'

# ---------------------------------------------------------------- patterns
# Detection condition: identical to Phase 5 so that DET-001 coverage does not
# silently change between phases.
$script:Soc002EncSwitchRx  = '(?i)\s-(e|en|enc|encodedcommand)(\s|$)'
$script:Soc002B64Rx        = '(?i)-(?:e|en|enc|encodedcommand)\s+"?([A-Za-z0-9+/=]{16,})'
$script:Soc002ImageRx      = '(?i)(powershell|pwsh)\.exe'

# BASE-01 (narrow baseline): WinRS transport wrapper. The parent command line
# must START with cmd.exe, then /C, then optionally powershell[.exe], then an
# encoded-command switch. "cmd.exe /C <anything else>" is not baselined.
$script:Soc002WrapperRx    = '(?i)^\s*"?[^"]*cmd\.exe"?\s+/c\s+("?[^\s"]*powershell(?:\.exe)?"?\s+)?-(e|en|enc|encodedcommand)(\s|$)'

# WinRM-registered host processes observed in this lab's telemetry.
$script:Soc002WinRmHosts   = @('winrshost.exe', 'wsmprovhost.exe')

# ESC-01..08: high-risk constructs looked for inside the DECODED payload of a
# baseline-matched event. These re-open an event as an investigation candidate.
$script:Soc002Escalators = @(
  [pscustomobject]@{ Id='ESC-01'; Desc='in-memory / reflection / AMSI interaction';        Rx='(?i)(reflection\.assembly|loadlibrary|virtualalloc|createthread|\bamsi)' }
  [pscustomobject]@{ Id='ESC-02'; Desc='invoke/execute stage or remote download';           Rx='(?i)(invoke-expression|\biex\b|downloadstring|downloaddata|downloadfile|\bwebclient\b|start-bitstransfer|bitsadmin|invoke-webrequest|\biwr\b)' }
  [pscustomobject]@{ Id='ESC-03'; Desc='second decode layer / encoded blob handling';       Rx='(?i)(frombase64string|frombase64chararray|certutil[^\r\n]{0,40}-decode|convert\]::frombase64)' }
  [pscustomobject]@{ Id='ESC-04'; Desc='execution-policy / AV tampering or hidden window';  Rx='(?i)(set-mppreference|add-mppreference|set-executionpolicy|executionpolicy\s+bypass|windowstyle\s+hidden|-w\s+hidden)' }
  [pscustomobject]@{ Id='ESC-05'; Desc='persistence primitive';                             Rx='(?i)(schtasks|register-scheduledtask|new-service|sc\.exe\s+create|currentversion\\run)' }
  [pscustomobject]@{ Id='ESC-06'; Desc='credential-access tooling / LSASS access';          Rx='(?i)(mimikatz|sekurlsa|lsass|minidump|comsvcs\.dll|procdump)' }
  [pscustomobject]@{ Id='ESC-07'; Desc='account or directory modification';                 Rx='(?i)(net\s+user\s+\S|net\s+localgroup|add-adgroupmember|set-adaccountpassword|dsadd)' }
  [pscustomobject]@{ Id='ESC-08'; Desc='nested encoded command (double encoding)';          Rx='(?i)(-(e|en|enc|encodedcommand)\s+[a-z0-9+/=]{16,})' }
)

# ---------------------------------------------------------------- helpers
function Get-Soc002Field {
  # Records reaching this library come from three adapters (live Sysmon reader,
  # live 4688 reader, Phase 5 evidence reader). They agree on 'Pid'/'Ppid' but
  # older/other spellings are tolerated here rather than silently yielding ''.
  param($Object, [string[]]$Names, $Default = '')
  if ($null -eq $Object) { return $Default }
  # Dictionary-backed records (the live Windows adapters and the process index
  # use hashtables) do NOT expose their keys through PSObject.Properties, so the
  # key path has to be handled explicitly - otherwise every lineage walk against
  # live telemetry would silently stop after the first hop.
  if ($Object -is [System.Collections.IDictionary]) {
    foreach ($n in $Names) { if ($Object.Contains($n)) { $v = $Object[$n]; if ($null -ne $v -and "$v" -ne '') { return $v } } }
    return $Default
  }
  $props = @($Object.PSObject.Properties.Name)
  foreach ($n in $Names) { if ($props -contains $n) { $v = $Object.$n; if ($null -ne $v -and "$v" -ne '') { return $v } } }
  return $Default
}

function Get-Soc002Leaf {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
  $p = $Path.Trim().Trim('"')
  $i = $p.LastIndexOf('\')
  if ($i -ge 0) { return $p.Substring($i + 1).ToLowerInvariant() }
  return $p.ToLowerInvariant()
}

function Get-Soc002LibIdentity {
  # Returns a stable identity block so evidence files can state which library
  # revision produced them.
  $p = Join-Path $PSScriptRoot $script:Soc002LibFile
  $h = ''
  if (Test-Path $p) { $h = (Get-FileHash -Algorithm SHA256 -Path $p).Hash }
  [pscustomobject]@{ LibVersion = $script:Soc002LibVersion; LibFile = $script:Soc002LibFile; LibSha256 = $h }
}

function Test-Soc002EncodedCommandLine {
  param([string]$CommandLine)
  if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $false }
  return ($CommandLine -match $script:Soc002EncSwitchRx)
}

function ConvertFrom-Soc002EncodedCommand {
  # READ-ONLY decode. The decoded text is NEVER executed or invoked by any
  # Phase 6 script - it is only scanned and displayed.
  param([string]$CommandLine, [int]$MaxChars = 4000)
  if ([string]::IsNullOrWhiteSpace($CommandLine)) { return [pscustomobject]@{ Ok=$false; Text=''; Reason='no command line' } }
  if ($CommandLine -notmatch $script:Soc002B64Rx) { return [pscustomobject]@{ Ok=$false; Text=''; Reason='no base64 payload found after the encoded switch' } }
  $b64 = ($matches[1] -replace '\s', '')
  try {
    $bytes = [Convert]::FromBase64String($b64)
    $txt = [Text.Encoding]::Unicode.GetString($bytes)
    if ($txt -match "[^\x09\x0A\x0D\x20-\x7E]") {
      # Not UTF-16LE text - fall back to UTF-8/ASCII so the analyst still sees something.
      $txt = [Text.Encoding]::UTF8.GetString($bytes)
    }
    if ($txt.Length -gt $MaxChars) { $txt = $txt.Substring(0, $MaxChars) + '...[cut]' }
    return [pscustomobject]@{ Ok=$true; Text=$txt; Reason='' }
  } catch {
    return [pscustomobject]@{ Ok=$false; Text=''; Reason='base64 decode failed' }
  }
}

function Get-Soc002EscalationHits {
  param([string]$DecodedText)
  $hits = @()
  if ([string]::IsNullOrWhiteSpace($DecodedText)) { return $hits }
  foreach ($e in $script:Soc002Escalators) {
    if ($DecodedText -match $e.Rx) { $hits += [pscustomobject]@{ Id=$e.Id; Desc=$e.Desc } }
  }
  return $hits
}

function Test-Soc002WinrsWrapper {
  # BASE-01 pattern test on the PARENT command line. Returns rule + detail.
  param([string]$ParentImage, [string]$ParentCommandLine)
  $leaf = Get-Soc002Leaf $ParentImage
  if ($leaf -ne 'cmd.exe') {
    return [pscustomobject]@{ Matched=$false; Rule=''; Detail="parent leaf '$leaf' is not cmd.exe" }
  }
  if ([string]::IsNullOrWhiteSpace($ParentCommandLine)) {
    return [pscustomobject]@{ Matched=$false; Rule=''; Detail='parent command line is empty (cmdl line telemetry not available)' }
  }
  if ($ParentCommandLine -match $script:Soc002WrapperRx) {
    return [pscustomobject]@{ Matched=$true; Rule='BASE-01'; Detail='parent is cmd.exe running the WinRS wrapper "cmd.exe /C powershell -encodedcommand ..."' }
  }
  return [pscustomobject]@{ Matched=$false; Rule=''; Detail='parent is cmd.exe but its command line is not the WinRS encoded-command wrapper' }
}

# ------------------------------------------------------- process index / lineage
function New-Soc002ProcessIndex {
  # Builds a lookup over process-create records.
  #   Returned hashtable keys:
  #     "guid:<computer>|<processguid>" -> record
  #     "pid:<computer>|<decimal pid>"  -> array of records (ascending TimeUtc)
  # A record is any hashtable/object carrying: Computer, TimeUtc, Pid, Ppid,
  # ProcessGuid, ParentGuid, Image, ParentImage, CommandLine, ParentCommandLine.
  param([Parameter(Mandatory=$true)] $Records)
  $idx = @{}
  foreach ($r in @($Records)) {
    if (-not $r) { continue }
    $c = "$($r.Computer)".ToLowerInvariant()
    if ($r.ProcessGuid) {
      $k = "guid:$c|$("$($r.ProcessGuid)".ToLowerInvariant())"
      if (-not $idx.ContainsKey($k)) { $idx[$k] = $r }
    }
    if ($r.Pid) {
      $k = "pid:$c|$($r.Pid)"
      if (-not $idx.ContainsKey($k)) { $idx[$k] = @() }
      $idx[$k] = @($idx[$k]) + $r
    }
  }
  foreach ($k in @($idx.Keys)) {
    if ($k -like 'pid:*') { $idx[$k] = @($idx[$k] | Sort-Object { $_.TimeUtc }) }
  }
  return $idx
}

function Find-Soc002ParentRecord {
  # Resolves the parent PROCESS CREATE record of $Child, using ParentProcessGuid
  # first and a time-filtered PID lookup second. The PID path refuses a
  # candidate whose image does not match the image name the child recorded for
  # its parent - that guard exists because Phase 5 evidence contains at least
  # one PID that is a winrshost.exe early in the window and a cmd.exe later
  # (PID reuse), and a blind PID join would silently mis-attribute the lineage.
  param(
    [Parameter(Mandatory=$true)] $Child,
    [Parameter(Mandatory=$true)] $ProcessIndex,
    [int]$MaxParentAgeMinutes = 720
  )
  $c = "$($Child.Computer)".ToLowerInvariant()
  $want = Get-Soc002Leaf (Get-Soc002Field $Child @('ParentImage'))
  $parentGuid = Get-Soc002Field $Child @('ParentGuid','ParentProcessGuid')
  $parentPid  = Get-Soc002Field $Child @('Ppid','ParentPid','ParentProcessId')

  if ($parentGuid) {
    $k = "guid:$c|$("$parentGuid".ToLowerInvariant())"
    if ($ProcessIndex.ContainsKey($k)) {
      $rec = $ProcessIndex[$k]
      $got = Get-Soc002Leaf $rec.Image
      if ((-not $want) -or ($got -eq $want)) {
        return [pscustomobject]@{ Found=$true; Record=$rec; How='ParentProcessGuid exact match'; Reason='' }
      }
      # fall through to PID path rather than mis-report
    }
  }
  if ($parentPid) {
    $k = "pid:$c|$parentPid"
    if ($ProcessIndex.ContainsKey($k)) {
      $cands = @($ProcessIndex[$k])
      $inTime = @($cands | Where-Object { $_.TimeUtc -le $Child.TimeUtc } | Where-Object { ($Child.TimeUtc - $_.TimeUtc).TotalMinutes -le $MaxParentAgeMinutes })
      if ($inTime.Count -gt 0) {
        $last = $inTime[-1]
        $got = Get-Soc002Leaf $last.Image
        if ((-not $want) -or ($got -eq $want)) {
          return [pscustomobject]@{ Found=$true; Record=$last; How="PID lookup (latest create <= child time; $($inTime.Count) candidate(s))"; Reason='' }
        }
        $match = @($inTime | Where-Object { (Get-Soc002Leaf $_.Image) -eq $want })
        if ($match.Count -gt 0) {
          return [pscustomobject]@{ Found=$true; Record=$match[-1]; How="PID lookup with image-name guard ($($match.Count) of $($inTime.Count) candidate(s) matched)"; Reason='' }
        }
        return [pscustomobject]@{ Found=$false; Record=$null; How=''; Reason="parent PID $parentPid present in telemetry but with a different image (PID reuse or missing parent event)" }
      }
    }
  }
  return [pscustomobject]@{ Found=$false; Record=$null; How=''; Reason='parent process create event not present in the queried window/evidence' }
}

function Resolve-Soc002Lineage {
  # Walks child -> parent -> grandparent ... using (a) fields recorded inside the
  # child's own process-create event and (b) the parent's own process-create
  # event when it is available.
  # Confidence labels:
  #   OBSERVED-CHILD-EVENT   image/cmdline comes from the child's own event
  #   OBSERVED-PARENT-EVENT  the parent's own process-create event was found
  #   NOT-RESOLVED           no telemetry to continue with
  param(
    [Parameter(Mandatory=$true)] $Record,
    $ProcessIndex = @{},
    [int]$MaxDepth = 5,
    [int]$MaxParentAgeMinutes = 720
  )
  $chain  = New-Object System.Collections.ArrayList
  $notes  = New-Object System.Collections.ArrayList
  $null   = $chain.Add([pscustomobject]@{
      Depth=0; Image=$Record.Image; Pid=(Get-Soc002Field $Record @('Pid')); Ppid=(Get-Soc002Field $Record @('Ppid','ParentPid'))
      CommandLine=$Record.CommandLine; RecordId=$Record.RecordId
      Confidence='OBSERVED-CHILD-EVENT'; Source="$($Record.Source)"
  })
  $cur = $Record
  for ($d = 1; $d -le $MaxDepth; $d++) {
    $img  = Get-Soc002Field $cur @('ParentImage')
    $cmd  = Get-Soc002Field $cur @('ParentCommandLine')
    $pid_ = Get-Soc002Field $cur @('Ppid','ParentPid','ParentProcessId')
    if ([string]::IsNullOrWhiteSpace($img) -and [string]::IsNullOrWhiteSpace($pid_)) {
      $null = $notes.Add("depth $d stop: no parent information on the depth $($d-1) record")
      break
    }
    $found = Find-Soc002ParentRecord -Child $cur -ProcessIndex $ProcessIndex -MaxParentAgeMinutes $MaxParentAgeMinutes
    if ($found.Found) {
      $p = $found.Record
      $null = $chain.Add([pscustomobject]@{
          Depth=$d; Image=$p.Image; Pid=$p.Pid; Ppid=$p.Ppid
          CommandLine=$p.CommandLine; RecordId=$p.RecordId
          Confidence='OBSERVED-PARENT-EVENT'; Source="$($p.Source) [$($found.How)]"
      })
      $cur = $p
    } else {
      $null = $chain.Add([pscustomobject]@{
          Depth=$d; Image=$img; Pid=$pid_; Ppid=''
          CommandLine=$cmd; RecordId=''
          Confidence='OBSERVED-CHILD-EVENT'; Source="recorded by the depth $($d-1) event; own process event not available"
      })
      $null = $notes.Add("depth $d lineage stops at '$img' ($($found.Reason))")
      break
    }
  }
  $hops = @($chain)
  $winRmDepths = @($hops | Where-Object { (Get-Soc002Leaf $_.Image) -in $script:Soc002WinRmHosts } | ForEach-Object { $_.Depth })
  $hasWinRm = ($winRmDepths.Count -gt 0)
  $parentCmd = ($(if ($hops.Count -gt 1) { (Get-Soc002Leaf $hops[1].Image) -eq 'cmd.exe' } else { $false }))
  $grandWinRm = ($(if ($hops.Count -gt 2) { (Get-Soc002Leaf $hops[2].Image) -in $script:Soc002WinRmHosts } else { $false }))
  $resolvedToRoot = ($hops | Where-Object { $_.Confidence -eq 'OBSERVED-CHILD-EVENT' -and $_.Depth -ge 1 }).Count -eq 0
  return [pscustomobject]@{
    Chain            = $hops
    DepthResolved    = $hops.Count - 1
    HasWinRmHost     = $hasWinRm
    WinRmHostDepths  = $winRmDepths
    ParentIsCmd      = $parentCmd
    GrandparentIsWinRm = $grandWinRm
    ShapeObserved    = ($parentCmd -and $grandWinRm)      # the LINEAGE-SHAPE seen in Phase 5
    FullChainResolved= $resolvedToRoot
    Notes            = @($notes)
  }
}

function Format-Soc002Chain {
  param($Lineage)
  if (-not $Lineage) { return '(lineage not computed)' }
  $hops = @($Lineage.Chain)
  $s = @()
  for ($i = 0; $i -lt $hops.Count; $i++) {
    $h = $hops[$i]
    $s += ("{0}({1})" -f (Get-Soc002Leaf $h.Image), $(if ($h.Pid) { $h.Pid } else { '?' }))
  }
  $shape = $s -join ' <- '
  $src = @()
  foreach ($h in $hops) { $src += ("depth {0}: {1} [{2}]" -f $h.Depth, (Get-Soc002Leaf $h.Image), $h.Confidence) }
  return @{ Shape = $shape; Sources = $src }
}

# ------------------------------------------------------------- DET-001 verdict
function Get-Soc002Det001Verdict {
  # Returns the Phase 6 classification for one encoded-PowerShell candidate.
  param(
    [Parameter(Mandatory=$true)] $Record,
    $Lineage = $null,
    [string]$DecodedText = '',
    [bool]$DecodeOk = $false,
    $Escalations = @(),
    [switch]$DecodeTruncated
  )
  $reasons = New-Object System.Collections.ArrayList
  $notes   = New-Object System.Collections.ArrayList
  $wrap    = Test-Soc002WinrsWrapper -ParentImage $Record.ParentImage -ParentCommandLine $Record.ParentCommandLine
  $esc     = @($Escalations)
  $tier    = 'INVESTIGATION'
  $severity= 'MEDIUM'
  $rule    = ''

  if ($wrap.Matched -and $esc.Count -eq 0) {
    $rule = 'BASE-01'
    $null = $reasons.Add('BASE-01 matched: parent is cmd.exe running the WinRS encoded-command wrapper')
    if (-not $DecodeOk) {
      # The transport pattern is met, but the fail-safe payload screen could not
      # run. The event is therefore capped at the WEAKER tier and the blind spot
      # is printed rather than hidden.
      $tier = 'BASELINE-TRANSPORT-PATTERN'; $severity = 'LOW'
      $null = $reasons.Add('baseline capped at PATTERN: the payload screen could NOT run for this instance')
    } elseif ($Lineage -and $Lineage.ShapeObserved) {
      $tier = 'BASELINE-TRANSPORT-CONFIRMED'; $severity = 'INFO'
      $null = $reasons.Add("ancestry resolved: parent cmd.exe's parent is a WinRM host (" + (Format-Soc002Chain $Lineage).Shape + ")")
      $null = $reasons.Add('payload screen: no ESC-* high-risk construct found in the decoded text')
    } else {
      $tier = 'BASELINE-TRANSPORT-PATTERN'; $severity = 'LOW'
      $null = $reasons.Add('ancestry NOT resolved from the available telemetry - the cmd.exe parent event is missing, so the WinRM host hop is NOT VERIFIED for this instance')
      $null = $reasons.Add('payload screen: no ESC-* high-risk construct found in the decoded text')
    }
  } else {
    if (-not $wrap.Matched) { $null = $reasons.Add("not baselined: $($wrap.Detail)") }
    if ($esc.Count -gt 0) {
      $null = $reasons.Add('BASE-01 OVERRIDDEN by payload escalation: ' + (($esc | ForEach-Object { $_.Id }) -join ','))
    }
  }
  if ($esc.Count -gt 0 -and $wrap.Matched) { $tier = 'INVESTIGATION'; $severity = 'MEDIUM'; $rule = 'BASE-01 overridden' }

  if (-not $DecodeOk) { $null = $notes.Add('payload could not be decoded - the ESC-* screen did NOT run for this instance (NOT VERIFIED)') }
  if ($DecodeTruncated) { $null = $notes.Add('decoded text was truncated before screening - an ESC-* construct could exist beyond the visible text (NOT VERIFIED)') }
  if ($Lineage -and -not $Lineage.ShapeObserved) { $null = $notes.Add("retained also because the lineage does NOT match the shape BASE-01 baselines; observed chain: " + (Format-Soc002Chain $Lineage).Shape) }

  return [pscustomobject]@{
    Detection   = 'SOC002-DET-001'
    Tier        = $tier
    Severity    = $severity
    Rule        = $rule
    WrapDetail  = $wrap.Detail
    Escalations = $esc
    PayloadScreened = $DecodeOk
    Reasons     = @($reasons)
    Notes       = @($notes)
    Lineage     = $Lineage
  }
}

# ------------------------------------------------------- DET-002 lineage record
function Get-Soc002Det002LineageRecord {
  # SOC002-DET-002 - PowerShell process lineage (context, not accusation).
  # Fires when a PowerShell process was delivered through a WinRM host process,
  # i.e. the lineage observed in Phase 5:
  #     winrshost.exe -> cmd.exe -> powershell.exe
  # TRUST CALL: winrshost.exe is the authorised management channel in this lab.
  # This detection therefore asserts CONTEXT ONLY and never a verdict.
  param(
    [Parameter(Mandatory=$true)] $Record,
    [Parameter(Mandatory=$true)] $Lineage
  )
  $shape = (Format-Soc002Chain $Lineage)
  return [pscustomobject]@{
    Detection      = 'SOC002-DET-002'
    Host           = $Record.Computer
    TimeUtc        = $Record.TimeUtc
    Pid            = $Record.Pid
    Image          = $Record.Image
    CommandLine    = $Record.CommandLine
    User           = $Record.User
    LogonId        = $Record.LogonId
    SysmonRecordId = $Record.RecordId
    ProcessGuid    = $Record.ProcessGuid
    Chain          = $Lineage.Chain
    ChainShape     = $shape.Shape
    ShapeObserved  = $Lineage.ShapeObserved
    WinRmHostLeaf  = ((@($Lineage.Chain | Where-Object { (Get-Soc002Leaf $_.Image) -in $script:Soc002WinRmHosts }))[0].Image)
    Encoded        = $(if (Test-Soc002EncodedCommandLine -CommandLine $Record.CommandLine) { 'present' }
                        elseif (([string]$Record.CommandLine) -match '\.\.\.\[cut\]') { 'not determinable - the preserved command line was truncated before the switch' }
                        else { 'absent' })
    Severity       = 'CONTEXT'
    Meaning        = 'execution was delivered through a WinRM host process'
    TrustCall      = 'winrshost.exe / wsmprovhost.exe is the SANCTIONED administration channel in this lab - this record is context, NOT evidence of maliciousness'
    Limits         = @(
      'This detection is about HOW a process was created, not about WHAT it did.',
      'A WinRM-rooted lineage is expected for all operator activity, including this lab''s own data collection.',
      'Lineage depth depends on the surviving process events: a missing parent event truncates the chain silently.'
    )
  }
}

# ----------------------------------------------------------- correlation layer
function Get-Soc002Correlation {
  # Joins SOC002-DET-001 (encoded PowerShell) with SOC002-DET-002 (lineage) on
  # host + process id. The result is investigation CONTEXT, never a verdict.
  param(
    [Parameter(Mandatory=$true)] $Det001Verdict,
    [Parameter(Mandatory=$true)] $Record,
    $Det002Record = $null
  )
  $lineageText = '-'
  $lineageShape = 'NOT-RESOLVED'
  if ($Det002Record) { $lineageShape = $Det002Record.ChainShape }
  elseif ($Det001Verdict.Lineage) { $lineageShape = (Format-Soc002Chain $Det001Verdict.Lineage).Shape }

  $narrative = New-Object System.Collections.ArrayList
  if ($Det001Verdict.Tier -eq 'INVESTIGATION') {
    $null = $narrative.Add('single signal: encoded PowerShell execution NOT explained by the narrow baseline')
  } else {
    $null = $narrative.Add("single signal: encoded PowerShell execution that matches the narrow baseline ($($Det001Verdict.Tier))")
  }
  if ($Det002Record) {
    $null = $narrative.Add("lineage context: delivered by a WinRM host process ($lineageShape)")
    $null = $narrative.Add('combined reading: remote/interactive administration context, consistent with the sanctioned WinRM management path; authorisation of the operator and the payload content still decide the verdict')
  } else {
    $null = $narrative.Add('lineage context: NOT AVAILABLE - the encoded execution could not be tied to a resolved process chain')
    $null = $narrative.Add('combined reading: LESS context than with lineage, therefore lower confidence and higher triage priority - the missing hop is itself an investigative gap')
  }
  if (@($Det001Verdict.Escalations).Count -gt 0) {
    $null = $narrative.Add('payload escalation: ' + (($Det001Verdict.Escalations | ForEach-Object { "$($_.Id) $($_.Desc)" }) -join '; '))
  }
  return [pscustomobject]@{
    CorrelationId = ("CORR-{0}-{1}-{2}" -f $Record.Computer.Split('.')[0].ToUpperInvariant(), $Record.Pid, $Record.TimeUtc.ToString('yyyyMMddTHHmmssZ'))
    Host          = $Record.Computer
    TimeUtc       = $Record.TimeUtc
    Pid           = $Record.Pid
    ProcessGuid   = $Record.ProcessGuid
    User          = $Record.User
    Det001Tier    = $Det001Verdict.Tier
    Det001Severity= $Det001Verdict.Severity
    Det001Rule    = $Det001Verdict.Rule
    Det002Present = [bool]$Det002Record
    LineageShape  = $lineageShape
    Escalations   = @($Det001Verdict.Escalations)
    Narrative     = @($narrative)
    Statement     = 'CORRELATION IS CONTEXT, NOT A VERDICT. Det-001 + Det-002 agreeing does not make this a compromise; it means the analyst gets the "what" and the "how" in one view.'
  }
}

# ------------------------------------------------------------------ reporting
function New-Soc002Stats {
  [pscustomobject]@{
    Candidates                 = 0
    InvestigationRetained      = 0
    BaselineConfirmed          = 0
    BaselinePatternUnconfirmed = 0
    EscalatedByPayload         = 0
    BaselineRetainedForCorr    = 0
  }
}

function Get-Soc002StatSummary {
  param($Stats)
  return @{
    Candidates                      = $Stats.Candidates
    RetainedInvestigationCandidates = $Stats.InvestigationRetained
    BaselineConfirmedWinRMAncestry  = $Stats.BaselineConfirmed
    BaselinePatternLineageMissing   = $Stats.BaselinePatternUnconfirmed
    SuppressedByNarrowBaseline      = ($Stats.BaselineConfirmed + $Stats.BaselinePatternUnconfirmed)
    EscalatedByPayloadScreen        = $Stats.EscalatedByPayload
  }
}

function Format-Soc002Det001Alert {
  # Full ALERT block - emitted only for retained investigation candidates.
  param(
    [Parameter(Mandatory=$true)] $Record,
    [Parameter(Mandatory=$true)] $Verdict,
    $Corroboration = @(),
    [int]$Index = 1,
    [int]$MaxText = 400,
    [switch]$CompactLineage
  )
  $sb = New-Object System.Text.StringBuilder
  $null = $sb.AppendLine('')
  $null = $sb.AppendLine(("[ALERT {0:D3}] Encoded PowerShell execution observed - INVESTIGATION REQUIRED" -f $Index))
  $null = $sb.AppendLine(("  Detection        = SOC002-DET-001 v2  tier={0} severity={1}" -f $Verdict.Tier, $Verdict.Severity))
  $null = $sb.AppendLine(("  Why retained     = {0}" -f ($Verdict.Reasons -join ' | ')))
  $null = $sb.AppendLine(("  Host             = {0}" -f $Record.Computer))
  $null = $sb.AppendLine(("  User             = {0}   LogonId={1}" -f $Record.User, $Record.LogonId))
  $null = $sb.AppendLine(("  EventUtc         = {0}" -f $Record.TimeUtc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')))
  $null = $sb.AppendLine(("  RecordId/Source  = {0} / {1}" -f $Record.RecordId, $Record.Source))
  $null = $sb.AppendLine(("  ProcessGuid      = {0}" -f $Record.ProcessGuid))
  $null = $sb.AppendLine(("  Process          = {0}   (PID {1})" -f $Record.Image, (Get-Soc002Field $Record @('Pid'))))
  $null = $sb.AppendLine(("  Parent           = {0}  (PPID {1})" -f $Record.ParentImage, (Get-Soc002Field $Record @('Ppid','ParentPid','ParentProcessId'))))
  $null = $sb.AppendLine(("  ParentCommandLine= {0}" -f $Record.ParentCommandLine))
  if ($Record.Hashes) { $null = $sb.AppendLine(("  Hashes           = {0}" -f $Record.Hashes)) }
  $null = $sb.AppendLine(("  CommandLine      = {0}" -f $Record.CommandLine))
  if ($Record.DecodedText) { $null = $sb.AppendLine(("  DecodedScript    = <<<{0}>>>  [decoded by detection - NOT executed]" -f $Record.DecodedText)) }
  if ($Record.DecodeOk -eq $false) { $null = $sb.AppendLine(("  DecodedScript    = <not decoded: {0}>" -f $Record.DecodeReason)) }
  if ($Verdict.Lineage) {
    $f = Format-Soc002Chain $Verdict.Lineage
    $null = $sb.AppendLine(("  Lineage          = {0}" -f $f.Shape))
    foreach ($s in $f.Sources) { $null = $sb.AppendLine(("                     {0}" -f $s)) }
  } else {
    $null = $sb.AppendLine('  Lineage          = NOT COMPUTED')
  }
  foreach ($c in @($Corroboration)) {
    $null = $sb.AppendLine(("  Corroboration    = PowerShell 4104 RecId={0} ExecPID={1} ScriptBlockId={2} Msg={3}/{4}" -f $c.RecordId, $c.ExecPid, $c.ScriptBlockId, $c.MessageNumber, $c.MessageTotal))
    if ($c.Text) { $null = $sb.AppendLine(("                     4104Text={0}" -f $c.Text)) }
  }
  if (@($Corroboration).Count -eq 0) { $null = $sb.AppendLine('  Corroboration    = NONE FOUND (4104 missing / not forwarded - see t7 failure modes)') }
  foreach ($n in @($Verdict.Notes)) { $null = $sb.AppendLine(("  Note             = {0}" -f $n)) }
  return $sb.ToString().TrimEnd()
}

function Format-Soc002Det001Baseline {
  # One-line record for an event suppressed by the narrow baseline. Never
  # dropped: it stays visible, stays available to correlation, and carries the
  # reason it was baselined.
  param([Parameter(Mandatory=$true)] $Record, [Parameter(Mandatory=$true)] $Verdict, [int]$Index = 1)
  $shape = '-'
  if ($Verdict.Lineage) { $shape = (Format-Soc002Chain $Verdict.Lineage).Shape }
  # Auditable one-liner: host, decision, process ids, the starting time and the
  # telemetry record id are all present so a reviewer can join this line back to
  # the source event (and to a Phase 5 alert) without re-running the query.
  $utc = Get-Soc002Field $Record @('TimeUtc','EventUtc')
  if ($utc) { $utc = ([datetime]$utc).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }
  return ("[BASE {0:D3}] rec={1} utc={2} {3} tier={4} sev={5} pid={6} parent={7}({8}) lineage={9} rule={10} payload={11}" -f `
      $Index, (Get-Soc002Field $Record @('RecordId')), $utc, $Record.Computer, $Verdict.Tier, $Verdict.Severity, (Get-Soc002Field $Record @('Pid')), `
      (Get-Soc002Leaf (Get-Soc002Field $Record @('ParentImage'))), (Get-Soc002Field $Record @('Ppid','ParentPid','ParentProcessId')), `
      $shape, $Verdict.Rule, $Verdict.PayloadScreened)
}

function Format-Soc002Det002 {
  param([Parameter(Mandatory=$true)] $LineageRecord, [int]$Index = 1)
  $sb = New-Object System.Text.StringBuilder
  $null = $sb.AppendLine('')
  $null = $sb.AppendLine(("[LINEAGE {0:D3}] SOC002-DET-002 PowerShell delivered through a WinRM host process - CONTEXT ONLY" -f $Index))
  $null = $sb.AppendLine(("  Host             = {0}" -f $LineageRecord.Host))
  $null = $sb.AppendLine(("  EventUtc         = {0}" -f $LineageRecord.TimeUtc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')))
  $null = $sb.AppendLine(("  Process          = {0}   (PID {1})" -f $LineageRecord.Image, $LineageRecord.Pid))
  $null = $sb.AppendLine(("  User             = {0}   LogonId={1}" -f $LineageRecord.User, $LineageRecord.LogonId))
  $null = $sb.AppendLine(("  Chain            = {0}" -f $LineageRecord.ChainShape))
  $null = $sb.AppendLine(("  Chain hops       = {0}" -f (($LineageRecord.Chain | ForEach-Object { "d$($_.Depth):$(Get-Soc002Leaf $_.Image)[$($_.Confidence)]" }) -join ' ')))
  $null = $sb.AppendLine(("  Shape LIN-01     = {0}   (winrshost.exe -> cmd.exe -> powershell.exe is the Phase 5 OBSERVED shape)" -f $(if ($LineageRecord.ShapeObserved) { 'MATCHED' } else { 'not matched' })))
  $null = $sb.AppendLine(("  Encoded switch   = {0}" -f $LineageRecord.Encoded))
  $null = $sb.AppendLine(("  Meaning          = {0} (INFERRED from the chain)" -f $LineageRecord.Meaning))
  $null = $sb.AppendLine(("  Trust call       = {0}" -f $LineageRecord.TrustCall))
  foreach ($l in $LineageRecord.Limits) { $null = $sb.AppendLine(("  Limit            = {0}" -f $l)) }
  return $sb.ToString().TrimEnd()
}

function Format-Soc002Correlation {
  param([Parameter(Mandatory=$true)] $Corr, [int]$Index = 1)
  $sb = New-Object System.Text.StringBuilder
  $null = $sb.AppendLine('')
  $null = $sb.AppendLine(("[CORRELATION {0:D3}] {1}" -f $Index, $Corr.CorrelationId))
  $null = $sb.AppendLine(("  Host/Process     = {0}  PID {1}  {2}" -f $Corr.Host, $Corr.Pid, $Corr.ProcessGuid))
  $null = $sb.AppendLine(("  EventUtc         = {0}" -f $Corr.TimeUtc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')))
  $null = $sb.AppendLine(("  User             = {0}" -f $Corr.User))
  $null = $sb.AppendLine(("  DET-001          = tier={0} severity={1} rule={2}" -f $Corr.Det001Tier, $Corr.Det001Severity, $Corr.Det001Rule))
  $null = $sb.AppendLine(("  DET-002          = {0} (lineage {1})" -f $(if ($Corr.Det002Present) { 'lineage record present' } else { 'NO lineage record' }), $Corr.LineageShape))
  foreach ($n in $Corr.Narrative) { $null = $sb.AppendLine(("  Reading          = {0}" -f $n)) }
  $null = $sb.AppendLine(("  REMINDER         = {0}" -f $Corr.Statement))
  return $sb.ToString().TrimEnd()
}

# ------------------------------------------------------------ single pipeline
function Invoke-Soc002Assessment {
  # The ONE assessment pipeline used by
  #   - the live detector on SOC002-DC1 (detect_encoded_powershell_v2.ps1)
  #   - the live correlation script (correlate_det001_det002.ps1)
  #   - the offline replay harness over the preserved Phase 5 evidence
  # Keeping it in one function is what makes the replay a measurement of the
  # real detection rather than of a lookalike.
  param(
    [Parameter(Mandatory=$true)] $Candidates,
    $ProcessIndex = @{},
    [int]$MaxDecodeChars = 4000,
    [switch]$NoLineage
  )
  $out = New-Object System.Collections.ArrayList
  foreach ($rec in @($Candidates)) {
    # Payload source: normally the live command line is decoded here. A
    # pre-decoded payload may be supplied on the record (PayloadText /
    # PayloadSource) - the replay harness uses this for the payload text that
    # Phase 5 preserved, and labels it so the evidence never overstates what was
    # screened.
    $presupplied = ($rec.PSObject.Properties.Name -contains 'PayloadText') -and -not [string]::IsNullOrWhiteSpace([string]$rec.PayloadText)
    if ($presupplied) {
      $dec = [pscustomobject]@{ Ok=$true; Text=[string]$rec.PayloadText; Reason='' }
      $payloadSource = [string]$rec.PayloadSource
    } else {
      $dec = ConvertFrom-Soc002EncodedCommand -CommandLine $rec.CommandLine -MaxChars $MaxDecodeChars
      $payloadSource = 'live command line (decoded by this detection, never executed)'
      if (-not $dec.Ok -and ([string]$rec.CommandLine) -match '\.\.\.\[cut\]') {
        $dec = [pscustomobject]@{ Ok=$false; Text=''; Reason='candidate command line was truncated in the source evidence, so the base64 payload could not be decoded (payload screen NOT VERIFIED for this instance)' }
      }
    }
    $truncated = (([string]$dec.Text).EndsWith('...[cut]'))
    $esc = @(Get-Soc002EscalationHits -DecodedText $dec.Text)
    $lineage = $null
    if (-not $NoLineage) { $lineage = Resolve-Soc002Lineage -Record $rec -ProcessIndex $ProcessIndex }
    $verdict = Get-Soc002Det001Verdict -Record $rec -Lineage $lineage -DecodedText $dec.Text -DecodeOk $dec.Ok -Escalations $esc -DecodeTruncated:$truncated
    $r2 = $rec
    $r2 = $r2 | Add-Member -NotePropertyName DecodedText  -NotePropertyValue $dec.Text   -PassThru -Force
    $r2 = $r2 | Add-Member -NotePropertyName DecodeOk     -NotePropertyValue $dec.Ok     -PassThru -Force
    $r2 = $r2 | Add-Member -NotePropertyName DecodeReason -NotePropertyValue $dec.Reason -PassThru -Force
    $r2 = $r2 | Add-Member -NotePropertyName PayloadSource -NotePropertyValue $payloadSource -PassThru -Force
    $det002 = $null
    if ($lineage -and $lineage.HasWinRmHost) { $det002 = Get-Soc002Det002LineageRecord -Record $r2 -Lineage $lineage }
    $corr = Get-Soc002Correlation -Det001Verdict $verdict -Record $r2 -Det002Record $det002
    $null = $out.Add([pscustomobject]@{
      Record    = $r2
      Verdict   = $verdict
      Lineage   = $lineage
      Det002    = $det002
      Corr      = $corr
      Decoded   = $dec.Text
      DecodeOk  = $dec.Ok
      PayloadSource = $payloadSource
      Escalations = $esc
      Truncated = $truncated
    })
  }
  return @($out)
}
