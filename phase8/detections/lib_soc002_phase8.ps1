<#
  SOC-002 | PHASE 8 | SHARED DECISION LOGIC  (lib_soc002_phase8.ps1)
  ======================================================================
  SOC002-DET-003  -  PowerShell Base64 Reconstruction / Decode Behaviour

  This file contains the DECISION logic only. It has no Windows-only
  dependencies (no Get-WinEvent). The live detector on SOC002-DC1 and the
  offline replay harness over the preserved Phase 7 evidence both dot-source
  this file and call the SAME functions, so the replay measures the real
  detection and not a re-implementation of it. (Same design rule as Phase 6.)

  WHY THIS DETECTION EXISTS
  -------------------------
  Phase 7 (SOC002-CASE-0002) experimentally confirmed that DET-001 v2's trigger
  is the encoded-command CLI SWITCH (-EncodedCommand / -enc / -e / -en). A
  PowerShell process that instead reconstructs data with

      -Command "[Convert]::FromBase64String(...)"

  is fully visible in Security 4688, Sysmon Event 1, PowerShell 4104 and DC1
  ForwardedEvents, yet never becomes a DET-001 candidate. DET-003 closes that
  gap as a SEPARATE detection. DET-001 v2 is not touched or extended.

  TRIGGER CONDITIONS (exact)
  --------------------------
  A telemetry record is a DET-003 candidate when its observed PowerShell text
  (Sysmon Event 1 CommandLine, Security 4688 CommandLine, or PowerShell 4104
  ScriptBlockText) contains a .NET Base64 RECONSTRUCTION CALL:

      REC-01  [Convert]::FromBase64String            (type accelerator, decode)
      REC-02  [System.Convert]::FromBase64String     (fully-qualified, decode)
      REC-03  FromBase64String(                      (unqualified call form)
      REC-04  FromBase64CharArray(                   (unqualified call form)
      REC-05  [Convert]::FromBase64CharArray         (type accelerator / fq)

  WHY THE CALL AND NOT THE WORD
  -----------------------------
  The trigger keys on the DECODE API, never on the literal word "Base64".
  "Base64" alone (a comment, a help string, a variable name, a file name,
  a -Base64 parameter name that is not a decode call) does NOT trigger. That
  is the difference between this detector and a naive keyword rule; the benign
  comparison suite in phase8/evidence measures exactly that difference.

  WHY THESE INDICATORS
  --------------------
  FromBase64String / FromBase64CharArray are the .NET APIs that turn an
  attacker-supplied blob back into bytes/text without any EncodedCommand
  switch. They are the minimal, stable, unambiguous surface of "base64
  reconstruction" in PowerShell. Selecting the call form (not the word) keeps
  precision; selecting the two decode methods keeps coverage of the realistic
  reconstruction variants while staying auditable.

  COMMENT SUPPRESSION
  -------------------
  A reconstruction call that appears only inside a comment (# line comment or
  block comment) is NOT a trigger. It is recorded as COMMENT-MENTION so
  the suppression is visible in the output rather than silent.

  CONTEXT (computed, never a trigger by itself)
  ---------------------------------------------
  CTX-EXEC-ADJACENT     an execution/loader primitive co-occurs with the decode
                        (Invoke-Expression / iex / Start-Process / Add-Type /
                        dot-source / call operator). Raises severity to MEDIUM.
  CTX-STRING-ROUNDTRIP  the decoded bytes are turned back into a string
                        ([Text.Encoding]::UTF8.GetString / GetString).
  CTX-REMOTE-RETRIEVAL  a network retrieval primitive co-occurs
                        (DownloadString / WebClient / Invoke-WebRequest / iwr /
                        Start-BitsTransfer). Raises severity to MEDIUM.
  CTX-PLUMBING          the record looks like in-lab file-transfer / staging
                        plumbing ([IO.File]::* together with the decode call).
                        This is a DOCUMENTED false-positive source: the lab's
                        own operator tooling uses [Convert]::FromBase64String to
                        move files over WinRM. It is reported, never hidden.

  SEVERITY / CLASS
  ----------------
  LOW     reconstruction observed, no execution/retrieval adjacency.
          Class = RECONSTRUCTION-OBSERVED
  MEDIUM  reconstruction observed with execution/retrieval adjacency.
          Class = RECONSTRUCTION-WITH-EXECUTION-ADJACENT

  WHAT THIS DETECTION DOES NOT DO
  -------------------------------
  It never executes, invokes, evaluates or decodes-and-runs anything. It only
  reads text and matches a pattern. It never asserts maliciousness: decoding
  base64 is a normal, everyday operation, and this detection says "reconstruction
  was observed, here is the context" - not "this host is compromised".
#>

$script:Soc002P8LibVersion = 'phase8-v1.0'
$script:Soc002P8LibFile    = 'lib_soc002_phase8.ps1'

# --- trigger pattern: the decode CALL, with an optional [Convert] / [System.Convert] prefix
$script:Soc002P8CallRx = '(?i)(?<prefix>\[\s*(?<type>system\.)?convert\s*\]\s*::\s*)?(?<method>frombase64string|frombase64chararray)\s*\('
# --- the literal word, used ONLY to explain a non-trigger (never to trigger)
$script:Soc002P8WordRx = '(?i)base64'
# --- context patterns (never triggers)
$script:Soc002P8CtxExecRx    = '(?i)(\biex\b|invoke-expression|start-process|add-type|invoke-command|&\s*[\(\$]|\.\s*\(\s*[A-Za-z_]|\|\s*iex)'
$script:Soc002P8CtxStringRx  = '(?i)(\[\s*(?:system\.)?text\.encoding\s*\]|getstring\s*\(|utf8|ascii|unicode)'
$script:Soc002P8CtxRemoteRx  = '(?i)(downloadstring|downloaddata|downloadfile|\bwebclient\b|invoke-webrequest|\biwr\b|start-bitstransfer|bitsadmin)'
$script:Soc002P8CtxPlumbingRx= '(?i)(\[\s*io\.file\s*\]|set-content|out-file|add-content|writeallbytes|writealltext|appendalltext|readalltext|readallbytes)'

$script:Soc002P8IndicatorLabels = @{
  'REC-01' = '[Convert]::FromBase64String'
  'REC-02' = '[System.Convert]::FromBase64String'
  'REC-03' = 'FromBase64String('
  'REC-04' = 'FromBase64CharArray('
  'REC-05' = '[Convert]::FromBase64CharArray'
}

function Get-Soc002P8LibIdentity {
  $p = Join-Path $PSScriptRoot $script:Soc002P8LibFile
  $h = ''
  if (Test-Path $p) { $h = (Get-FileHash -Algorithm SHA256 -Path $p).Hash }
  [pscustomobject]@{ LibVersion = $script:Soc002P8LibVersion; LibFile = $script:Soc002P8LibFile; LibSha256 = $h }
}

function Remove-Soc002P8Comments {
  # Returns a string of the SAME LENGTH as the input with comment text blanked
  # to spaces, so match offsets map straight back onto the original text.
  # Handles: # line comments, brace-delimited block comment (< hash ... hash >)s, single-quoted strings
  # ('with '' escape'), double-quoted strings ("with ` escape").
  # LIMITATION: here-strings (@' ... '@ / @" ... "@) are NOT specially handled;
  # see phase8/evidence/t13_limitations.txt.
  param([string]$Text)
  if ([string]::IsNullOrEmpty($Text)) { return $Text }
  $chars = $Text.ToCharArray()
  $n = $chars.Length
  $i = 0
  $inSingle = $false; $inDouble = $false
  while ($i -lt $n) {
    $c = $chars[$i]
    if ($inSingle) {
      if ($c -eq "'") {
        if (($i + 1) -lt $n -and $chars[$i + 1] -eq "'") { $i += 2; continue }
        $inSingle = $false; $i++; continue
      }
      $i++; continue
    }
    if ($inDouble) {
      if ($c -eq '`') { $i += 2; continue }
      if ($c -eq '"') { $inDouble = $false; $i++; continue }
      $i++; continue
    }
    if ($c -eq "'") { $inSingle = $true; $i++; continue }
    if ($c -eq '"') { $inDouble = $true; $i++; continue }
    if ($c -eq '<' -and ($i + 1) -lt $n -and $chars[$i + 1] -eq '#') {
      $j = $Text.IndexOf('#>', $i + 2)
      if ($j -lt 0) { for ($k = $i; $k -lt $n; $k++) { $chars[$k] = ' ' }; $i = $n; continue }
      for ($k = $i; $k -le ($j + 1); $k++) { if ($chars[$k] -ne "`n" -and $chars[$k] -ne "`r") { $chars[$k] = ' ' } }
      $i = $j + 2; continue
    }
    if ($c -eq '#') { $j = $i; while ($j -lt $n -and $chars[$j] -ne "`n") { $chars[$j] = ' '; $j++ }; $i = $j; continue }
    $i++
  }
  return (-join $chars)
}

function Get-Soc002P8Base64Indicators {
  # All reconstruction-call occurrences in $Text, each classified as code or
  # comment. Returns a flat array of occurrence objects.
  param([string]$Text, [int]$SnippetChars = 48)
  $hits = New-Object System.Collections.ArrayList
  if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
  $stripped = Remove-Soc002P8Comments -Text $Text
  foreach ($m in [regex]::Matches($Text, $script:Soc002P8CallRx)) {
    $hasPrefix = $m.Groups['prefix'].Success
    $isSystem  = ($m.Groups['type'].Value -ne '')
    $method    = $m.Groups['method'].Value.ToLowerInvariant()
    if ($method -eq 'frombase64string') {
      if ($hasPrefix) { $id = $(if ($isSystem) { 'REC-02' } else { 'REC-01' }) } else { $id = 'REC-03' }
    } else {
      if ($hasPrefix) { $id = 'REC-05' } else { $id = 'REC-04' }
    }
    $slice = $stripped.Substring($m.Index, $m.Length)
    $inComment = (-not ($slice -match '\S'))
    $start = [Math]::Max(0, $m.Index - 12)
    $len   = [Math]::Min($SnippetChars, $Text.Length - $start)
    $snip  = ($Text.Substring($start, $len) -replace '\r?\n', ' ')
    $null = $hits.Add([pscustomobject]@{
      Id        = $id
      Label     = $script:Soc002P8IndicatorLabels[$id]
      Index     = $m.Index
      Text      = $m.Value
      InComment = $inComment
      Snippet   = $snip
    })
  }
  return @($hits)
}

function Get-Soc002P8Context {
  # Context flags computed on the comment-stripped text. These NEVER trigger the
  # detection on their own; they only shape severity and the investigation note.
  param([string]$Text)
  $code = Remove-Soc002P8Comments -Text $Text
  $flags = New-Object System.Collections.ArrayList
  if ([string]::IsNullOrWhiteSpace($code)) { return @() }
  if ($code -match $script:Soc002P8CtxExecRx)     { $null = $flags.Add([pscustomobject]@{ Id='CTX-EXEC-ADJACENT';    Desc='execution/loader primitive co-occurs with the decode (INFERRED from text only)' }) }
  if ($code -match $script:Soc002P8CtxStringRx)   { $null = $flags.Add([pscustomobject]@{ Id='CTX-STRING-ROUNDTRIP'; Desc='decoded bytes are turned back into a string' }) }
  if ($code -match $script:Soc002P8CtxRemoteRx)   { $null = $flags.Add([pscustomobject]@{ Id='CTX-REMOTE-RETRIEVAL'; Desc='network retrieval primitive co-occurs with the decode' }) }
  if ($code -match $script:Soc002P8CtxPlumbingRx) { $null = $flags.Add([pscustomobject]@{ Id='CTX-PLUMBING';         Desc='looks like in-lab file-transfer/staging plumbing ([IO.File]::* + decode) - a DOCUMENTED false-positive source' }) }
  return @($flags)
}

function Test-Soc002P8Base64Reconstruction {
  # The DET-003 trigger decision for ONE piece of text.
  param([string]$Text, [int]$SnippetChars = 48)
  $occ = @(Get-Soc002P8Base64Indicators -Text $Text -SnippetChars $SnippetChars)
  $code = @($occ | Where-Object { -not $_.InComment })
  $commentOnly = @($occ | Where-Object { $_.InComment })
  $ctx = @(Get-Soc002P8Context -Text $Text)
  $wordCount = 0
  if (-not [string]::IsNullOrWhiteSpace($Text)) { $wordCount = ([regex]::Matches($Text, $script:Soc002P8WordRx)).Count }
  $triggered = ($code.Count -gt 0)
  $sev = 'LOW'
  $cls = 'RECONSTRUCTION-OBSERVED'
  $ctxIds = @($ctx | ForEach-Object { $_.Id })
  if ($triggered -and (($ctxIds -contains 'CTX-EXEC-ADJACENT') -or ($ctxIds -contains 'CTX-REMOTE-RETRIEVAL'))) {
    $sev = 'MEDIUM'; $cls = 'RECONSTRUCTION-WITH-EXECUTION-ADJACENT'
  }
  $lead = $null
  if ($triggered) {
    $lead = ($code | Sort-Object Index | Select-Object -First 1)
  }
  return [pscustomobject]@{
    Triggered        = $triggered
    IndicatorIds     = @($code | ForEach-Object { $_.Id } | Select-Object -Unique)
    TriggerCount     = $code.Count
    Occurrences      = $occ
    CommentOnlyCount = $commentOnly.Count
    CommentOnlyIds   = @($commentOnly | ForEach-Object { $_.Id } | Select-Object -Unique)
    CommentMention   = ($commentOnly.Count -gt 0)
    WordCount        = $wordCount
    WordOnlyMention  = (($wordCount -gt 0) -and (-not $triggered))
    Contexts         = $ctx
    ContextIds       = $ctxIds
    Severity         = $sev
    Class            = $cls
    LeadIndicator    = $(if ($lead) { $lead.Label } else { '' })
    LeadIndicatorId  = $(if ($lead) { $lead.Id } else { '' })
    LeadSnippet      = $(if ($lead) { $lead.Snippet } else { '' })
  }
}

function Get-Soc002P8Det003Record {
  # The structured DET-003 record. Every field the mission asks for is present
  # (blank/NA where the telemetry source does not carry it).
  param(
    [Parameter(Mandatory=$true)] $Record,
    [Parameter(Mandatory=$true)] $Scan,
    $LinkedProcess = $null,
    $Lineage = $null
  )
  $pid_ = ''
  if ($Record.PSObject.Properties.Name -contains 'Pid') { $pid_ = $Record.Pid }
  if (-not $pid_ -and $Record.PSObject.Properties.Name -contains 'ExecPid') { $pid_ = $Record.ExecPid }
  $parentImg = ''
  if ($Record.PSObject.Properties.Name -contains 'ParentImage') { $parentImg = $Record.ParentImage }
  $ppid = ''
  if ($Record.PSObject.Properties.Name -contains 'Ppid') { $ppid = $Record.Ppid }
  if ($LinkedProcess) {
    if (-not $parentImg) { $parentImg = $LinkedProcess.ParentImage }
    if (-not $ppid) { $ppid = $LinkedProcess.Ppid }
  }
  $sbId = ''
  if ($Record.PSObject.Properties.Name -contains 'ScriptBlockId') { $sbId = $Record.ScriptBlockId }
  $pg = ''
  if ($Record.PSObject.Properties.Name -contains 'ProcessGuid') { $pg = $Record.ProcessGuid }
  if (-not $pg -and $LinkedProcess) { $pg = $LinkedProcess.ProcessGuid }
  $logon = ''
  if ($Record.PSObject.Properties.Name -contains 'LogonId') { $logon = $Record.LogonId }
  if (-not $logon -and $LinkedProcess) { $logon = $LinkedProcess.LogonId }
  $user = ''
  if ($Record.PSObject.Properties.Name -contains 'User') { $user = $Record.User }
  if (-not $user -and $LinkedProcess) { $user = $LinkedProcess.User }

  $reasons = New-Object System.Collections.ArrayList
  $null = $reasons.Add("Base64 reconstruction indicator(s) present in $($Record.Source): " + ($Scan.IndicatorIds -join ','))
  $null = $reasons.Add('A decode call alone is NOT evidence of maliciousness - it is a common, legitimate operation.')
  if ($Scan.ContextIds.Count -gt 0) { $null = $reasons.Add('context flags: ' + ($Scan.ContextIds -join ', ')) }
  if ($Scan.Severity -eq 'MEDIUM') { $null = $reasons.Add('severity raised because an execution/retrieval primitive co-occurs with the decode (INFERRED from text, not observed execution)') }
  if ($Scan.CommentMention) { $null = $reasons.Add('comment-only reconstruction mention(s) suppressed as non-trigger: ' + ($Scan.CommentOnlyIds -join ',')) }
  $null = $reasons.Add('Required next step: check authorisation of the operator and read the surrounding command/script (never execute it).')

  return [pscustomobject]@{
    Detection        = 'SOC002-DET-003'
    Title            = 'PowerShell Base64 reconstruction / decode behaviour observed'
    TimeUtc          = $Record.TimeUtc
    Host             = $Record.Computer
    User             = $user
    Pid              = $pid_
    ParentProcess    = $parentImg
    Ppid             = $ppid
    CommandLine      = $(if ($Record.PSObject.Properties.Name -contains 'CommandLine') { $Record.CommandLine } else { '' })
    LogonId          = $logon
    ProcessGuid      = $pg
    ScriptBlockId    = $sbId
    MatchedIndicator = $Scan.LeadIndicator
    MatchedIndicatorId = $Scan.LeadIndicatorId
    AllIndicators    = $Scan.IndicatorIds
    IndicatorCount   = $Scan.TriggerCount
    MatchSnippet     = $Scan.LeadSnippet
    SourceEvent      = $Record.Source
    SourceRecordId   = $Record.RecordId
    Severity         = $Scan.Severity
    Class            = $Scan.Class
    Contexts         = $Scan.ContextIds
    InvestigationReason = @($reasons)
    ExecutesDecodedContent = 'NO - this detection only reads text; nothing is executed or decoded-and-run'
    LineageChain     = $(if ($Lineage) { (Get-Soc002Leaf $Lineage.Chain[0].Image) } else { '' })
  }
}

function Format-Soc002P8Det003 {
  param([Parameter(Mandatory=$true)] $Det, [int]$Index = 1, [int]$MaxText = 400)
  $cut = { param($t) if ($null -eq $t) { $t = '' }; if ($t.Length -gt $MaxText) { $t.Substring(0, $MaxText) + '...[cut]' } else { $t } }
  $sb = New-Object System.Text.StringBuilder
  $null = $sb.AppendLine('')
  $null = $sb.AppendLine(("[DET-003 {0:D3}] Base64 reconstruction observed - INVESTIGATION CONTEXT REQUIRED" -f $Index))
  $null = $sb.AppendLine(("  Detection        = SOC002-DET-003  severity={0} class={1}" -f $Det.Severity, $Det.Class))
  $null = $sb.AppendLine(("  Timestamp (UTC)  = {0}" -f ([datetime]$Det.TimeUtc).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')))
  $null = $sb.AppendLine(("  Host             = {0}" -f $Det.Host))
  $null = $sb.AppendLine(("  User             = {0}" -f $Det.User))
  $null = $sb.AppendLine(("  PID              = {0}   (PPID {1})" -f $Det.Pid, $Det.Ppid))
  $null = $sb.AppendLine(("  Parent process   = {0}" -f $Det.ParentProcess))
  $null = $sb.AppendLine(("  LogonId          = {0}" -f $Det.LogonId))
  $null = $sb.AppendLine(("  ProcessGuid      = {0}" -f $Det.ProcessGuid))
  $null = $sb.AppendLine(("  ScriptBlockId    = {0}" -f $Det.ScriptBlockId))
  $null = $sb.AppendLine(("  Matched indicator= {0} ({1})  [{2} occurrence(s)]" -f $Det.MatchedIndicator, $Det.MatchedIndicatorId, $Det.IndicatorCount))
  $null = $sb.AppendLine(("  Source event     = {0}  RecordId={1}" -f $Det.SourceEvent, $Det.SourceRecordId))
  if ($Det.Contexts.Count -gt 0) { $null = $sb.AppendLine(("  Context flags    = {0}" -f ($Det.Contexts -join ', '))) }
  $null = $sb.AppendLine(("  Match snippet    = {0}" -f (& $cut $Det.MatchSnippet)))
  if ($Det.CommandLine) { $null = $sb.AppendLine(("  CommandLine      = {0}" -f (& $cut $Det.CommandLine))) }
  $null = $sb.AppendLine(("  Decoded content  = {0}" -f $Det.ExecutesDecodedContent))
  foreach ($r in $Det.InvestigationReason) { $null = $sb.AppendLine(("  Investigation    = {0}" -f $r)) }
  return $sb.ToString().TrimEnd()
}

function Get-Soc002P8Correlation {
  # CORR-002 - joins a DET-003 reconstruction record with the surrounding
  # process telemetry: the matching Sysmon Event 1, the matching Security 4688,
  # the PowerShell 4104 block it came from (or the 4104 block for its PID), and
  # the DET-002 lineage context where a WinRM-rooted chain exists.
  param(
    [Parameter(Mandatory=$true)] $Det003,
    [Parameter(Mandatory=$true)] $Record,
    $Lineage = $null,
    $Det002Record = $null,
    $SysmonCounterpart = $null,
    $SecurityCounterpart = $null,
    $ScriptBlockCounterpart = $null
  )
  $narr = New-Object System.Collections.ArrayList
  $null = $narr.Add('DET-003 supplies the WHAT: a base64 reconstruction call was observed in the text.')
  $null = $narr.Add('DET-002 (when present) supplies the HOW: the process was delivered through a WinRM host process.')
  if ($SysmonCounterpart)     { $null = $narr.Add("linked Sysmon Event 1 (ProcessGuid $($SysmonCounterpart.ProcessGuid), PID $($SysmonCounterpart.Pid))") } else { $null = $narr.Add('NO linked Sysmon Event 1 for this PID/window (correlation gap)') }
  if ($SecurityCounterpart)   { $null = $narr.Add("linked Security 4688 (RecordId $($SecurityCounterpart.RecordId), PID $($SecurityCounterpart.Pid))") } else { $null = $narr.Add('NO linked Security 4688 for this PID/window (correlation gap)') }
  if ($ScriptBlockCounterpart){ $null = $narr.Add("linked PowerShell 4104 (ScriptBlockId $($ScriptBlockCounterpart.ScriptBlockId), ExecPID $($ScriptBlockCounterpart.ExecPid))") } else { $null = $narr.Add('NO linked PowerShell 4104 script block for this PID/window (correlation gap)') }
  $null = $narr.Add('Correlation is CONTEXT, not a verdict. Authorisation and payload content still decide the reading.')

  return [pscustomobject]@{
    CorrelationId   = ("CORR2-{0}-{1}-{2}" -f ([string]$Det003.Host).Split('.')[0].ToUpperInvariant(), $Det003.Pid, ([datetime]$Det003.TimeUtc).ToString('yyyyMMddTHHmmssZ'))
    Host            = $Det003.Host
    TimeUtc         = $Det003.TimeUtc
    Pid             = $Det003.Pid
    User            = $Det003.User
    ProcessGuid     = $Det003.ProcessGuid
    ScriptBlockId   = $Det003.ScriptBlockId
    MatchedIndicator= $Det003.MatchedIndicator
    Severity        = $Det003.Severity
    SysmonLinked    = [bool]$SysmonCounterpart
    Security4688Linked = [bool]$SecurityCounterpart
    ScriptBlock4104Linked = [bool]$ScriptBlockCounterpart
    Det002Linked    = [bool]$Det002Record
    Det002Shape     = $(if ($Det002Record) { $Det002Record.ChainShape } elseif ($Lineage) { (Format-Soc002Chain $Lineage).Shape } else { 'NOT-RESOLVED' })
    Gaps            = @(
      $(if (-not $SysmonCounterpart) { 'no Sysmon Event 1 for this process in the retained window' })
      $(if (-not $SecurityCounterpart) { 'no Security 4688 for this process in the retained window' })
      $(if (-not $ScriptBlockCounterpart) { 'no PowerShell 4104 block linked to this process' })
      $(if (-not $Det002Record) { 'no WinRM-rooted lineage resolved (DET-002 did not fire) - the process context is weaker' })
    )
    Narrative       = @($narr)
    Statement       = 'CORRELATION IS CONTEXT, NOT A VERDICT.'
  }
}

function Format-Soc002P8Correlation {
  param([Parameter(Mandatory=$true)] $Corr, [int]$Index = 1)
  $sb = New-Object System.Text.StringBuilder
  $null = $sb.AppendLine('')
  $null = $sb.AppendLine(("[CORR-002 {0:D3}] {1}" -f $Index, $Corr.CorrelationId))
  $null = $sb.AppendLine(("  Host/PID         = {0}  PID {1}" -f $Corr.Host, $Corr.Pid))
  $null = $sb.AppendLine(("  EventUtc         = {0}" -f ([datetime]$Corr.TimeUtc).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')))
  $null = $sb.AppendLine(("  User             = {0}" -f $Corr.User))
  $null = $sb.AppendLine(("  ProcessGuid      = {0}" -f $Corr.ProcessGuid))
  $null = $sb.AppendLine(("  ScriptBlockId    = {0}" -f $Corr.ScriptBlockId))
  $null = $sb.AppendLine(("  Indicator        = {0}   severity={1}" -f $Corr.MatchedIndicator, $Corr.Severity))
  $null = $sb.AppendLine(("  Links            = Sysmon1={0}  Security4688={1}  PowerShell4104={2}  DET-002={3}" -f $Corr.SysmonLinked, $Corr.Security4688Linked, $Corr.ScriptBlock4104Linked, $Corr.Det002Linked))
  $null = $sb.AppendLine(("  DET-002 lineage  = {0}" -f $Corr.Det002Shape))
  $gaps = @($Corr.Gaps | Where-Object { $_ })
  if ($gaps.Count -gt 0) { foreach ($g in $gaps) { $null = $sb.AppendLine(("  Correlation gap  = {0}" -f $g)) } }
  foreach ($nstr in $Corr.Narrative) { $null = $sb.AppendLine(("  Reading          = {0}" -f $nstr)) }
  $null = $sb.AppendLine(("  REMINDER         = {0}" -f $Corr.Statement))
  return $sb.ToString().TrimEnd()
}

function New-Soc002P8Stats {
  [pscustomobject]@{ RecordsExamined = 0; Candidates = 0; Low = 0; Medium = 0; WordOnlyNonTriggers = 0; CommentSuppressed = 0 }
}

function Invoke-Soc002P8Assessment {
  # The ONE DET-003 pipeline. Used by the live DC1 detector and by the offline
  # replay harness, so both measure the same logic.
  #
  # -Records is an array of normalised telemetry records. Each must carry:
  #   Computer, TimeUtc, Source, RecordId, Text   (Text = the PowerShell text)
  # Process-create records (Sysmon-Event1 / Security-4688) additionally carry:
  #   Pid, Ppid, ProcessGuid, ParentGuid, Image, CommandLine, ParentImage,
  #   ParentCommandLine, User, LogonId, Hashes
  # 4104 records carry: ExecPid, ScriptBlockId
  param(
    [Parameter(Mandatory=$true)] $Records,
    $ProcessIndex = @{},
    [switch]$NoLineage
  )
  $out = New-Object System.Collections.ArrayList
  $stats = New-Soc002P8Stats
  foreach ($rec in @($Records)) {
    $stats.RecordsExamined++
    $text = [string]$rec.Text
    $scan = Test-Soc002P8Base64Reconstruction -Text $text
    if (-not $scan.Triggered) {
      if ($scan.WordOnlyMention) { $stats.WordOnlyNonTriggers++ }
      if ($scan.CommentMention)  { $stats.CommentSuppressed++ }
      continue
    }
    $stats.Candidates++
    if ($scan.Severity -eq 'MEDIUM') { $stats.Medium++ } else { $stats.Low++ }

    $linked = $null
    $lineage = $null
    if (-not $NoLineage) {
      if ($rec.Source -eq 'PowerShell-4104') {
        $key = "pid:$(([string]$rec.Computer).ToLowerInvariant())|$($rec.ExecPid)"
        if ($ProcessIndex.ContainsKey($key)) {
          # PID is NOT unique over a wide window (the lab reuses it), so the
          # process-create record is chosen by CLOSEST TIME first and never
          # silently: the gap is reported if nothing lands inside the tolerance.
          $rt = [datetime]$rec.TimeUtc
          $sel = @($ProcessIndex[$key] | Where-Object { [math]::Abs((([datetime]$_.TimeUtc) - $rt).TotalSeconds) -le 120 } |
                                        Sort-Object { [math]::Abs((([datetime]$_.TimeUtc) - $rt).TotalSeconds) })
          if ($sel.Count -gt 0) { $linked = $sel[0] }
        }
        if ($linked) { $lineage = Resolve-Soc002Lineage -Record $linked -ProcessIndex $ProcessIndex }
      } else {
        $lineage = Resolve-Soc002Lineage -Record $rec -ProcessIndex $ProcessIndex
      }
    }
    $det002 = $null
    if ($lineage -and $lineage.HasWinRmHost) {
      $anchor = $(if ($linked) { $linked } else { $rec })
      $det002 = Get-Soc002Det002LineageRecord -Record $anchor -Lineage $lineage
    }

    $det = Get-Soc002P8Det003Record -Record $rec -Scan $scan -LinkedProcess $linked -Lineage $lineage

    # counterparts for correlation
    $syComp = $null; $seComp = $null; $sbComp = $null
    $holdP = $rec
    $pidForJoin = $(if ($rec.Source -eq 'PowerShell-4104') { $rec.ExecPid } else { $rec.Pid })
    if ($pidForJoin) {
      $key = "pid:$(([string]$rec.Computer).ToLowerInvariant())|$pidForJoin"
      $rt  = [datetime]$rec.TimeUtc
      $detGuid = $det.ProcessGuid
      if ($ProcessIndex.ContainsKey($key)) {
        foreach ($c in @($ProcessIndex[$key] | Sort-Object { [math]::Abs((([datetime]$_.TimeUtc) - $rt).TotalSeconds) })) {
          # time tolerance first, then ProcessGuid agreement when both sides have one;
          # this is what stops a reused PID from being joined to the wrong process.
          if ([math]::Abs((([datetime]$c.TimeUtc) - $rt).TotalSeconds) -gt 120) { continue }
          if ($detGuid -and $c.ProcessGuid -and ($c.ProcessGuid -ne $detGuid)) { continue }
          if ($c.Source -eq 'Sysmon-Event1' -and -not $syComp) { $syComp = $c }
          if ($c.Source -eq 'Security-4688' -and -not $seComp) { $seComp = $c }
        }
      }
    }
    if ($rec.Source -eq 'PowerShell-4104') { $sbComp = $rec }
    elseif ($rec.LastScriptBlock) { $sbComp = $rec.LastScriptBlock }
    # a 4104 block for the same pid may be supplied on the record by the caller
    if (-not $sbComp) {
      if ($rec.PSObject.Properties.Name -contains 'ScriptBlocks' -and $rec.ScriptBlocks) {
        $sbComp = @($rec.ScriptBlocks)[0]
      }
    }

    $corr = Get-Soc002P8Correlation -Det003 $det -Record $rec -Lineage $lineage -Det002Record $det002 `
              -SysmonCounterpart $syComp -SecurityCounterpart $seComp -ScriptBlockCounterpart $sbComp
    $null = $out.Add([pscustomobject]@{
      Record = $rec; Scan = $scan; Det003 = $det; Lineage = $lineage; Det002 = $det002; Corr = $corr
      Linked = $linked
    })
  }
  return [pscustomobject]@{ Results = @($out); Stats = $stats }
}
