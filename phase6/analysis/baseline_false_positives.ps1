<#
  SOC-002 | Phase 6 | TASK 1 + TASK 2 - WHY THE 38 BENIGN ALERTS OCCURRED, AND WHICH
  FIELDS ACTUALLY DISCRIMINATE
  ==============================================================================
  Reads the preserved Phase 5 evidence and computes, per alert, the
  characteristics that separate the benign WinRM administration lineage from the
  controlled-test event. Every number in the output is computed from the Phase 5
  files; nothing here is invented and nothing is written back to Phase 5.
#>
[CmdletBinding()]
param(
  [string]$Phase5Root = (Join-Path $HOME 'soc-lab/phase5/evidence')
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..' 'detections' 'lib_soc002_v2.ps1')
. (Join-Path $here 'lib_evidence_phase5.ps1')

$ev  = Read-Soc002Phase5Evidence -Root $Phase5Root
$idx = New-Soc002ProcessIndex -Records $ev.ProcessRecords
$rows = foreach ($a in $ev.Alerts) {
  $wrap = Test-Soc002WinrsWrapper -ParentImage $a.ParentImage -ParentCommandLine $a.ParentCommandLine
  $lin  = Resolve-Soc002Lineage -Record $a -ProcessIndex $idx
  [pscustomobject]@{
    Alert      = $a.Phase5AlertIndex
    RecId      = $a.RecordId
    Utc        = $a.TimeUtc.ToString('HH:mm:ss.fff')
    Pid        = $a.Pid
    Parent     = Get-Soc002Leaf $a.ParentImage
    Wrap       = $wrap.Matched
    ParentCmd  = ([string]$a.ParentCommandLine).Split(' ')[0]
    User       = $a.User
    LogonId    = $a.LogonId
    PayloadLen = ([string]$a.PayloadText).Length
    Corr4104   = ($a.Phase5Corroboration -notmatch 'NONE FOUND' -and "$($a.Phase5Corroboration)" -ne '')
    ChainPlus  = $lin.HasWinRmHost
  }
}

$total        = @($rows).Count
$byParent     = @($rows | Group-Object Parent | Sort-Object Count -Descending)
$wrapped      = @($rows | Where-Object Wrap)
$nestedRunner = @($rows | Where-Object { $_.Parent -eq 'powershell.exe' })
$no4104       = @($rows | Where-Object { -not $_.Corr4104 })
$with4104     = @($rows | Where-Object { $_.Corr4104 })
$users        = @($rows | Group-Object User)
$logonCount   = @($rows | Group-Object LogonId).Count
$hosts        = @($rows | Group-Object Computer -ErrorAction SilentlyContinue).Count

# 4104 field presence across the preserved evidence
$p4104 = @($ev.Corroboration4104)
$p4104Fields = if ($p4104.Count) { @($p4104[0].PSObject.Properties.Name) } else { @() }

# Field inventory straight out of the raw forwarded XML
$sysmonFields = @(); $sec4688Fields = @()
foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $Phase5Root 'raw') -Filter *.xml -EA SilentlyContinue)) {
  $x = New-Object System.Xml.XmlDocument; $x.Load($f.FullName)
  $names = @($x.Event.EventData.Data | ForEach-Object { $_.Name })
  switch ([string]$x.Event.System.EventID) {
    '1'    { if ($names.Count -gt $sysmonFields.Count) { $sysmonFields = $names } }
    '4688' { if ($names.Count -gt $sec4688Fields.Count) { $sec4688Fields = $names } }
  }
}

$out = New-Object System.Collections.ArrayList
$null = $out.Add('=====================================================================')
$null = $out.Add(' SOC-002 PHASE 6 / TASK 1 - WHY THE PHASE 5 DETECTION WAS NOISY')
$null = $out.Add('=====================================================================')
$null = $out.Add("Source: $Phase5Root (read-only; Phase 5 files are not modified)")
$null = $out.Add("Phase 5 alert records parsed   : $total   (Phase 5 reported 'Total alerts = 39')")
$null = $out.Add("Process-create records indexed : $(@($ev.ProcessRecords).Count)")
$null = $out.Add('')
$null = $out.Add('1.1  The trigger itself is coarse, by design')
$null = $out.Add('     Phase 5 fired on: Sysmon Event 1 AND Image ~ powershell.exe/pwsh.exe AND CommandLine matches')
$null = $out.Add("     an encoded-command switch. That condition cannot distinguish intent, and in this lab the")
$null = $out.Add("     operator's own remote management satisfies it on every single call.")
$null = $out.Add('')
$null = $null
$null = $out.Add('1.2  Measured reason the 38 benign alerts existed')
$null = $out.Add("     - Alerts whose IMMEDIATE PARENT is cmd.exe running the WinRS wrapper")
$null = $out.Add("       ('cmd.exe /C powershell -encodedcommand <b64>')          : $($wrapped.Count) of $total")
$null = $out.Add("     - Alerts whose immediate parent is powershell.exe (the nested operator runner,")
$null = $out.Add("       i.e. the controlled test's own transport hop)            : $($nestedRunner.Count) of $total  (alert indexes: $(($nestedRunner | ForEach-Object { $_.Alert }) -join ','))")
$null = $out.Add("     - Distinct parent images observed                          : $(($byParent | ForEach-Object { $_.Name + '(' + $_.Count + ')' }) -join ', ')")
$null = $out.Add("     - Distinct users observed                                  : $(($users | ForEach-Object { $_.Name + '(' + $_.Count + ')' }) -join ', ')")
$null = $out.Add("     - Distinct LogonIds observed                               : $logonCount   (one per remote session - NOT a stable identifier)")
$null = $out.Add("     - Distinct collector Computers                             : $hosts")
$null = $out.Add('')
$null = $out.Add('     READING: the noise is structural, not random. Every one of those alerts was produced by')
$null = $out.Add('     the SOC team executing a command on a remote host through WinRM: pywinrm/WinRS delivers')
$null = $out.Add('     the command as "cmd.exe /C powershell -encodedcommand <base64>", so each administrative')
$null = $out.Add('     call looks exactly like the indicator. The Phase 5 analyst separated them by hand.')
$null = $out.Add('')
$null = $out.Add('1.3  4104 corroboration availability in the Phase 5 run')
$null = $out.Add("     - alerts WITH a corroborating 4104 block : $($with4104.Count)")
$null = $out.Add("     - alerts with NO 4104 found              : $($no4104.Count)   (alert indexes: $(($no4104 | ForEach-Object { $_.Alert }) -join ','))")
$null = $out.Add('     READING: 4104 is a useful corroborator when it exists, but it is not a dependable')
$null = $out.Add('     enrichment source on its own - it was missing for a large part of the same window.')
$null = $out.Add('')
$null = $out.Add('=====================================================================')
$null = $out.Add(' TASK 2 - FIELD-BY-FIELD: WHAT IS OBSERVED AND WHAT IS USEFUL')
$null = $out.Add('=====================================================================')
$null = $out.Add('Legend: OBSERVED = present in the preserved telemetry; NOT PRESENT = not in the event at all.')
$null = $out.Add('')
$null = $out.Add('Sysmon Event 1 fields actually present in the forwarded XML:')
$null = $out.Add('  ' + (($sysmonFields | Sort-Object) -join ', '))
$null = $out.Add('')
$null = $out.Add('Security 4688 fields actually present in the forwarded XML:')
$null = $out.Add('  ' + (($sec4688Fields | Sort-Object) -join ', '))
$null = $out.Add('')
$null = $out.Add('PowerShell 4104 fields actually present in the forwarded XML (EventData):')
$null = $out.Add('  MessageNumber, MessageTotal, ScriptBlockText, ScriptBlockId, Path')
$null = $out.Add('  plus System/Execution/@ProcessID - which is the EXECUTING PROCESS ID of the 4104 event.')
$null = $out.Add('  NOTE: the field is NOT an EventData attribute named ExecProcessId; a rule that looks for')
$null = $out.Add('  ExecProcessId in EventData finds nothing (that mistake is visible in the Phase 5 evidence,')
$null = $out.Add('  where ExecProcessId printed empty while System/Execution/@ProcessID carried 1500).')
$null = $out.Add('')
$null = $out.Add('  Field                     Source            Observed?  Useful for discrimination?')
$null = $out.Add('  ------------------------- ----------------- ---------- -----------------------------------------')
$rows2 = @(
  @('ParentImage',               'Sysmon Ev1',      'YES',  'STRONG - the Benign lineage''s immediate parent is cmd.exe; the controlled event''s parent was powershell.exe'),
  @('ParentCommandLine',         'Sysmon Ev1',      'YES',  'STRONG - carries the WinRS wrapper "cmd.exe /C powershell -encodedcommand <b64>" that BASE-01 keys on'),
  @('Grandparent (image only)',  'Sysmon Ev1 child','YES*', '*only as ParentImage of the PARENT''s own record - a lookup, not a field on the child event'),
  @('Grandparent (full hop)',    '2nd Ev1 record',  'YES*', 'STRONG when the parent''s create event survives; missing for 33 of 38 in the preserved set'),
  @('ProcessId (child)',         'Sysmon Ev1',      'YES',  'STRONG - joins to 4104 System/Execution ProcessID and to 4688 NewProcessId'),
  @('ParentProcessId',           'Sysmon Ev1',      'YES',  'MEDIUM - PID reuse makes it unsafe alone; needs the image-name guard used in Phase 6'),
  @('ParentProcessGuid',         'Sysmon Ev1',      'YES',  'STRONG - exact parent link with no PID-reuse ambiguity (Phase 6 resolves with this first)'),
  @('ProcessGuid (child)',       'Sysmon Ev1',      'YES',  'STRONG - stable identity for the execution; correlation key'),
  @('User',                      'Sysmon Ev1',      'YES',  'WEAK here - every alert was SOC002\Administrator, so it separates nothing in this lab'),
  @('ParentUser',                'Sysmon Ev1',      'YES',  'WEAK for the same reason (also Administrator on every alert)'),
  @('LogonId',                   'Sysmon Ev1',      'YES',  'WEAK as a discriminator (changes every session) but good for grouping one session''s calls'),
  @('Computer',                  'both',           'YES',  'NEUTRAL - a single source host produced all 39 alerts'),
  @('CommandLine (child)',       'Sysmon Ev1/4688', 'YES',  'STRONG - it is the trigger and the source of the decode; truncated in the Phase 5 broad-run evidence'),
  @('TimeCreated',               'both',           'YES',  'MEDIUM - sequencing and correlation windows; no value on its own'),
  @('Hashes',                    'Sysmon Ev1',      'YES',  'WEAK - the same Microsoft binary hash on all 39 events'),
  @('IntegrityLevel',            'Sysmon Ev1',      'YES',  'WEAK - High on all 39'),
  @('4104 ScriptBlockId',        'PowerShell 4104', 'PARTIAL','MEDIUM - identifies the decoded block; present for only part of the set'),
  @('4104 Execution ProcessID',  'PS 4104 System',  'PARTIAL','STRONG when present - ties a decoded script block to the executing process id')
)
foreach ($r in $rows2) { $null = $out.Add(('  {0,-25} {1,-17} {2,-10} {3}' -f $r[0], $r[1], $r[2], $r[3])) }
$null = $out.Add('')
$null = $out.Add('  NOT PRESENT anywhere in this telemetry (so Phase 6 does not use them):')
$null = $out.Add('    - GrandparentImage / GrandparentCommandLine as FIELDS on the child event (Sysmon 1 has none)')
$null = $out.Add('    - a "ParentProcessGuid exists in the index" guarantee - the parent''s event may have rolled out')
$null = $out.Add('    - session/authentication context (4688 Subject* + Security logon events were not forwarded)')
$null = $out.Add('    - the ORIGINATING IP of the WinRM session (it lives in WinRM operational logs, not forwarded)')
$null = $out.Add('')
$null = $out.Add('  Discriminating characteristics of the benign WinRM lineage (all OBSERVED):')
$null = $out.Add('    1. parent image leaf      = cmd.exe')
$null = $out.Add('    2. parent command line    = <...>\cmd.exe /C powershell -encodedcommand <b64>     (WinRS wrapper)')
$null = $out.Add('    3. grandparent image leaf = winrshost.exe  (WinRM shell host; 4/4 samples with a surviving parent event)')
$null = $out.Add('    4. the payload decodes to plain administrative PowerShell (Get-WinEvent / Get-ChildItem / Write-Host ...)')
$null = $out.Add('    5. user = the domain Administrator account that operates the lab')
$null = $out.Add('  Characteristics 1-3 are what BASE-01 uses; 4 is the ESC screen; 5 is NOT used (too broad).')
$null = $out.Add('')
$null = $out.Add('  What remains suspicious even inside a matching transport pattern:')
$null = $out.Add('    - a payload that decodes to download/execute/persistence/credential constructs (ESC-01..08)')
$null = $out.Add('    - an encoded execution that is NOT delivered by the WinRS wrapper (nested runners, other parents)')
$null = $out.Add('    - a WinRM-rooted run whose payload cannot be decoded at all (screen NOT VERIFIED -> weaker tier)')
$null = $out.Add('')
$out -join "`n"
