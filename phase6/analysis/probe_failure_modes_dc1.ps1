<#
  SOC-002 | Phase 6 | TASK 7 - FAILURE-MODE PROBE  (READ-ONLY, runs on SOC002-DC1)
  ==============================================================================
  WHAT THIS IS
    A read-only measurement of what the DET-001 telemetry set looks like from the
    collector when individual sources are considered in isolation. It answers:

      FM-1  if Sysmon Event 1 did not exist, could Security 4688 still feed DET-001?
      FM-2  how many candidates have a PowerShell 4104 block, and how many do not?
      FM-3  how many candidates have a resolvable process lineage?
      FM-4  how many candidate command lines are empty / unusable for the trigger?

  WHAT IT IS NOT
    - It does NOT disable, reconfigure or restart any logging subsystem. No
      telemetry source is turned off to "create" a failure; the counts are
      computed by simply NOT READING the source and observing the remainder.
    - It does NOT write outside the Phase 6 temp directory and writes no
      credentials. It performs Get-WinEvent reads only.
    - It does NOT prove what a real attacker would look like; the lab has no
      adversary telemetry.

  WINDOW: default = the Phase 5 broad 60-minute window (local time on DC1).
#>
[CmdletBinding()]
param(
  [string]$LogName  = 'ForwardedEvents',
  [string]$Since    = '2026-10-15 00:04:46',
  [string]$Until    = '2026-10-15 01:04:46',
  [int]$CorroBack   = 5,
  [int]$CorroFwd    = 45
)
$ErrorActionPreference = 'SilentlyContinue'
$start = Get-Date $Since
$end   = Get-Date $Until
$rx    = '(?i)\s-(e|en|enc|encodedcommand)(\s|$)'
$imgRx = '(?i)(powershell|pwsh)\.exe'

function Get-EventData {
  param($Event)
  $x = [xml]$Event.ToXml()
  $d = @{}
  foreach ($n in @($x.Event.EventData.Data)) { if ($n.Name) { $d[$n.Name] = [string]$n.'#text' } }
  [pscustomobject]@{ X=$x; D=$d; Computer=[string]$x.Event.System.Computer
                     RecordId=[string]$x.Event.System.EventRecordID
                     TimeUtc=$Event.TimeCreated.ToUniversalTime()
                     ExecPid=[string]$x.Event.System.Execution.ProcessID }
}
function To-Dec([string]$v) { if ([string]::IsNullOrWhiteSpace($v)) { return '' }; if ($v -match '^0x') { return ([Convert]::ToInt64($v.Substring(2),16)).ToString() }; return $v }

$sys = New-Object System.Collections.ArrayList
foreach ($e in @(Get-WinEvent -FilterHashtable @{LogName=$LogName;Id=1;StartTime=$start;EndTime=$end})) {
  if ($e.ProviderName -notmatch 'Sysmon') { continue }
  $p = Get-EventData $e
  if ($p.D['Image'] -notmatch $imgRx) { continue }
  if ($p.D['CommandLine'] -notmatch $rx) { continue }
  $null = $sys.Add([pscustomobject]@{
    Computer=$p.Computer; RecordId=$p.RecordId; TimeUtc=$p.TimeUtc
    Pid=(To-Dec $p.D['ProcessId']); Ppid=(To-Dec $p.D['ParentProcessId'])
    Image=$p.D['Image']; CommandLine=[string]$p.D['CommandLine']
    ParentImage=$p.D['ParentImage']; ParentCommandLine=$p.D['ParentCommandLine']
    ProcessGuid=$p.D['ProcessGuid']; ParentGuid=$p.D['ParentProcessGuid']
  })
}
$s4 = New-Object System.Collections.ArrayList
foreach ($e in @(Get-WinEvent -FilterHashtable @{LogName=$LogName;Id=4688;StartTime=$start;EndTime=$end})) {
  $p = Get-EventData $e
  if ($p.D['NewProcessName'] -notmatch $imgRx) { continue }
  if ($p.D['CommandLine'] -notmatch $rx) { continue }
  $null = $s4.Add([pscustomobject]@{
    Computer=$p.Computer; RecordId=$p.RecordId; TimeUtc=$p.TimeUtc
    Pid=(To-Dec $p.D['NewProcessId']); Ppid=(To-Dec $p.D['ProcessId'])
    Image=$p.D['NewProcessName']; CommandLine=[string]$p.D['CommandLine']
    ParentImage=$p.D['ParentProcessName']; CommandLineEmpty=[string]::IsNullOrEmpty($p.D['CommandLine'])
  })
}
# every powershell.exe 4688 in the window (to measure how often the command line is unusable)
$all4688ps = @()
foreach ($e in @(Get-WinEvent -FilterHashtable @{LogName=$LogName;Id=4688;StartTime=$start;EndTime=$end})) {
  $p = Get-EventData $e
  if ($p.D['NewProcessName'] -match $imgRx) { $all4688ps += [pscustomobject]@{ Cl=[string]$p.D['CommandLine'] } }
}
$p4104 = @()
foreach ($e in @(Get-WinEvent -FilterHashtable @{LogName=$LogName;Id=4104;StartTime=$start.AddSeconds(-$CorroBack);EndTime=$end.AddSeconds($CorroFwd)})) {
  $p = Get-EventData $e
  $p4104 += [pscustomobject]@{ Computer=$p.Computer; ExecPid=$p.ExecPid; RecordId=$p.RecordId; Text=[string]$p.D['ScriptBlockText'] }
}

$all = @($sys) + @($s4)
function Jk($r) { "$($r.Computer)|$($r.Pid)|$($r.TimeUtc.ToString('HH:mm:ss'))" }
$seen = @{}
foreach ($r in $sys) { $seen[(Jk $r)] = $true }
$four688NotInSysmon = @($s4 | Where-Object { -not $seen.ContainsKey((Jk $_)) })
$sysKeys = @{}
foreach ($r in $sys) { $sysKeys[(Jk $r)] = $true }
$s4Keys = @{}
foreach ($r in $s4) { $s4Keys[(Jk $r)] = $true }

# FM-2: 4104 binding for each Sysmon candidate (by executing pid within the window)
$with4104 = 0; $without4104 = 0
foreach ($r in $sys) {
  $hit = @($p4104 | Where-Object { $_.Computer -eq $r.Computer -and $_.ExecPid -eq "$($r.Pid)" })
  if ($hit.Count -gt 0) { $with4104++ } else { $without4104++ }
}
# 4104 blocks that could not be tied to any candidate's executing pid
$candPids = @{}
foreach ($r in $sys) { $candPids["$($r.Computer)|$($r.Pid)"] = $true }
$orphan4104 = @($p4104 | Where-Object { -not $candPids.ContainsKey("$($_.Computer)|$($_.ExecPid)") })

# FM-3: lineage resolvable?  the parent's own Sysmon Ev1 must be in the index
$idx = @{}
foreach ($e in @(Get-WinEvent -FilterHashtable @{LogName=$LogName;Id=1;StartTime=$start.AddMinutes(-120);EndTime=$end})) {
  if ($e.ProviderName -notmatch 'Sysmon') { continue }
  $p = Get-EventData $e
  if (-not $p.D['Image']) { continue }
  $idx["$($p.Computer)|$((To-Dec $p.D['ProcessId']))"] = $p.D['Image']
  if ($p.D['ProcessGuid']) { $idx["guid:$($p.D['ProcessGuid'])"] = $p.D['Image'] }
}
$linOk = 0; $linMissing = 0
foreach ($r in $sys) {
  $byGuid = if ($r.ParentGuid) { $idx["guid:$($r.ParentGuid)"] } else { $null }
  $byPid  = $idx["$($r.Computer)|$($r.Ppid)"]
  $leafOk = $false
  if ($byGuid -and ([IO.Path]::GetFileNameWithoutExtension($byGuid) -ieq [IO.Path]::GetFileNameWithoutExtension($r.ParentImage))) { $leafOk = $true }
  elseif ($byPid  -and ([IO.Path]::GetFileNameWithoutExtension($byPid)  -ieq [IO.Path]::GetFileNameWithoutExtension($r.ParentImage))) { $leafOk = $true }
  if ($leafOk) { $linOk++ } else { $linMissing++ }
}

$lines = New-Object System.Collections.ArrayList
$null = $lines.Add('=== SOC-002 PHASE 6 | TASK 7 - FAILURE-MODE PROBE (READ-ONLY, SOC002-DC1) ===')
$null = $lines.Add("Log=$LogName  Window=$($start.ToString('yyyy-MM-dd HH:mm:ss')) .. $($end.ToString('yyyy-MM-dd HH:mm:ss')) (collector local)")
$null = $lines.Add('No logging subsystem was disabled, reconfigured or restarted for this measurement:')
$null = $lines.Add('each figure is computed by NOT reading one source and observing what remains.')
$null = $lines.Add('-------------------------------------------------------------------')
$null = $lines.Add("FM-1 / baseline: Sysmon Event 1 encoded-PowerShell candidates in window = $($sys.Count)")
$null = $lines.Add("FM-1 / Security 4688 encoded-PowerShell records in window               = $($s4.Count)")
$null = $lines.Add("FM-1 / 4688 encoded-PowerShell with NO Sysmon Ev1 twin (same host+pid+second) = $($four688NotInSysmon.Count)")
$null = $lines.Add("FM-1 / Sysmon Ev1 encoded-PowerShell with NO 4688 twin (same host+pid+second) = $(@($sys | Where-Object { -not $s4Keys.ContainsKey((Jk $_)) }).Count)")
$null = $lines.Add("FM-1 / distinct host+pid+SECOND keys (Sysmon->4688 join, +/- within same second): Sysmon=$($sysKeys.Count) 4688=$($s4Keys.Count) union=$(@($sysKeys.Keys + $s4Keys.Keys | Sort-Object -Unique).Count)")
$null = $lines.Add('')
$null = $lines.Add("FM-2 / candidates WITH a binding 4104 block (executing PID match)       = $with4104")
$null = $lines.Add("FM-2 / candidates WITHOUT any 4104 block                                = $without4104")
$null = $lines.Add("FM-2 / 4104 blocks in window that bind to no candidate executing PID    = $($orphan4104.Count)")
$null = $lines.Add('')
$null = $lines.Add("FM-3 / candidates whose immediate-parent process-create record was found = $linOk")
$null = $lines.Add("FM-3 / candidates whose immediate-parent record was NOT found            = $linMissing")
$null = $lines.Add('')
$null = $lines.Add("FM-4 / powershell.exe 4688 records in window (any command line)          = $($all4688ps.Count)")
$null = $lines.Add("FM-4 / ... of which command line is EMPTY (trigger could not evaluate)   = $(@($all4688ps | Where-Object { $_.Cl -eq '' }).Count)")
$null = $lines.Add("FM-4 / Sysmon Ev1 candidates whose command line is empty                 = $(@($sys | Where-Object { $_.CommandLine -eq '' }).Count)")
$null = $lines.Add('')
# FM-1b: continuity of the two sources across the window (10-minute buckets)
$buckets = @{}
foreach ($r in $sys) { $k = $r.TimeUtc.ToLocalTime().ToString('HH:mm').Substring(0,4)+'0'; $buckets[$k] = $buckets[$k] + 1 }
$b4688 = @{}
foreach ($r in $s4)  { $k = $r.TimeUtc.ToLocalTime().ToString('HH:mm').Substring(0,4)+'0'; $b4688[$k] = $b4688[$k] + 1 }
$allKeys = @($buckets.Keys + $b4688.Keys | Sort-Object -Unique)
$null = $lines.Add('FM-1b / encoded-PowerShell candidates per 10-minute bucket (local):')
$null = $lines.Add(('{0,-10} {1,10} {2,10}' -f 'bucket','SysmonEv1','4688'))
foreach ($k in $allKeys) {
  $null = $lines.Add(('{0,-10} {1,10} {2,10}' -f $k, [int]$buckets[$k], [int]$b4688[$k]))
}
$sorted = @($sys | Sort-Object TimeUtc)
$gapMax = 0; $gapAt = ''
for ($i = 1; $i -lt $sorted.Count; $i++) {
  $g = ($sorted[$i].TimeUtc - $sorted[$i-1].TimeUtc).TotalSeconds
  if ($g -gt $gapMax) { $gapMax = $g; $gapAt = "$($sorted[$i-1].TimeUtc.ToLocalTime().ToString('HH:mm:ss')) -> $($sorted[$i].TimeUtc.ToLocalTime().ToString('HH:mm:ss'))" }
}
$null = $lines.Add('')
$null = $lines.Add("FM-1c / largest gap between consecutive Sysmon Ev1 candidates = $([int]$gapMax) s  ($gapAt)")
$null = $lines.Add('      (a period with zero Sysmon Ev1 candidates is NOT the same as a period with zero activity:')
$null = $lines.Add('       compare the 4688 column above before reading any gap as "nothing happened")')
$null = $lines.Add('')
$lines -join "`n"
