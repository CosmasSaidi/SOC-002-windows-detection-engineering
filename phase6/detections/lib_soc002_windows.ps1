<#
  SOC-002 | Phase 6 | WINDOWS / WEF ADAPTER  (lib_soc002_windows.ps1)
  ==================================================================
  Everything in this file touches Get-WinEvent, so it is Windows-only.
  The decision logic lives in lib_soc002_v2.ps1 (cross-platform) and is shared
  with the offline replay harness. Keeping the two apart is what allows the
  Phase 6 measurement to run the REAL classification against preserved
  evidence instead of a second implementation of it.

  Collector note carried over from Phase 5 (DETECTION_LIMITATIONS.txt):
  events forwarded into DC1 ForwardedEvents carry NO rendered message text, so
  every reader here parses the EventData XML. Filtering on $_.Message silently
  matches nothing centrally.
#>

function Convert-Soc002EventRecord {
  param([Parameter(Mandatory=$true)] $Event)
  $x = [xml]$Event.ToXml()
  $d = @{}
  foreach ($n in @($x.Event.EventData.Data)) { if ($n.Name) { $d[$n.Name] = [string]$n.'#text' } }
  [pscustomobject]@{
    Event      = $Event
    Xml        = $x
    Data       = $d
    Computer   = [string]$x.Event.System.Computer
    RecordId   = [string]$x.Event.System.EventRecordID
    Provider   = [string]$Event.ProviderName
    TimeUtc    = $Event.TimeCreated.ToUniversalTime()
    SystemExecPid = [string]$x.Event.System.Execution.ProcessID
  }
}

function Get-Soc002PidDecimal {
  param([string]$Value)
  if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
  $v = $Value.Trim()
  if ($v -match '^0x[0-9a-fA-F]+$') { return ([Convert]::ToInt64($v.Substring(2), 16)).ToString() }
  return $v
}

function Read-Soc002ProcessRecords {
  # Sysmon Event 1 records (and optionally Security 4688 records) normalised to
  # the record shape used by the Phase 6 library.
  param(
    [string]$LogName   = 'ForwardedEvents',
    [datetime]$Start,
    [datetime]$End,
    [switch]$Include4688,
    [switch]$SysmonOnly4688
  )
  $out = New-Object System.Collections.ArrayList
  if (-not $SysmonOnly4688) {
    foreach ($e in @(Get-WinEvent -FilterHashtable @{LogName=$LogName; Id=1; StartTime=$Start; EndTime=$End} -EA SilentlyContinue)) {
      if ($e.ProviderName -notmatch 'Sysmon') { continue }
      $p = Convert-Soc002EventRecord -Event $e
      if (-not $p.Data['Image']) { continue }
      $null = $out.Add(@{
        Computer=$p.Computer; TimeUtc=$p.TimeUtc; RecordId=$p.RecordId; Source='Sysmon-Event1'
        ProcessGuid=$p.Data['ProcessGuid']; Pid=(Get-Soc002PidDecimal $p.Data['ProcessId'])
        Ppid=(Get-Soc002PidDecimal $p.Data['ParentProcessId']); ParentGuid=$p.Data['ParentProcessGuid']
        Image=$p.Data['Image']; CommandLine=$p.Data['CommandLine']
        ParentImage=$p.Data['ParentImage']; ParentCommandLine=$p.Data['ParentCommandLine']
        User=$p.Data['User']; LogonId=$p.Data['LogonId']; ParentUser=$p.Data['ParentUser']
        Hashes=$p.Data['Hashes']; IntegrityLevel=$p.Data['IntegrityLevel']
      })
    }
  }
  if ($Include4688) {
    foreach ($e in @(Get-WinEvent -FilterHashtable @{LogName=$LogName; Id=4688; StartTime=$Start; EndTime=$End} -EA SilentlyContinue)) {
      $p = Convert-Soc002EventRecord -Event $e
      if (-not $p.Data['NewProcessName']) { continue }
      $null = $out.Add(@{
        Computer=$p.Computer; TimeUtc=$p.TimeUtc; RecordId=$p.RecordId; Source='Security-4688'
        ProcessGuid=''; Pid=(Get-Soc002PidDecimal $p.Data['NewProcessId'])
        Ppid=(Get-Soc002PidDecimal $p.Data['ProcessId']); ParentGuid=''
        Image=$p.Data['NewProcessName']; CommandLine=$p.Data['CommandLine']
        ParentImage=$p.Data['ParentProcessName']; ParentCommandLine=''
        User=("$($p.Data['SubjectDomainName'])\$($p.Data['SubjectUserName'])")
        LogonId=$p.Data['SubjectLogonId']; ParentUser=''; Hashes=''; IntegrityLevel=$p.Data['MandatoryLabel']
      })
    }
  }
  return @($out)
}

function Get-Soc002EncodedCandidates {
  # THE DET-001 trigger, byte-for-byte the Phase 5 condition:
  #   Sysmon Event 1, Image matches powershell.exe/pwsh.exe,
  #   CommandLine matches the encoded-command switch.
  # With -Include4688Fallback: Security 4688 events for the same process are
  # added ONLY when no Sysmon record exists for that (host,pid,second), and the
  # parent command line is recovered from the creator's own 4688 record.
  param(
    [string]$LogName = 'ForwardedEvents',
    [datetime]$Start,
    [datetime]$End,
    [switch]$Include4688Fallback,
    [string]$ImageRx = ''
  )
  if (-not $ImageRx) { $ImageRx = '(?i)(powershell|pwsh)\.exe' }
  $cands = New-Object System.Collections.ArrayList
  $seen  = @{}
  foreach ($e in @(Get-WinEvent -FilterHashtable @{LogName=$LogName; Id=1; StartTime=$Start; EndTime=$End} -EA SilentlyContinue)) {
    if ($e.ProviderName -notmatch 'Sysmon') { continue }
    $p = Convert-Soc002EventRecord -Event $e
    if ($p.Data['Image'] -notmatch $ImageRx) { continue }
    if (-not (Test-Soc002EncodedCommandLine -CommandLine $p.Data['CommandLine'])) { continue }
    $pid_ = Get-Soc002PidDecimal $p.Data['ProcessId']
    $seen["$($p.Computer)|$pid_|$($p.TimeUtc.ToString('HH:mm:ss.fff'))"] = $true
    $null = $cands.Add([pscustomobject]@{
      Source='Sysmon-Event1'; Computer=$p.Computer; TimeUtc=$p.TimeUtc; RecordId=$p.RecordId
      ProcessGuid=$p.Data['ProcessGuid']; Pid=$pid_
      Ppid=(Get-Soc002PidDecimal $p.Data['ParentProcessId']); ParentGuid=$p.Data['ParentProcessGuid']
      Image=$p.Data['Image']; CommandLine=$p.Data['CommandLine']
      ParentImage=$p.Data['ParentImage']; ParentCommandLine=$p.Data['ParentCommandLine']
      User=$p.Data['User']; LogonId=$p.Data['LogonId']; ParentUser=$p.Data['ParentUser']
      Hashes=$p.Data['Hashes']; IntegrityLevel=$p.Data['IntegrityLevel']
    })
  }
  if ($Include4688Fallback) {
    foreach ($e in @(Get-WinEvent -FilterHashtable @{LogName=$LogName; Id=4688; StartTime=$Start; EndTime=$End} -EA SilentlyContinue)) {
      $p = Convert-Soc002EventRecord -Event $e
      if ($p.Data['NewProcessName'] -notmatch $ImageRx) { continue }
      if (-not (Test-Soc002EncodedCommandLine -CommandLine $p.Data['CommandLine'])) { continue }
      $pid_ = Get-Soc002PidDecimal $p.Data['NewProcessId']
      if ($seen.ContainsKey("$($p.Computer)|$pid_|$($p.TimeUtc.ToString('HH:mm:ss.fff'))")) { continue }
      $creator = Get-Soc002PidDecimal $p.Data['ProcessId']
      $parentLine = ''
      foreach ($q in @(Get-WinEvent -FilterHashtable @{LogName=$LogName; Id=4688; StartTime=$p.TimeUtc.AddSeconds(-30); EndTime=$p.TimeUtc.AddSeconds(2)} -EA SilentlyContinue)) {
        $qq = Convert-Soc002EventRecord -Event $q
        if ((Get-Soc002PidDecimal $qq.Data['NewProcessId']) -eq $creator -and $qq.Data['NewProcessName'] -match '(?i)cmd\.exe') { $parentLine = $qq.Data['CommandLine']; break }
      }
      $null = $cands.Add([pscustomobject]@{
        Source='Security-4688 (no Sysmon Event 1 for this process)'; Computer=$p.Computer; TimeUtc=$p.TimeUtc; RecordId=$p.RecordId
        ProcessGuid=''; Pid=$pid_; Ppid=$creator; ParentGuid=''
        Image=$p.Data['NewProcessName']; CommandLine=$p.Data['CommandLine']
        ParentImage=$p.Data['ParentProcessName']; ParentCommandLine=$parentLine
        User=("$($p.Data['SubjectDomainName'])\$($p.Data['SubjectUserName'])"); LogonId=$p.Data['SubjectLogonId']
        Hashes=''; IntegrityLevel=$p.Data['MandatoryLabel']
      })
    }
  }
  return @($cands | Sort-Object TimeUtc -Descending)
}

function Get-Soc0024104Corroboration {
  # PowerShell 4104 records tied to the candidate process id, or carrying the
  # marker text. NOTE: the process id lives in the System/Execution section of
  # the 4104 event (there is no EventData field named ExecProcessId).
  param(
    [string]$LogName = 'ForwardedEvents',
    [Parameter(Mandatory=$true)] $Record,
    [string]$Marker = '',
    [int]$Back = 5,
    [int]$Forward = 45,
    [int]$TextChars = 200
  )
  $out = New-Object System.Collections.ArrayList
  foreach ($q in @(Get-WinEvent -FilterHashtable @{LogName=$LogName; Id=4104; StartTime=$Record.TimeUtc.AddSeconds(-$Back); EndTime=$Record.TimeUtc.AddSeconds($Forward)} -EA SilentlyContinue)) {
    $qx = [xml]$q.ToXml()
    $qd = @{}; foreach ($n in @($qx.Event.EventData.Data)) { if ($n.Name) { $qd[$n.Name] = [string]$n.'#text' } }
    $execPid = [string]$qx.Event.System.Execution.ProcessID
    $byPid = ($Record.Pid -ne '' -and $execPid -eq "$($Record.Pid)")
    $byMarker = ($Marker -and ([string]$qd['ScriptBlockText'] -match [regex]::Escape($Marker)))
    if (-not ($byPid -or $byMarker)) { continue }
    $txt = ([string]$qd['ScriptBlockText'] -replace '\r?\n', ' ')
    if ($txt.Length -gt $TextChars) { $txt = $txt.Substring(0, $TextChars) + '...[cut]' }
    $null = $out.Add([pscustomobject]@{
      RecordId=[string]$q.RecordId; ExecPid=$execPid; ScriptBlockId=$qd['ScriptBlockId']
      MessageNumber=$qd['MessageNumber']; MessageTotal=$qd['MessageTotal']; Text=$txt
      MatchBy=$(if ($byPid) { 'ExecProcessID' } else { 'marker-text' })
    })
  }
  return @($out)
}
