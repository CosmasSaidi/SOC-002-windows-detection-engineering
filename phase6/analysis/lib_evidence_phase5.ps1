<#
  SOC-002 | Phase 6 | PHASE 5 EVIDENCE READERS  (read-only)
  ===========================================================
  Parsers for the PRESERVED Phase 5 evidence under ~/soc-lab/phase5/evidence/.
  Nothing here writes to, renames, or truncates any Phase 5 file: Phase 6 only
  reads them. Phase 5 remains the original evidence of record.

  Reader surface
    Read-Soc002Phase5Evidence        - opens everything and returns one bundle
    Read-Soc002Phase5AlertBlocks     - t6_detection_broad60_dc1.txt (the 39 alerts)
    Read-Soc002Phase5KeyValueBlocks  - the "Key=Value" evidence dumps (t3a/t3b/t3x_*/t3y_*)
    Read-Soc002Phase5Ancestry        - t3z_ancestry_ws001.txt
    Read-Soc002Phase5RawXml          - evidence/raw/*.xml (Sysmon 1, 4688, 4104)

  Labelling: every record produced here carries Source = the file it came from,
  so a Phase 6 conclusion can always be traced back to a Phase 5 artefact.
#>

function ConvertTo-Soc002Utc {
  param([string]$Text, [string]$AssumeDate = '2026-10-14')
  if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
  $t = $Text.Trim()
  if ($t -match '^\d{2}:\d{2}:\d{2}(\.\d+)?$') { $t = "${AssumeDate}T$t" + 'Z' }   # t3z prints time-of-day only
  $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
  try { return [datetime]::Parse($t, [Globalization.CultureInfo]::InvariantCulture, $styles) } catch { return $null }
}

function ConvertTo-Soc002Int {
  param([string]$Text)
  if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
  $t = $Text.Trim()
  if ($t -match '^0x[0-9a-fA-F]+$') { return ([Convert]::ToInt64($t.Substring(2), 16)).ToString() }
  if ($t -match '^\d+$') { return $t }
  return $t
}

function Read-Soc002Phase5AlertBlocks {
  # Parses the Phase 5 DET-001 output (broad 60-minute run) into candidate
  # records. Parsing is block-based rather than line-based because the decoded
  # payload inside a block spans multiple lines. Phase 5 truncated long values
  # with '...[cut]'; that truncation is preserved and flagged, never "repaired".
  param([Parameter(Mandatory=$true)][string]$Path)
  $text = (Get-Content -LiteralPath $Path -Raw) -replace "`r`n", "`n" -replace "`r", "`n"
  $blocks = [regex]::Split($text, '(?m)^(?=\[ALERT \d+\])')
  $out = New-Object System.Collections.ArrayList
  foreach ($b in $blocks) {
    if ($b -notmatch '^\[ALERT (\d+)\]') { continue }
    $alertIndex = [int]$Matches[1]
    function Grab([string]$rx) { if ($b -match $rx) { return $Matches[1].Trim() } else { return '' } }
    $procLine   = Grab '(?m)^\s{2}Process\s+=\s*(.*?)\s+\(PID (\d+)\)\s*$'
    if ($procLine -eq '' -and $b -match '(?m)^\s{2}Process\s+=\s*(.+)$') { $procLine = $Matches[1] }
    $img = ''; $pid_ = ''
    if ($b -match '(?m)^\s{2}Process\s+=\s*(.*?)\s+\(PID (\d+)\)\s*$') { $img = $Matches[1]; $pid_ = $Matches[2] }
    $pimg = ''; $ppid_ = ''
    if ($b -match '(?m)^\s{2}Parent\s+=\s*(.*?)\s+\(PPID (\d+)\)\s*$') { $pimg = $Matches[1]; $ppid_ = $Matches[2] }
    $user = ''; $logon = ''
    if ($b -match '(?m)^\s{2}User\s+=\s*(.*?)\s+LogonId=(\S+)\s*$') { $user = $Matches[1].Trim(); $logon = $Matches[2] }
    $sysmonRec = ''; $guid = ''
    if ($b -match '(?m)^\s{2}SysmonRecordId\s+=\s*(\d+)\s+ProcessGuid=(\S+)') { $sysmonRec = $Matches[1]; $guid = $Matches[2] }
    $decoded = ''
    if ($b -match '(?s)DecodedScript\s*=\s*<<<(.*?)>>>') { $decoded = $Matches[1] }
    $corr = @([regex]::Matches($b, '(?m)^\s{2}Corroboration\s+=\s*(.+)$') | ForEach-Object { $_.Groups[1].Value.Trim() })
    $null = $out.Add([pscustomobject]@{
      Phase5AlertIndex = $alertIndex
      Source       = ('Phase 5 evidence: t6_detection_broad60_dc1.txt ([ALERT {0:D3}])' -f $alertIndex)
      SourceKind   = 'Sysmon-Event1 (as reported by the Phase 5 detection)'
      Computer     = (Grab '(?m)^\s{2}Host\s+=\s*(.+)$')
      TimeUtc      = ConvertTo-Soc002Utc (Grab '(?m)^\s{2}EventUtc\s+=\s*(\S+)\s*$')
      RecordId     = $sysmonRec
      ProcessGuid  = $guid
      Pid          = $pid_
      Ppid         = $ppid_
      ParentGuid   = ''
      Image        = $img
      CommandLine  = (Grab '(?m)^\s{2}CommandLine\s+=\s*(.+)$')
      ParentImage  = $pimg
      ParentCommandLine = (Grab '(?m)^\s{2}ParentCommandLine=\s*(.+)$')
      User         = $user
      LogonId      = $logon
      Hashes       = (Grab '(?m)^\s{2}Hashes\s+=\s*(.+)$')
      IntegrityLevel = ''
      PayloadText  = $decoded
      PayloadSource= 'Phase 5 decoded snippet (decoded from the FULL live command line by the Phase 5 detection, then truncated for display) - NOT VERIFIED beyond the truncation point'
      CommandLineTruncated = ((Grab '(?m)^\s{2}CommandLine\s+=\s*(.+)$') -match '\.\.\.\[cut\]')
      Phase5Corroboration = ($corr -join ' || ')
      Phase5DetectionLine = (Grab '(?m)^\s{2}Detection\s+=\s*(.+)$')
    })
  }
  return @($out)
}

function Read-Soc002Phase5KeyValueBlocks {
  # Parses the evidence dumps produced on/after the Phase 5 activity. Two shapes
  # are handled: Sysmon Event 1 dumps and Security 4688 dumps. RAWXML payloads
  # embedded in those files are skipped (they are parsed from evidence/raw/).
  param([Parameter(Mandatory=$true)][string]$Path)
  $out = New-Object System.Collections.ArrayList
  $cur = $null
  foreach ($line in (Get-Content -LiteralPath $Path)) {
    if ($line -match '^---\s*RecId=(\d+)') {
      if ($null -ne $cur -and $cur.Keys.Count -gt 1) { $null = $out.Add($cur) }
      $cur = @{ RecId = $Matches[1] }; continue
    }
    if ($line -match '^(===|\[STDERR\]|\[RC\]|\[EP\])') {
      # end of a record section (the RAWXML dump that follows a record belongs
      # to that record, so the block has to be flushed here, not discarded)
      if ($null -ne $cur -and $cur.Keys.Count -gt 1) { $null = $out.Add($cur) }
      $cur = $null; continue
    }
    if ($null -eq $cur) { continue }
    if ($line -match '^([A-Za-z0-9]+)=(.*)$') { $cur[$Matches[1]] = ($Matches[2] -replace "`r", '') }
  }
  if ($null -ne $cur -and $cur.Keys.Count -gt 1) { $null = $out.Add($cur) }

  $src = Split-Path -Leaf $Path
  $recs = New-Object System.Collections.ArrayList
  foreach ($r in $out) {
    if ($r.ContainsKey('NewProcessName')) {
      $null = $recs.Add(@{
        Source='Phase 5 evidence: ' + $src; SourceKind='Security-4688'
        Computer=$r['Computer']; TimeUtc=(ConvertTo-Soc002Utc $r['TimeUtc']); RecordId=$r['RecId']
        ProcessGuid=''; Pid=(ConvertTo-Soc002Int $r['NewProcessId']); Ppid=(ConvertTo-Soc002Int $r['ProcessId']); ParentGuid=''
        Image=$r['NewProcessName']; CommandLine=$r['CommandLine']
        ParentImage=$r['ParentProcessName']; ParentCommandLine=''
        User=("$($r['SubjectDomainName'])\$($r['SubjectUserName'])"); LogonId=$r['SubjectLogonId']
        Hashes=''; IntegrityLevel=$r['MandatoryLabel']
      })
    } elseif ($r.ContainsKey('Image')) {
      $null = $recs.Add(@{
        Source='Phase 5 evidence: ' + $src; SourceKind='Sysmon-Event1'
        Computer=$r['Computer']; TimeUtc=(ConvertTo-Soc002Utc $r['TimeUtc']); RecordId=$r['RecId']
        ProcessGuid=$r['ProcessGuid']; Pid=(ConvertTo-Soc002Int $r['ProcessId']); Ppid=(ConvertTo-Soc002Int $r['ParentProcessId']); ParentGuid=$r['ParentProcessGuid']
        Image=$r['Image']; CommandLine=$r['CommandLine']
        ParentImage=$r['ParentImage']; ParentCommandLine=$r['ParentCommandLine']
        User=$r['User']; LogonId=$r['LogonId']
        Hashes=$r['Hashes']; IntegrityLevel=$r['IntegrityLevel']
      })
    }
  }
  return @($recs)
}

function Read-Soc002Phase5Ancestry {
  # t3z_ancestry_ws001.txt: "RecId=3531 Utc=21:59:47.472 PID=5800 PPID=716 Img=winrshost.exe Parent=svchost.exe"
  # NOTE: this file records time-of-day only; the date is taken as the Phase 5
  # activity date (2026-10-14 UTC) and that assumption is recorded in the output.
  param([Parameter(Mandatory=$true)][string]$Path)
  $recs = New-Object System.Collections.ArrayList
  foreach ($line in (Get-Content -LiteralPath $Path)) {
    if ($line -notmatch '^RecId=(\d+)\s+Utc=([\d\.:]+)\s+PID=(\d+)\s+PPID=(\d+)\s+Img=(\S+)\s+Parent=(\S+)') { continue }
    $null = $recs.Add(@{
      Source='Phase 5 evidence: t3z_ancestry_ws001.txt (Sysmon Event 1 summary line)'; SourceKind='Sysmon-Event1 (summary)'
      Computer='SOC002-WS001.soc002.local'; TimeUtc=(ConvertTo-Soc002Utc $Matches[2]); RecordId=$Matches[1]
      ProcessGuid=''; Pid=$Matches[3]; Ppid=$Matches[4]; ParentGuid=''
      Image=$Matches[5]; CommandLine=''
      ParentImage=$Matches[6]; ParentCommandLine=''
      User=''; LogonId=''; Hashes=''; IntegrityLevel=''
    })
  }
  return @($recs)
}

function Read-Soc002Phase5RawXml {
  # evidence/raw/*.xml - the verbatim forwarded events that Phase 5 preserved.
  # Returns process-create records (Sysmon 1 / Security 4688) and 4104 records.
  param([Parameter(Mandatory=$true)][string]$Path)
  $name = Split-Path -Leaf $Path
  $x = New-Object System.Xml.XmlDocument
  $x.Load($Path)
  $d = @{}
  foreach ($n in @($x.Event.EventData.Data)) { if ($n.Name) { $d[$n.Name] = [string]$n.'#text' } }
  $computer = [string]$x.Event.System.Computer
  $recId    = [string]$x.Event.System.EventRecordID
  $eid      = [string]$x.Event.System.EventID
  $timeUtc  = ConvertTo-Soc002Utc ([string]$x.Event.System.TimeCreated.SystemTime)
  $src      = "Phase 5 evidence: raw/$name"

  if ($eid -eq '4104') {
    return [pscustomobject]@{ Kind='PowerShell4104'; Record=[pscustomobject]@{
        Computer=$computer; RecordId=$recId; TimeUtc=$timeUtc; ExecPid=[string]$x.Event.System.Execution.ProcessID
        ScriptBlockId=$d['ScriptBlockId']; MessageNumber=$d['MessageNumber']; MessageTotal=$d['MessageTotal']
        Text=([string]$d['ScriptBlockText'] -replace '\r?\n',' '); Source=$src } }
  }
  if ($eid -eq '1') {
    return [pscustomobject]@{ Kind='ProcessRecord'; Record=@{
        Source=$src; SourceKind='Sysmon-Event1 (raw forwarded XML)'
        Computer=$computer; TimeUtc=$timeUtc; RecordId=$recId
        ProcessGuid=$d['ProcessGuid']; Pid=(ConvertTo-Soc002Int $d['ProcessId']); Ppid=(ConvertTo-Soc002Int $d['ParentProcessId']); ParentGuid=$d['ParentProcessGuid']
        Image=$d['Image']; CommandLine=$d['CommandLine']
        ParentImage=$d['ParentImage']; ParentCommandLine=$d['ParentCommandLine']
        User=$d['User']; LogonId=$d['LogonId']; Hashes=$d['Hashes']; IntegrityLevel=$d['IntegrityLevel'] } }
  }
  if ($eid -eq '4688') {
    return [pscustomobject]@{ Kind='ProcessRecord'; Record=@{
        Source=$src; SourceKind='Security-4688 (raw forwarded XML)'
        Computer=$computer; TimeUtc=$timeUtc; RecordId=$recId
        ProcessGuid=''; Pid=(ConvertTo-Soc002Int $d['NewProcessId']); Ppid=(ConvertTo-Soc002Int $d['ProcessId']); ParentGuid=''
        Image=$d['NewProcessName']; CommandLine=$d['CommandLine']
        ParentImage=$d['ParentProcessName']; ParentCommandLine=''
        User=("$($d['SubjectDomainName'])\$($d['SubjectUserName'])"); LogonId=$d['SubjectLogonId']
        Hashes=''; IntegrityLevel=$d['MandatoryLabel'] } }
  }
  return [pscustomobject]@{ Kind='Other'; Record=$null }
}

function Read-Soc002Phase5Evidence {
  param([string]$Root = (Join-Path $HOME 'soc-lab/phase5/evidence'))
  $records = New-Object System.Collections.ArrayList
  $alerts  = New-Object System.Collections.ArrayList
  $corr4104= New-Object System.Collections.ArrayList
  $files   = New-Object System.Collections.ArrayList
  $notes   = New-Object System.Collections.ArrayList
  $seen    = @{}

  foreach ($f in @('t3a_sysmon1_ws001.txt','t3b_4688_ws001.txt','t3x_a_sysmon1_ws001.txt','t3x_b_4688_ws001.txt','t3y_a_sysmon1_dc1.txt','t3y_b_4688_dc1.txt','t3z_ancestry_ws001.txt')) {
    $p = Join-Path $Root $f
    if (-not (Test-Path $p)) { $null = $notes.Add("missing evidence file: $f"); continue }
    $null = $files.Add($p)
    if ($f -like '*ancestry*') { $rs = Read-Soc002Phase5Ancestry -Path $p } else { $rs = Read-Soc002Phase5KeyValueBlocks -Path $p }
    foreach ($r in $rs) {
      $k = "$($r.SourceKind)|$($r.Computer)|$($r.RecordId)"
      if ($seen.ContainsKey($k)) { continue }
      $seen[$k] = $true
      $null = $records.Add([pscustomobject]$r)
    }
  }
  $rawDir = Join-Path $Root 'raw'
  if (Test-Path $rawDir) {
    foreach ($f in @(Get-ChildItem -LiteralPath $rawDir -Filter *.xml | Sort-Object Name)) {
      $null = $files.Add($f.FullName)
      $r = Read-Soc002Phase5RawXml -Path $f.FullName
      if ($r.Kind -eq 'ProcessRecord') {
        $k = "$($r.Record.SourceKind)|$($r.Record.Computer)|$($r.Record.RecordId)"
        if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $null = $records.Add([pscustomobject]$r.Record) }
      } elseif ($r.Kind -eq 'PowerShell4104') {
        $k = "4104|$($r.Record.Computer)|$($r.Record.RecordId)"
        if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $null = $corr4104.Add($r.Record) }
      }
    }
  }
  $alertFile = Join-Path $Root 't6_detection_broad60_dc1.txt'
  if (Test-Path $alertFile) {
    $null = $files.Add($alertFile)
    foreach ($a in (Read-Soc002Phase5AlertBlocks -Path $alertFile)) { $null = $alerts.Add($a) }
  }
  [pscustomobject]@{
    Root         = $Root
    Files        = @($files)
    ProcessRecords = @($records)
    Alerts       = @($alerts)
    Corroboration4104 = @($corr4104)
    Notes        = @($notes)
  }
}
