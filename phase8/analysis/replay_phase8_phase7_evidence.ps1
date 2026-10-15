<#
  SOC-002 | PHASE 8 | REPLAY OF PRESERVED PHASE 7 EVIDENCE  (offline, read-only)
  =====================================================================
  Reads the unmodified Phase 7 raw telemetry (evidence/raw/t4b_*.txt on WS001 and
  t5b_*.txt on DC1, one "EVXML|<xml>" line per event) and runs the REAL DET-003
  pipeline (lib_soc002_phase8.ps1) over it. The Phase 6 library is dot-sourced
  READ-ONLY so the same run can also answer "did DET-001 v2 see this?" for
  contrast. Neither library is modified.

  This is the FIRST validation the mission asks for: replay the actual Phase 7
  blind-spot event against DET-003 BEFORE any new live activity.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$Raw,
  [Parameter(Mandatory=$true)][string]$Out,
  [string]$Label = 'phase7-evidence',
  [string]$JsonOut = '',
  [string]$Phase8Lib = "$PSScriptRoot/../detections",
  [string]$Phase6Lib = "$PSScriptRoot/../../phase6/detections",
  [int]$MaxText = 400
)
$ErrorActionPreference = 'Stop'
. (Join-Path $Phase8Lib 'lib_soc002_phase8.ps1')
. (Join-Path $Phase6Lib 'lib_soc002_v2.ps1')

function H2D([string]$v) { if ([string]::IsNullOrWhiteSpace($v)) { return '' }; if ($v -match '^0x[0-9a-fA-F]+$') { return ([Convert]::ToInt64($v.Substring(2),16)).ToString() }; return $v }

$events = New-Object System.Collections.ArrayList
foreach ($line in (Get-Content -LiteralPath $Raw)) {
  if (-not $line.StartsWith('EVXML|')) { continue }
  $x = [xml]$line.Substring(6)
  $d = @{}; foreach ($n in @($x.Event.EventData.Data)) { if ($n.Name) { $d[$n.Name] = [string]$n.'#text' } }
  $null = $events.Add([pscustomobject]@{
    Id = [string]$x.Event.System.EventID
    Rec = [string]$x.Event.System.EventRecordID
    Comp = [string]$x.Event.System.Computer
    Prov = [string]$x.Event.System.Provider.Name
    Utc = ([datetime]$x.Event.System.TimeCreated.SystemTime).ToUniversalTime()
    ExecPid = [string]$x.Event.System.Execution.ProcessID
    D = $d
  })
}

# ---- build the DET-003 input records -----------------------------------
$input_ = New-Object System.Collections.ArrayList
$procRecs = New-Object System.Collections.ArrayList
foreach ($e in $events) {
  if ($e.Id -eq '1' -and $e.Prov -match 'Sysmon') {
    $r = [pscustomobject]@{
      Computer=$e.Comp; TimeUtc=$e.Utc; RecordId=$e.Rec; Source='Sysmon-Event1'
      ProcessGuid=$e.D['ProcessGuid']; Pid=(H2D $e.D['ProcessId']); Ppid=(H2D $e.D['ParentProcessId']); ParentGuid=$e.D['ParentProcessGuid']
      Image=$e.D['Image']; CommandLine=$e.D['CommandLine']; ParentImage=$e.D['ParentImage']; ParentCommandLine=$e.D['ParentCommandLine']
      User=$e.D['User']; LogonId=$e.D['LogonId']; Hashes=$e.D['Hashes']; IntegrityLevel=$e.D['IntegrityLevel']; Text=$e.D['CommandLine']
    }
    $null = $procRecs.Add($r)
    if ($r.Image -match '(?i)(powershell|pwsh)\.exe') { $null = $input_.Add($r) }
  } elseif ($e.Id -eq '4688') {
    $r = [pscustomobject]@{
      Computer=$e.Comp; TimeUtc=$e.Utc; RecordId=$e.Rec; Source='Security-4688'
      ProcessGuid=''; Pid=(H2D $e.D['NewProcessId']); Ppid=(H2D $e.D['ProcessId']); ParentGuid=''
      Image=$e.D['NewProcessName']; CommandLine=$e.D['CommandLine']; ParentImage=$e.D['ParentProcessName']; ParentCommandLine=''
      User=("$($e.D['SubjectDomainName'])\$($e.D['SubjectUserName'])"); LogonId=$e.D['SubjectLogonId']; Hashes=''; IntegrityLevel=$e.D['MandatoryLabel']; Text=$e.D['CommandLine']
    }
    $null = $procRecs.Add($r)
    if ($r.Image -match '(?i)(powershell|pwsh)\.exe') { $null = $input_.Add($r) }
  } elseif ($e.Id -eq '4104') {
    $r = [pscustomobject]@{
      Computer=$e.Comp; TimeUtc=$e.Utc; RecordId=$e.Rec; Source='PowerShell-4104'
      ExecPid=$e.ExecPid; ScriptBlockId=$e.D['ScriptBlockId']; MessageNumber=$e.D['MessageNumber']; MessageTotal=$e.D['MessageTotal']
      CommandLine=''; Text=[string]$e.D['ScriptBlockText']
    }
    $null = $input_.Add($r)
  }
}
$index = New-Soc002ProcessIndex -Records @($procRecs)
$assessment = Invoke-Soc002P8Assessment -Records @($input_) -ProcessIndex $index

$lib8 = Get-Soc002P8LibIdentity
$lib6 = Get-Soc002LibIdentity
$lines = New-Object System.Collections.ArrayList
$null = $lines.Add("=== SOC-002 PHASE 8 :: DET-003 RUN OVER PRESERVED TELEMETRY ($Label) ===")
$null = $lines.Add("Raw input      = $Raw   ($($events.Count) events)")
$null = $lines.Add("DET-003 library= $($lib8.LibVersion) sha256=$($lib8.LibSha256)")
$null = $lines.Add("DET-001 library= $($lib6.LibVersion) sha256=$($lib6.LibSha256)  (read-only, for contrast only)")
$null = $lines.Add("Replay is offline and read-only. Nothing was executed; the preserved XML was parsed as text.")
$null = $lines.Add('-------------------------------------------------------------------')
$null = $lines.Add('')
$null = $lines.Add('--- A) DET-003 CANDIDATES IN THE REPLAYED EVIDENCE -------------------')
$i = 0
foreach ($a in $assessment.Results) { $i++; $null = $lines.Add((Format-Soc002P8Det003 -Det $a.Det003 -Index $i -MaxText $MaxText)) }
$null = $lines.Add('')
$null = $lines.Add("DET-003 candidates = $($assessment.Stats.Candidates) of $($assessment.Stats.RecordsExamined) records examined")
$null = $lines.Add("   LOW=$($assessment.Stats.Low)  MEDIUM=$($assessment.Stats.Medium)")
$null = $lines.Add('')

# ---- B) the DET-001 v2 vs DET-003 contrast on every PowerShell create event ----
$null = $lines.Add('--- B) DET-001 v2 TRIGGER vs DET-003 TRIGGER, per PowerShell process-create ---')
$null = $lines.Add('    (DET-001 keys on the encoded-command CLI switch; DET-003 keys on a Base64 reconstruction CALL)')
$null = $lines.Add('    utc                        pid   ppid  det001  det003  indicator        image/parent')
$allPs = @($procRecs | Where-Object { $_.Image -match '(?i)(powershell|pwsh)\.exe' } | Sort-Object TimeUtc)
foreach ($p in $allPs) {
  $d1 = Test-Soc002EncodedCommandLine -CommandLine $p.CommandLine
  $s3 = Test-Soc002P8Base64Reconstruction -Text $p.CommandLine
  $null = $lines.Add(("    {0}  {1,-5} {2,-5} {3,-7} {4,-7} {5,-16} {6} <- {7}" -f `
     ([datetime]$p.TimeUtc).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'), $p.Pid, $p.Ppid,
     $(if($d1){'HIT'}else{'miss'}), $(if($s3.Triggered){'HIT'}else{'miss'}),
     $(if($s3.Triggered){($s3.IndicatorIds -join ',')}else{'-'}),
     (Get-Soc002Leaf $p.Image), (Get-Soc002Leaf $p.ParentImage)))
}
$null = $lines.Add('')
# ---- C) 4104 script blocks ----
$null = $lines.Add('--- C) PowerShell 4104 blocks: DET-003 trigger per ScriptBlockId ----------------')
$sb4104 = @($input_ | Where-Object { $_.Source -eq 'PowerShell-4104' } | Sort-Object TimeUtc)
foreach ($b in $sb4104) {
  $s3 = Test-Soc002P8Base64Reconstruction -Text $b.Text
  $null = $lines.Add(("    rec={0,-7} utc={1} execpid={2,-5} sb={3} det003={4} {5}" -f `
     $b.RecordId, ([datetime]$b.TimeUtc).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'), $b.ExecPid, $b.ScriptBlockId,
     $(if($s3.Triggered){'HIT'}else{'miss'}), $(if($s3.Triggered){'('+($s3.IndicatorIds -join ',')+')'}elseif($s3.WordOnlyMention){'(word-only, non-trigger)'}else{''})))
}
$null = $lines.Add('')
$null = $lines.Add('--- D) CORRELATION (CORR-002) OVER THE REPLAYED EVIDENCE ----------------------')
$c = 0
foreach ($a in $assessment.Results) { $c++; $null = $lines.Add((Format-Soc002P8Correlation -Corr $a.Corr -Index $c)) }
$null = $lines.Add('')

# ---- E) targeted cross-check: the Phase 7 payload, located by its own signature ---
# PID alone is not safe here: the session window reuses PID 1428 several times, so
# the payload is located by the base64 blob ONLY the Phase 7 payload carries
# (base64 of "SOC002-PHASE7-B..."), not by pid.
$null = $lines.Add('--- E) TARGETED PHASE 7 CROSS-CHECK (payload located by its blob signature) ---')
$sig = 'U09DMDAyLVBIQVNFNy1C'
$payload = @($allPs | Where-Object { [string]$_.CommandLine -like "*$sig*" } | Sort-Object TimeUtc)
if ($payload.Count -eq 0) {
  $null = $lines.Add("  Phase 7 payload signature ($sig) NOT PRESENT in this evidence file.")
} else {
  foreach ($rec in $payload) {
    $d1 = Test-Soc002EncodedCommandLine -CommandLine $rec.CommandLine
    $s3 = Test-Soc002P8Base64Reconstruction -Text $rec.CommandLine
    $null = $lines.Add("  PAYLOAD  utc=$(([datetime]$rec.TimeUtc).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))  PID=$($rec.Pid)  PPID=$($rec.Ppid)  parent=$(Get-Soc002Leaf $rec.ParentImage)  [blob signature matched]")
    $null = $lines.Add("    DET-001 v2 (encoded switch) = $(if($d1){'TRIGGER'}else{'NO TRIGGER'})")
    $null = $lines.Add("    DET-003    (reconstruction)= $(if($s3.Triggered){'TRIGGER ' + ($s3.IndicatorIds -join ',')}else{'NO TRIGGER'})   severity=$(if($s3.Triggered){$s3.Severity}else{'-'})")
    $tr = @($allPs | Where-Object { $_.Pid -eq $rec.Ppid -and $_.TimeUtc -le $rec.TimeUtc } | Sort-Object TimeUtc | Select-Object -Last 1)
    if ($tr) {
      $td1 = Test-Soc002EncodedCommandLine -CommandLine $tr.CommandLine
      $ts3 = Test-Soc002P8Base64Reconstruction -Text $tr.CommandLine
      $null = $lines.Add("  TRANSPORT utc=$(([datetime]$tr.TimeUtc).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))  PID=$($tr.Pid)  [immediate parent]")
      $null = $lines.Add("    DET-001 v2 (encoded switch) = $(if($td1){'TRIGGER'}else{'NO TRIGGER'})")
      $null = $lines.Add("    DET-003    (reconstruction)= $(if($ts3.Triggered){'TRIGGER'}else{'NO TRIGGER'})")
    }
  }
}
$null = $lines.Add('')
$lines -join "`n" | Set-Content -LiteralPath $Out -Encoding utf8
if ($JsonOut) {
  $summary = [pscustomobject]@{
    label = $Label; raw = $Raw; events = $events.Count
    records_examined = $assessment.Stats.RecordsExamined
    det003_candidates = $assessment.Stats.Candidates
    det003_low = $assessment.Stats.Low; det003_medium = $assessment.Stats.Medium
    word_only_non_triggers = $assessment.Stats.WordOnlyNonTriggers
    comment_suppressed = $assessment.Stats.CommentSuppressed
    candidates = @($assessment.Results | ForEach-Object {
      [pscustomobject]@{ source=$_.Det003.SourceEvent; recordid=$_.Det003.SourceRecordId; pid=$_.Det003.Pid
        scriptblockid=$_.Det003.ScriptBlockId; indicator=$_.Det003.MatchedIndicator; severity=$_.Det003.Severity
        class=$_.Det003.Class; host=$_.Det003.Host }
    })
  }
  $summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $JsonOut -Encoding utf8
}
"wrote $Out" + $(if ($JsonOut) { " and $JsonOut" } else { '' })
