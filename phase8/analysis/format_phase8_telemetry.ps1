<#
  SOC-002 | PHASE 8 | LIVE TELEMETRY RENDERING (offline, read-only)
  Renders the raw EVXML|<xml> lines captured from WS001 (local logs) and DC1
  (ForwardedEvents), and annotates each record with whether DET-003 triggers on
  it. No detection state is changed; the trigger is only called for a label.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$Raw,
  [Parameter(Mandatory=$true)][string]$Out,
  [int]$MaxText = 600,
  [string]$Phase8Lib = "$PSScriptRoot/../detections"
)
$ErrorActionPreference = 'Stop'
. (Join-Path $Phase8Lib 'lib_soc002_phase8.ps1')
function Cut([string]$t,[int]$n){ if($null -eq $t){$t=''}; if($t.Length -gt $n){$t.Substring(0,$n)+'...[cut]'}else{$t} }
function H2D([string]$v){ if([string]::IsNullOrWhiteSpace($v)){return ''}; if($v -match '^0x[0-9a-fA-F]+$'){return ([Convert]::ToInt64($v.Substring(2),16)).ToString()}; return $v }
function P($h,[string[]]$names){ foreach($n in $names){ if($h.ContainsKey($n) -and "$($h[$n])" -ne ''){return $h[$n]} } return '' }

$recs = New-Object System.Collections.ArrayList
foreach ($line in (Get-Content -LiteralPath $Raw)) {
  if (-not $line.StartsWith('EVXML|')) { continue }
  $x = [xml]$line.Substring(6)
  $d = @{}; foreach ($n in @($x.Event.EventData.Data)) { if ($n.Name) { $d[$n.Name] = [string]$n.'#text' } }
  $null = $recs.Add([pscustomobject]@{
    Id=[string]$x.Event.System.EventID; Rec=[string]$x.Event.System.EventRecordID
    Comp=[string]$x.Event.System.Computer; Prov=[string]$x.Event.System.Provider.Name
    Utc=([datetime]$x.Event.System.TimeCreated.SystemTime).ToUniversalTime()
    ExecPid=[string]$x.Event.System.Execution.ProcessID; D=$d
  })
}
$L = New-Object System.Collections.ArrayList
$null = $L.Add("=== SOC-002 PHASE 8 :: LIVE TELEMETRY RENDERING ===")
$null = $L.Add("Raw = $Raw   ($($recs.Count) events)")
$null = $L.Add("DET-003 trigger applied as a label only: 'det003=FIRE(<id>)' means the reconstruction call is present.")
$null = $L.Add('===================================================')
foreach ($id in '4688','1','4104','3') {
  $set = @($recs | Where-Object { $_.Id -eq $id } | Sort-Object Utc)
  $title = switch ($id) { '4688'{'A) Security 4688 - process creation (CommandLine audit)'}
                         '1'{'B) Sysmon Event ID 1 - ProcessCreate'}
                         '4104'{'C) PowerShell Event ID 4104 - ScriptBlockLogging'}
                         '3'{'D) Sysmon Event ID 3 - NetworkConnect'} }
  $null = $L.Add(''); $null = $L.Add("--- $title ---"); $null = $L.Add("records = $($set.Count)")
  foreach ($r in $set) {
    $d = $r.D
    if ($id -eq '4688') {
      $s = Test-Soc002P8Base64Reconstruction -Text ([string](P $d @('CommandLine')))
      $null = $L.Add("[4688] utc=$($r.Utc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')) RecId=$($r.Rec) host=$($r.Comp)")
      $null = $L.Add("       NewPID=$((H2D (P $d @('NewProcessId'))))  NewProc=$(P $d @('NewProcessName'))")
      $null = $L.Add("       CreatorPID=$((H2D (P $d @('ProcessId'))))  Parent=$(P $d @('ParentProcessName'))")
      $null = $L.Add("       Subject=$(P $d @('SubjectDomainName'))\$(P $d @('SubjectUserName'))  LogonId=$(P $d @('SubjectLogonId'))")
      $null = $L.Add("       CommandLine=$(Cut (P $d @('CommandLine')) $MaxText)")
      $null = $L.Add("       det003=$(if($s.Triggered){'FIRE('+($s.IndicatorIds -join ',')+') sev='+$s.Severity}else{'clear'})")
    } elseif ($id -eq '1') {
      $s = Test-Soc002P8Base64Reconstruction -Text ([string](P $d @('CommandLine')))
      $null = $L.Add("[Sysmon1] utc=$($r.Utc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')) RecId=$($r.Rec) host=$($r.Comp)")
      $null = $L.Add("       ProcessGuid=$(P $d @('ProcessGuid'))  PID=$((H2D (P $d @('ProcessId'))))  PPID=$((H2D (P $d @('ParentProcessId'))))")
      $null = $L.Add("       Image=$(P $d @('Image'))  ParentImage=$(P $d @('ParentImage'))  ParentGuid=$(P $d @('ParentProcessGuid'))")
      $null = $L.Add("       User=$(P $d @('User'))  LogonId=$(P $d @('LogonId'))  Hashes=$(P $d @('Hashes'))")
      $null = $L.Add("       CommandLine=$(Cut (P $d @('CommandLine')) $MaxText)")
      $null = $L.Add("       det003=$(if($s.Triggered){'FIRE('+($s.IndicatorIds -join ',')+') sev='+$s.Severity}else{'clear'})")
    } elseif ($id -eq '4104') {
      $txt = [string](P $d @('ScriptBlockText'))
      $s = Test-Soc002P8Base64Reconstruction -Text $txt
      $null = $L.Add("[4104] utc=$($r.Utc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')) RecId=$($r.Rec) host=$($r.Comp)")
      $null = $L.Add("       ExecutingPID=$($r.ExecPid)  ScriptBlockId=$(P $d @('ScriptBlockId'))  Msg=$(P $d @('MessageNumber'))/$(P $d @('MessageTotal'))  Len=$($txt.Length)")
      $null = $L.Add("       Text=$(Cut ($txt -replace '\r?\n',' | ') $MaxText)")
      $null = $L.Add("       det003=$(if($s.Triggered){'FIRE('+($s.IndicatorIds -join ',')+') sev='+$s.Severity}else{'clear'})")
    } else {
      $null = $L.Add("[Sysmon3] utc=$($r.Utc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')) RecId=$($r.Rec) host=$($r.Comp)")
      $null = $L.Add("       PID=$((H2D (P $d @('ProcessId'))))  Image=$(P $d @('Image'))  User=$(P $d @('User'))")
      $null = $L.Add("       $(P $d @('Protocol'))  Initiated=$(P $d @('Initiated'))  Source=$(P $d @('SourceIp')):$(P $d @('SourcePort'))  Dest=$(P $d @('DestinationIp')):$(P $d @('DestinationPort'))  DestHost=$(P $d @('DestinationHostname'))")
    }
  }
}
$L -join "`n" | Set-Content -LiteralPath $Out -Encoding utf8
"wrote $Out"
