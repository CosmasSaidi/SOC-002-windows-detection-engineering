<#
  SOC-002 | PHASE 7 | RAW-XML -> READABLE EVIDENCE FORMATTER
  =====================================================================
  Runs offline on the operator workstation. Reads the raw EVXML|<xml> lines
  produced by scripts/collect_raw_events.py and prints the analyst-facing view
  of the three required sources (Security 4688, Sysmon Event 1, PowerShell
  4104), plus a per-record marker check.

  It performs no detection and no classification - it only renders what the
  collector captured.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$Raw,
  [Parameter(Mandatory=$true)][string]$Out,
  [int]$MaxText = 900
)
$ErrorActionPreference = 'Stop'
$marker = 'SOC002-PHASE7-BLINDSPOT-TEST'
function Cut([string]$t, [int]$n) { if ($null -eq $t) { $t = '' }; if ($t.Length -gt $n) { $t.Substring(0,$n) + '...[cut]' } else { $t } }
function HexToDec([string]$v) {
  if ([string]::IsNullOrWhiteSpace($v)) { return '' }
  $v = $v.Trim(); if ($v -match '^0x[0-9a-fA-F]+$') { return ([Convert]::ToInt64($v.Substring(2),16)).ToString() }
  return $v
}
function P($h, [string[]]$names) { foreach ($n in $names) { if ($h.ContainsKey($n) -and "$($h[$n])" -ne '') { return $h[$n] } } return '' }

$lines = New-Object System.Collections.ArrayList
$records = @()
foreach ($line in (Get-Content -LiteralPath $Raw)) {
  if (-not $line.StartsWith('EVXML|')) { if ($line.Trim()) { $null = $lines.Add($line) }; continue }
  $x = [xml]$line.Substring(6)
  $d = @{}
  foreach ($n in @($x.Event.EventData.Data)) { if ($n.Name) { $d[$n.Name] = [string]$n.'#text' } }
  $records += [pscustomobject]@{
    Id  = [string]$x.Event.System.EventID
    Rec = [string]$x.Event.System.EventRecordID
    Comp= [string]$x.Event.System.Computer
    Prov= [string]$x.Event.System.Provider.Name
    Utc = ([datetime]$x.Event.System.TimeCreated.SystemTime).ToUniversalTime()
    ExecPid = [string]$x.Event.System.Execution.ProcessID
    D   = $d
  }
}

foreach ($id in '4688','1','4104','3') {
  $set = @($records | Where-Object { $_.Id -eq $id } | Sort-Object Utc)
  $title = switch ($id) { '4688' { 'A) Security 4688 - process creation (CommandLine audit)' }
                         '1'    { 'B) Sysmon Event ID 1 - ProcessCreate' }
                         '4104' { 'C) PowerShell Event ID 4104 - ScriptBlockLogging' }
                         '3'    { 'D) Sysmon Event ID 3 - NetworkConnect (proves/disproves network contact)' } }
  $null = $lines.Add("--- $title ---")
  $null = $lines.Add("records = $($set.Count)")
  $i = 0
  foreach ($r in $set) {
    $i++; $d = $r.D
    $null = $lines.Add(("[{0}-{1:D3}] Utc={2} RecId={3} Computer={4} Provider={5}" -f $id, $i,
      $r.Utc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'), $r.Rec, $r.Comp, $r.Prov))
    if ($id -eq '4688') {
      $null = $lines.Add("        NewProcessId=$((HexToDec (P $d @('NewProcessId'))))  NewProcessName=$(P $d @('NewProcessName'))")
      $null = $lines.Add("        CreatorPID=$((HexToDec (P $d @('ProcessId'))))  ParentProcessName=$(P $d @('ParentProcessName'))")
      $null = $lines.Add("        Subject=$(P $d @('SubjectDomainName'))\$(P $d @('SubjectUserName'))  LogonId=$(P $d @('SubjectLogonId'))  Elevation=$(P $d @('TokenElevationType'))  Integrity=$(P $d @('MandatoryLabel'))")
      $null = $lines.Add("        CommandLine=$(Cut (P $d @('CommandLine')) $MaxText)")
    } elseif ($id -eq '1') {
      $null = $lines.Add("        ProcessGuid=$(P $d @('ProcessGuid'))  PID=$((HexToDec (P $d @('ProcessId'))))")
      $null = $lines.Add("        Image=$(P $d @('Image'))")
      $null = $lines.Add("        ParentProcessGuid=$(P $d @('ParentProcessGuid'))  PPID=$((HexToDec (P $d @('ParentProcessId'))))  ParentImage=$(P $d @('ParentImage'))")
      $null = $lines.Add("        User=$(P $d @('User'))  LogonId=$(P $d @('LogonId'))  Integrity=$(P $d @('IntegrityLevel'))")
      $null = $lines.Add("        Hashes=$(P $d @('Hashes'))")
      $null = $lines.Add("        CommandLine=$(Cut (P $d @('CommandLine')) $MaxText)")
      $null = $lines.Add("        ParentCommandLine=$(Cut (P $d @('ParentCommandLine')) $MaxText)")
    } elseif ($id -eq '3') {
      $null = $lines.Add("        PID=$((HexToDec (P $d @('ProcessId'))))  Image=$(P $d @('Image'))  User=$(P $d @('User'))")
      $null = $lines.Add("        Proto=$(P $d @('Protocol'))  Initiated=$(P $d @('Initiated'))  Source=$(P $d @('SourceIp')):$(P $d @('SourcePort'))  Destination=$(P $d @('DestinationIp')):$(P $d @('DestinationPort'))  DestHost=$(P $d @('DestinationHostname'))")
    } else {
      $txt = [string](P $d @('ScriptBlockText'))
      $flag = if ($txt -match [regex]::Escape($marker)) { "   <== PHASE7 MARKER PRESENT" }
              elseif ($txt -match '(?i)FromBase64String') { "   <== contains [Convert]::FromBase64String" } else { '' }
      $null = $lines.Add("        ExecutingPID=$($r.ExecPid)  ScriptBlockId=$(P $d @('ScriptBlockId'))  Msg=$(P $d @('MessageNumber'))/$(P $d @('MessageTotal'))  Path=$(P $d @('Path'))")
      $null = $lines.Add("        Len=$($txt.Length)$flag")
      $null = $lines.Add("        Text=$(Cut ($txt -replace '\r?\n',' | ') $MaxText)")
    }
  }
  $null = $lines.Add('')
}
$lines -join "`n" | Set-Content -LiteralPath $Out -Encoding utf8
"wrote $Out  ($($records.Count) events)"
