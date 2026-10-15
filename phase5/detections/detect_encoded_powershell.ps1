<#
  SOC-002 | Phase 5 | DETECTION 001
  ---------------------------------------------------------------------------
  Title      : Encoded PowerShell Execution Observed - Investigation Required
  Data source: Windows Event Forwarding collector - ForwardedEvents (SOC002-DC1)
  Primary    : Sysmon Event 1 where Image is powershell.exe/pwsh.exe AND the
               CommandLine contains an encoded-command switch
               (-EncodedCommand | -enc | -en | -e).
  Corroborate: PowerShell Event 4104 whose executing process id and time window
               match the Sysmon process (or whose text carries a known marker).
  Output     : one alert block per hit, plus a READ-ONLY decode of the command.
  IMPORTANT  : This detection says "investigate". It does NOT say "malicious".
  Usage      : .\detect_encoded_powershell.ps1 [-Minutes 1440] [-Since <local-dt>]
                                              [-Until <local-dt>] [-Marker <text>]
                                              [-MaxText 400]
#>
param(
  [string]$LogName = 'ForwardedEvents',
  [int]$Minutes = 1440,
  [string]$Since = '',
  [string]$Until = '',
  [string]$Marker = '',
  [int]$MaxText = 400
)
$ErrorActionPreference = 'SilentlyContinue'
$now   = Get-Date
$start = if ($Since) { Get-Date $Since } else { $now.AddMinutes(-$Minutes) }
$end   = if ($Until) { Get-Date $Until } else { $now.AddMinutes(1) }
$encRx = '(?i)\s-(e|en|enc|encodedcommand)(\s|$)'
$b64Rx = '(?i)-(?:e|en|enc|encodedcommand)\s+"?([A-Za-z0-9+/=]{16,})'
$imgRx = '(?i)(powershell|pwsh)\.exe'
$alerts = 0
function Cut($s, $n) { $s = [string]$s; if ($s.Length -gt $n) { $s.Substring(0, $n) + '...[cut]' } else { $s } }

"=== SOC002-DET-001 :: Encoded PowerShell Execution ==="
"Log=$LogName  Window=$($start.ToString('yyyy-MM-dd HH:mm:ss')) .. $($end.ToString('yyyy-MM-dd HH:mm:ss')) (local)"
"-------------------------------------------------------------------"

foreach ($e in (Get-WinEvent -FilterHashtable @{LogName=$LogName; Id=1; StartTime=$start; EndTime=$end} -EA SilentlyContinue)) {
  $x = [xml]$e.ToXml()
  $d = @{}; foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
  if ($d['Image']       -notmatch $imgRx) { continue }
  if ($d['CommandLine'] -notmatch $encRx) { continue }

  # 1) decode the encoded command (READ-ONLY: never executed)
  $decoded = '<none>'
  if ($d['CommandLine'] -match $b64Rx) {
    try   { $decoded = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(($matches[1] -replace '\s',''))) }
    catch { $decoded = '<base64 decode failed>' }
  }

  # 2) corroborating 4104 from the SAME process id within a small window
  $procId = "$($d['ProcessId'])"
  $corr = @()
  foreach ($q in (Get-WinEvent -FilterHashtable @{LogName=$LogName; Id=4104; StartTime=$e.TimeCreated.AddSeconds(-5); EndTime=$e.TimeCreated.AddSeconds(45)} -EA SilentlyContinue)) {
    $qx = [xml]$q.ToXml()
    if ("$($qx.Event.System.Execution.ProcessID)" -eq $procId) { $corr += $q }
    elseif ($Marker -and $q.ToXml() -match [regex]::Escape($Marker)) { $corr += $q }
  }

  $alerts++
  ""
  "[ALERT $('{0:D3}' -f $alerts)] Encoded PowerShell execution observed - INVESTIGATION REQUIRED"
  "  Detection        = SOC002-DET-001  (severity MEDIUM: triage, not proof of compromise)"
  "  Host             = $($x.Event.System.Computer)"
  "  User             = $($d['User'])   LogonId=$($d['LogonId'])"
  "  EventUtc         = $($e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
  "  SysmonRecordId   = $($e.RecordId)   ProcessGuid=$($d['ProcessGuid'])"
  "  Process          = $($d['Image'])   (PID $($d['ProcessId']))"
  "  Parent           = $($d['ParentImage'])  (PPID $($d['ParentProcessId']))"
  "  ParentCommandLine= $(Cut $d['ParentCommandLine'] $MaxText)"
  "  Hashes           = $($d['Hashes'])"
  "  EncodedSwitch    = -EncodedCommand (indicator matched)"
  "  CommandLine      = $(Cut $d['CommandLine'] $MaxText)"
  "  DecodedScript    = <<<$(Cut $decoded ($MaxText*2))>>>  [decoded by detection - NOT executed]"
  if ($Marker -and $decoded -match [regex]::Escape($Marker)) { "  MarkerMatch      = $Marker  (controlled-test marker present in decoded script)" }
  if ($corr.Count -gt 0) {
    foreach ($c in $corr) {
      $cx = [xml]$c.ToXml(); $cd = @{}; foreach ($n in $cx.Event.EventData.Data) { $cd[$n.Name] = $n.'#text' }
      "  Corroboration    = PowerShell 4104 RecId=$($c.RecordId) ExecPID=$($cx.Event.System.Execution.ProcessID) ScriptBlockId=$($cd['ScriptBlockId']) Msg=$($cd['MessageNumber'])/$($cd['MessageTotal'])"
      "                     4104Text=$(Cut ($cd['ScriptBlockText'] -replace '\r?\n',' ') 200)"
    }
  } else { "  Corroboration    = NONE FOUND (4104 missing / not forwarded - see limitations)" }
}
""
"-------------------------------------------------------------------"
"Total alerts = $alerts"
if ($alerts -eq 0) { "No encoded PowerShell execution matched the criteria in this window." }
