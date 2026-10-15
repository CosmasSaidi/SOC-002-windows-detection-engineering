$ErrorActionPreference='Continue'
$SysmonLog = 'Microsoft-Windows-Sysmon/Operational'
$SecLog    = 'Security'
$PsLog     = 'Microsoft-Windows-PowerShell/Operational'
$marker    = 'SOC002-PHASE5-ENCODED-POWERSHELL'
$Start     = Get-Date '2026-10-15 00:58:00'
$End       = Get-Date '2026-10-15 01:08:00'

function Parse($e){
  $x=[xml]$e.ToXml(); $d=[ordered]@{}
  foreach($n in $x.Event.EventData.Data){ $d[$n.Name]=$n.'#text' }
  @{ Ev=$e; X=$x; D=$d }
}
function Raw($e,$label){
  "===RAWXML-BEGIN $label==="
  $e.ToXml()
  "===RAWXML-END $label==="
}

"=== SOC-002 PHASE5 TASK3 TELEMETRY COLLECTION ==="
"HOST          = $env:COMPUTERNAME"
"COLLECT_LOCAL = $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
"WINDOW_LOCAL  = $($Start.ToString('yyyy-MM-dd HH:mm:ss')) .. $($End.ToString('yyyy-MM-dd HH:mm:ss'))"
"LOGS          = Sysmon=$SysmonLog | Security=$SecLog | PowerShell=$PsLog"

"### A. SYSMON EVENT 1 (ProcessCreate) ==="
$e1 = @(Get-WinEvent -FilterHashtable @{LogName=$SysmonLog;Id=1;StartTime=$Start;EndTime=$End} -ErrorAction SilentlyContinue |
      Where-Object { $_.Message -match 'EncodedCommand' })
"MATCH_COUNT = $($e1.Count)"
foreach($e in $e1){
  $p=Parse $e
  "--- Sysmon Event1 RecId=$($e.RecordId) ---"
  "  TimeCreatedLocal = $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss.fff'))"
  "  TimeCreatedUtc   = $($e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
  "  Computer         = $($p.X.Event.System.Computer)"
  "  Provider         = $($p.X.Event.System.Provider.Name)"
  "  UtcTime          = $($p.D['UtcTime'])"
  "  ProcessGuid      = $($p.D['ProcessGuid'])"
  "  ProcessId        = $($p.D['ProcessId'])"
  "  Image            = $($p.D['Image'])"
  "  CommandLine      = $($p.D['CommandLine'])"
  "  User             = $($p.D['User'])"
  "  LogonId          = $($p.D['LogonId'])"
  "  ParentImage      = $($p.D['ParentImage'])"
  "  ParentProcessId  = $($p.D['ParentProcessId'])"
  "  ParentCommandLine= $($p.D['ParentCommandLine'])"
  "  Hashes           = $($p.D['Hashes'])"
  "  IntegrityLevel   = $($p.D['IntegrityLevel'])"
  "  CurrentDirectory = $($p.D['CurrentDirectory'])"
  Raw $e "Sysmon1-Rec$($e.RecordId)"
}

"### B. WINDOWS SECURITY 4688 (Process Creation) ==="
$e4 = @(Get-WinEvent -FilterHashtable @{LogName=$SecLog;Id=4688;StartTime=$Start;EndTime=$End} -ErrorAction SilentlyContinue |
      Where-Object { $_.Message -match 'EncodedCommand' })
"MATCH_COUNT = $($e4.Count)"
foreach($e in $e4){
  $p=Parse $e
  "--- 4688 RecId=$($e.RecordId) ---"
  "  TimeCreatedLocal = $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss.fff'))"
  "  TimeCreatedUtc   = $($e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
  "  Computer         = $($p.X.Event.System.Computer)"
  "  NewProcessId     = $($p.D['NewProcessId'])"
  "  NewProcessName   = $($p.D['NewProcessName'])"
  "  CommandLine      = $($p.D['CommandLine'])"
  "  ParentProcessName= $($p.D['ParentProcessName'])"
  "  CreatorProcessId = $($p.D['ProcessId'])"
  "  SubjectUserSid   = $($p.D['SubjectUserSid'])"
  "  SubjectUser      = $($p.D['SubjectDomainName'])\$($p.D['SubjectUserName'])"
  "  SubjectLogonId   = $($p.D['SubjectLogonId'])"
  "  TokenElevation   = $($p.D['TokenElevationType'])"
  "  MandatoryLabel   = $($p.D['MandatoryLabel'])"
  Raw $e "Security4688-Rec$($e.RecordId)"
}

"### C. POWERSHELL 4104 (ScriptBlock) marker-bearing ==="
$e5 = @(Get-WinEvent -FilterHashtable @{LogName=$PsLog;Id=4104;StartTime=$Start;EndTime=$End} -ErrorAction SilentlyContinue |
      Where-Object { $_.Message -match [regex]::Escape($marker) })
"MATCH_COUNT = $($e5.Count)"
foreach($e in $e5){
  $p=Parse $e
  "--- 4104 RecId=$($e.RecordId) ---"
  "  TimeCreatedLocal = $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss.fff'))"
  "  TimeCreatedUtc   = $($e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
  "  Computer         = $($p.X.Event.System.Computer)"
  "  ExecProcessId    = $($p.X.Event.System.ExecutionProcessID)"
  "  ExecThreadId     = $($p.X.Event.System.ExecutionThreadID)"
  "  MessageNumber    = $($p.D['MessageNumber'])"
  "  MessageTotal     = $($p.D['MessageTotal'])"
  "  ScriptBlockId    = $($p.D['ScriptBlockId'])"
  "  Path             = $($p.D['Path'])"
  "  ScriptBlockText  = <<<$($p.D['ScriptBlockText'])>>>"
  Raw $e "PowerShell4104-Rec$($e.RecordId)"
}

"### D. SYSMON EVENT 3 (NetworkConnect) for the encoded process ==="
$pg = @{}
foreach($e in $e1){ $p=Parse $e; if($p.D['ProcessGuid']){ $pg[$p.D['ProcessGuid']]=$true } }
$e3 = @(Get-WinEvent -FilterHashtable @{LogName=$SysmonLog;Id=3;StartTime=$Start;EndTime=$End} -ErrorAction SilentlyContinue |
      Where-Object { $_.Message -match 'powershell' })
"WINDOW_EVENT3_TOTAL = $($e3.Count)"
$hit=0
foreach($e in $e3){
  $p=Parse $e
  if($pg.ContainsKey($p.D['ProcessGuid'])){
    $hit++
    "--- Sysmon Event3 RecId=$($e.RecordId) (ProcessGuid matches encoded ps) ---"
    "  UtcTime     = $($p.D['UtcTime'])"
    "  ProcessGuid = $($p.D['ProcessGuid'])"
    "  Image       = $($p.D['Image'])"
    "  DestinationIp = $($p.D['DestinationIp'])"
    "  DestinationPort = $($p.D['DestinationPort'])"
    "  DestinationHostname = $($p.D['DestinationHostname'])"
    Raw $e "Sysmon3-Rec$($e.RecordId)"
  }
}
"NETWORK_EVENTS_FOR_ENCODED_PROCESS = $hit"
"### COLLECTION COMPLETE ###"
