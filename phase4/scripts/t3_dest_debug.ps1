$ErrorActionPreference='Continue'
"NOW=" + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
$sy = Get-WinEvent -LogName ForwardedEvents -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -like '*Sysmon*' }
"totalSysmonFwd=$($sy.Count)"
"newestUtcTime=$($sy[0].TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
"=== newest 6 Sysmon Event 1 with their CommandLine ==="
$sy | Where-Object Id -eq 1 | Select-Object -First 6 | ForEach-Object { $x=[xml]$_.ToXml(); $d=@{}; foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.'#text'}; "FwdRec=$($_.RecordId) $($_.TimeCreated.ToUniversalTime().ToString('HH:mm:ss')) PG=$($d['ProcessGuid']) CL=$($d['CommandLine'])" }
"=== search specific ProcessGuid ==="
$pg='{edcef402-f7be-6acf-d304-000000000700}'
$hit = $sy | Where-Object { $_.Message -match [regex]::Escape($pg) } | Select-Object -First 1
if ($hit) { "FOUND guid event: FwdRec=$($hit.RecordId) Id=$($hit.Id)" } else { "guid not present" }
"=== newest 6 Sysmon Event 3 ==="
$sy | Where-Object Id -eq 3 | Select-Object -First 6 | ForEach-Object { $x=[xml]$_.ToXml(); $d=@{}; foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.'#text'}; "FwdRec=$($_.RecordId) $($_.TimeCreated.ToUniversalTime().ToString('HH:mm:ss')) PG=$($d['ProcessGuid']) SrcPort=$($d['SourcePort']) Dst=$($d['DestinationIp']):$($d['DestinationPort'])" }
