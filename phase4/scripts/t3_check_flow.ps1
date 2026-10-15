$ErrorActionPreference='Continue'
"=== ForwardedEvents provider/ID summary ==="
Get-WinEvent -LogName ForwardedEvents -MaxEvents 600 -ErrorAction SilentlyContinue |
  Group-Object ProviderName,Id | Sort-Object Count -Descending | Select-Object Name,Count | Format-Table -AutoSize | Out-String
"=== Sysmon events in ForwardedEvents (newest 5) ==="
$sy = Get-WinEvent -LogName ForwardedEvents -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -like '*Sysmon*' }
"count=$($sy.Count)"
$sy | Select-Object -First 5 | ForEach-Object { $x=[xml]$_.ToXml(); $d=@{}; foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.'#text'}; "FwdRecId=$($_.RecordId) Id=$($_.Id) Time=$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) Comp=$($x.Event.System.Computer) Image=$($d['Image']) Dst=$($d['DestinationIp']):$($d['DestinationPort'])" }
