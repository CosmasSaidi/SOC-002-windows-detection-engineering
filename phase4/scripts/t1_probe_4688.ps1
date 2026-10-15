$ErrorActionPreference='Continue'
"=== Registry key last write (approx via reg export / info) ==="
"=== Latest 5 x 4688 raw CommandLine presence ==="
$evts = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 8 -ErrorAction SilentlyContinue
if (-not $evts) { "NO 4688 FOUND" } else {
  foreach ($e in $evts) {
    $x = [xml]$e.ToXml()
    $d = @{}
    foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
    [pscustomobject]@{
      EventRecordID = $e.RecordId
      TimeCreated   = $e.TimeCreated
      NewProcessName= $d['NewProcessName']
      CommandLine   = if ($d.ContainsKey('CommandLine')) { $d['CommandLine'] } else { '<absent>' }
      SubjectUser   = "$($d['SubjectDomainName'])\$($d['SubjectUserName'])"
      CreatorPID    = $d['ProcessId']
    } | Format-List | Out-String
  }
}
"=== Total 4688 count in Security log & oldest/newest ==="
$all = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -ErrorAction SilentlyContinue
"count=$($all.Count)"
if ($all.Count) { "oldest=$($all[-1].TimeCreated)  newest=$($all[0].TimeCreated)" }
"=== Security log retention ==="
$log = Get-WinEvent -ListLog Security
"LogMode=$($log.LogMode)  MaxSizeKB=$([math]::Round($log.MaximumSizeInBytes/1KB))  FileSizeKB=$([math]::Round($log.FileSizeInBytes/1KB))  RecordCount=$($log.RecordCount)"
