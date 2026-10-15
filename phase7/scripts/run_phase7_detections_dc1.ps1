<#
  SOC-002 | PHASE 7 | EXISTING-DETECTION-STACK RUNNER  (on SOC002-DC1)
  =====================================================================
  Runs the UNMODIFIED Phase 6 detection stack over a Phase 7 window:

      SOC002-DET-001 v2   detect_encoded_powershell_v2.ps1
      SOC002-DET-002      detect_powershell_lineage.ps1
      SOC002-CORR-001     correlate_det001_det002.ps1

  This wrapper contains NO detection logic. It only:
    - converts a UTC window into the collector's local time (the Phase 6
      detectors take local windows, as they did in Phase 6), and
    - invokes the three Phase 6 scripts with their documented parameters
      (-Since / -Until / -Marker / -LibPath).

  It prints the SHA256 of every Phase 6 detection file it invokes so the
  "unchanged detection logic" claim is checkable from the evidence itself.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$SinceUtc,
  [Parameter(Mandatory=$true)][string]$UntilUtc,
  [ValidateSet('all','det001','det002','corr001')][string]$Detector = 'all',
  [string]$Marker = 'SOC002-PHASE7-BLINDSPOT-TEST',
  [string]$DetDir = 'C:\Windows\Temp\soc002-phase7\detections'
)
$ErrorActionPreference = 'Continue'

function ConvertTo-UtcDate([string]$s) {
  [datetime]::Parse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal)
}
$sU = ConvertTo-UtcDate $SinceUtc
$eU = ConvertTo-UtcDate $UntilUtc
$sL = $sU.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
$eL = $eU.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')

'### PHASE7 DETECTION STACK RUN ==='
"RunOn        = $env:COMPUTERNAME"
"WindowUtc    = $($sU.ToString('yyyy-MM-ddTHH:mm:ssZ')) .. $($eU.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
"WindowLocal  = $sL .. $eL   (collector local, as passed to the Phase 6 detectors)"
"Marker       = $Marker"
"LibDir       = $DetDir"
'--- Phase 6 detection file integrity (sha256 taken NOW, on the collector) ---'
foreach ($f in 'lib_soc002_v2.ps1','lib_soc002_windows.ps1','detect_encoded_powershell_v2.ps1','detect_powershell_lineage.ps1','correlate_det001_det002.ps1') {
  $p = Join-Path $DetDir $f
  "{0,-38} {1}" -f $f, (Get-FileHash -Algorithm SHA256 -Path $p -EA SilentlyContinue).Hash
}
''

if ($Detector -in @('all','det001')) {
  '##################### SOC002-DET-001 v2 #####################'
  & (Join-Path $DetDir 'detect_encoded_powershell_v2.ps1') -Since $sL -Until $eL -Marker $Marker -LibPath $DetDir -MaxAlerts 500
  ''
}
if ($Detector -in @('all','det002')) {
  '##################### SOC002-DET-002 #####################'
  & (Join-Path $DetDir 'detect_powershell_lineage.ps1') -Since $sL -Until $eL -LibPath $DetDir -MaxRecords 400
  ''
}
if ($Detector -in @('all','corr001')) {
  '##################### SOC002-CORR-001 #####################'
  & (Join-Path $DetDir 'correlate_det001_det002.ps1') -Since $sL -Until $eL -Marker $Marker -LibPath $DetDir
  ''
}
'### END PHASE7 DETECTION STACK RUN ###'
