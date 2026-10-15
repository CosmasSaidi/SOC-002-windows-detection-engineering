<#
  SOC-002 | Phase 6 | TASK 10 - SHA256 MANIFEST BUILDER
  ======================================================
  Produces evidence/SHA256_MANIFEST.txt containing:
    A. sha256 of every Phase 6 artefact (so the phase is reproducible/auditable)
    B. a verification that EVERY Phase 5 file still matches the hash recorded in
       phase5/evidence/MANIFEST.txt - i.e. proof that Phase 5 was preserved.

  Read-only with respect to Phase 5: it only hashes Phase 5 files.
  Usage: pwsh -File build_manifest.ps1
#>
[CmdletBinding()]
param(
  [string]$Phase6Root = (Split-Path -Parent $PSScriptRoot),
  [string]$Phase5Root = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'phase5'),
  [string]$OutFile    = (Join-Path (Split-Path -Parent $PSScriptRoot) 'evidence/SHA256_MANIFEST.txt')
)
$ErrorActionPreference = 'Stop'
$selfName = 'evidence/SHA256_MANIFEST.txt'

function Get-RelSha([string]$path, [string]$root) {
  $rel = $path.Substring($root.Length).TrimStart('/', '\') -replace '\\', '/'
  [pscustomobject]@{ Rel = $rel; Sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash; Bytes = (Get-Item -LiteralPath $path).Length }
}

$o = New-Object System.Collections.ArrayList
function W([string]$s) { $null = $o.Add($s) }

W 'SOC-002 PHASE 6 - SHA256 MANIFEST'
W '=================================='
W "Generated (UTC) : $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
W 'Scope           : every file under ~/soc-lab/phase6 (this manifest excluded),'
W '                  plus verification that no Phase 5 file has changed.'
W 'No credentials or secrets are stored anywhere in this tree.'
W ''
W '-------------------------------------------------------------------------------'
W "SECTION A - PHASE 6 ARTEFACTS  (bytes | sha256)"
W '-------------------------------------------------------------------------------'

$files = @(Get-ChildItem -LiteralPath $Phase6Root -Recurse -File |
           Where-Object { $_.FullName -notlike "*$selfName" } |
           Sort-Object FullName)
foreach ($f in $files) {
  $r = Get-RelSha $f.FullName $Phase6Root
  W ('{0} | {1} | {2}' -f $r.Rel, $r.Bytes, $r.Sha)
}
W ''
W "Phase 6 files hashed = $($files.Count)"
W ''
W '-------------------------------------------------------------------------------'
W 'SECTION B - PHASE 5 PRESERVATION CHECK'
W '-------------------------------------------------------------------------------'
W 'Each Phase 5 file is re-hashed now and compared with the sha256 recorded in'
W 'phase5/evidence/MANIFEST.txt (written at the end of Phase 5). Any difference'
W 'would mean Phase 6 modified Phase 5 evidence, which it must not do.'
W ''

$manifest = Join-Path $Phase5Root 'evidence/MANIFEST.txt'
$ok = 0; $bad = New-Object System.Collections.ArrayList; $missing = New-Object System.Collections.ArrayList
foreach ($line in (Get-Content -LiteralPath $manifest)) {
  if ($line -notmatch '^(\S+)\s\|\s(\d+)\s\|\s([0-9a-fA-F]{64})\s*$') { continue }
  $rel = $Matches[1]; $bytes = [int64]$Matches[2]; $want = $Matches[3].ToUpperInvariant()
  $p = Join-Path $Phase5Root ($rel -replace '/', '\')
  if (-not (Test-Path -LiteralPath $p)) { $null = $missing.Add($rel); continue }
  $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash
  if ($got -eq $want) { $ok++ }
  else { $null = $bad.Add("$rel  expected=$want  actual=$got") }
}
W "Phase 5 files verified unchanged : $ok"
W "Phase 5 files CHANGED            : $($bad.Count)"
W "Phase 5 files MISSING            : $($missing.Count)"
foreach ($b in $bad)     { W "  CHANGED: $b" }
foreach ($m in $missing) { W "  MISSING: $m" }
W ''
if ($bad.Count -eq 0 -and $missing.Count -eq 0) {
  W 'RESULT: Phase 5 evidence is byte-for-byte preserved. Phase 6 added only new files.'
} else {
  W 'RESULT: ATTENTION - Phase 5 and the manifest disagree. Investigate before trusting Phase 6.'
}
W ''
W '-------------------------------------------------------------------------------'
W 'SECTION C - PHASE 5 FILES ADDED SINCE ITS MANIFEST (informational)'
W '-------------------------------------------------------------------------------'
$recorded = @{}
foreach ($line in (Get-Content -LiteralPath $manifest)) {
  if ($line -match '^(\S+)\s\|\s(\d+)\s\|\s([0-9a-fA-F]{64})\s*$') { $recorded[$Matches[1]] = $true }
}
$extra = @(Get-ChildItem -LiteralPath $Phase5Root -Recurse -File |
           ForEach-Object { (Get-RelSha $_.FullName $Phase5Root).Rel } |
           Where-Object { -not $recorded.ContainsKey($_) } | Sort-Object)
if ($extra.Count -eq 0) { W 'None - the Phase 5 tree contains exactly the files its manifest lists.' }
else { foreach ($e in $extra) { W "  not in Phase 5 manifest: $e" } }

[IO.File]::WriteAllText($OutFile, ($o -join "`n"))
Write-Output "wrote $OutFile"
Write-Output ("SECTION A files = {0} ; SECTION B verified = {1} ; changed = {2} ; missing = {3}" -f $files.Count, $ok, $bad.Count, $missing.Count)
if ($extra.Count -gt 0) { Write-Output ("extra phase5 files = {0}" -f $extra.Count) }
