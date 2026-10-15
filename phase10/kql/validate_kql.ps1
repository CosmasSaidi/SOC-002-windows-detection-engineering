#!/usr/bin/env pwsh
<#
  SOC-002 | PHASE 10 | validate_kql.ps1
  ---------------------------------------------------------------------------
  OFFLINE, STATIC validation of the Phase 10 KQL translation artefact set.

  It checks STRUCTURE and CLAIMS, not detection performance, and it does NOT
  execute KQL. There is no KQL parser, backend or Sentinel workspace in this
  environment; every check below is a deterministic local text/hash check.

  Verifies:
    1. required files exist and the two query files are non-empty
    2. EventID 1 is represented in both queries
    3. the Sysmon source is represented in both queries
    4. powershell.exe AND pwsh.exe are represented in both queries
    5. the encoded-command switch logic is represented in both queries
    6. the other detection's reconstruction logic (FromBase64String family) is
       absent from the query LOGIC
    7. the environment-specific baseline suppression (BASE-01) is absent from the
       query LOGIC
    8. PowerShell Event ID 4104 is not required by the primary query
    9. no affirmative production / live-Sentinel execution claim is made
   10. the notes and README document the assumptions and limitations
   11. SHA256_MANIFEST.txt is valid and covers every artefact
   12. the pre-existing Phase 5-9 files are byte-identical to the recorded
       PRE_KQL_HASHES.txt baseline (per-file + recursive tree digest)

  Requirements: PowerShell 7+. No internet, no KQL parser, no Sentinel.
  Exit code: 0 = PASS (all checks passed), 1 = FAIL.
#>
[CmdletBinding()]
param(
  [string]$KqlDir   = '',
  [string]$RepoRoot = ''
)

$ErrorActionPreference = 'Stop'
if (-not $KqlDir) { $KqlDir = $PSScriptRoot }
if (-not $KqlDir) { $KqlDir = (Get-Location).Path }
if (-not $RepoRoot) { $RepoRoot = (Split-Path (Split-Path $KqlDir -Parent) -Parent) }

$primaryPath = Join-Path $KqlDir 'SOC002-DET-001-encoded-powershell.kql'
$regexPath   = Join-Path $KqlDir 'SOC002-DET-001-encoded-powershell-regex.kql'
$notesPath   = Join-Path $KqlDir 'KQL_NOTES.md'
$readmePath  = Join-Path $KqlDir 'README.md'
$prePath     = Join-Path $KqlDir 'PRE_KQL_HASHES.txt'
$manPath     = Join-Path $KqlDir 'SHA256_MANIFEST.txt'
$reportPath  = Join-Path $KqlDir 'KQL_VALIDATION_REPORT.md'

$script:Results = New-Object System.Collections.ArrayList
function Add-Check {
  param([string]$Area, [string]$Name, [bool]$Pass, [string]$Detail = '')
  $null = $script:Results.Add([pscustomobject]@{ Area=$Area; Name=$Name; Pass=$Pass; Detail=$Detail })
  $tag = if ($Pass) { 'PASS' } else { 'FAIL' }
  Write-Host ("  [{0}] {1}" -f $tag, $Name)
  if ($Detail) { Write-Host ("         {0}" -f $Detail) }
}
function Section { param([string]$t) ; Write-Host '' ; Write-Host "== $t ==" }

# KQL logic = raw text with comment lines removed (a `//` comment is not logic).
function Get-KqlLogic {
  param([string]$Text)
  $kept = foreach ($line in ($Text -split "`n")) {
    if ($line.TrimStart().StartsWith('//')) { continue }
    $line
  }
  return ($kept -join "`n")
}

Write-Host '=== SOC-002 Phase 10 :: KQL translation validation (offline, static) ==='
Write-Host ("RepoRoot = {0}" -f $RepoRoot)
Write-Host ("KqlDir   = {0}" -f $KqlDir)
Write-Host 'NOTE: this validator does NOT execute KQL. No local KQL parser/backend exists.'

# --------------------------------------------------------------- file presence
Section 'Artefact presence and non-emptiness'
$requiredFiles = @($primaryPath, $regexPath, $notesPath, $readmePath, $prePath, $manPath, $reportPath, (Join-Path $KqlDir 'validate_kql.ps1'))
foreach ($p in $requiredFiles) {
  Add-Check 'presence' ("exists: {0}" -f (Split-Path $p -Leaf)) (Test-Path -LiteralPath $p)
}
if (-not (Test-Path -LiteralPath $primaryPath) -or -not (Test-Path -LiteralPath $regexPath)) {
  Write-Host ''
  Write-Host 'FATAL: a KQL query file is missing; nothing else can be validated.'
  exit 1
}

$primaryRaw = Get-Content -Raw -LiteralPath $primaryPath
$regexRaw   = Get-Content -Raw -LiteralPath $regexPath
$notesText  = if (Test-Path -LiteralPath $notesPath)  { Get-Content -Raw -LiteralPath $notesPath }  else { '' }
$readmeText = if (Test-Path -LiteralPath $readmePath) { Get-Content -Raw -LiteralPath $readmePath } else { '' }
$primaryCode = Get-KqlLogic $primaryRaw
$regexCode   = Get-KqlLogic $regexRaw

foreach ($pair in @(@{n='SOC002-DET-001-encoded-powershell.kql';t=$primaryRaw}, @{n='SOC002-DET-001-encoded-powershell-regex.kql';t=$regexRaw})) {
  Add-Check 'presence' ("non-empty: {0}" -f $pair.n) ([bool]($pair.t -and $pair.t.Trim().Length -gt 0)) ("{0} chars" -f $pair.t.Length)
  Add-Check 'presence' ("contains KQL, not just comments: {0}" -f $pair.n) ([bool]($(if ($pair.n -like '*-regex.kql') { $regexCode } else { $primaryCode }).Trim().Length -gt 0))
}

# --------------------------------------------------------------- representation
Section 'DET-001 representation in the query LOGIC (comments ignored)'
foreach ($q in @(@{label='portable'; code=$primaryCode; raw=$primaryRaw}, @{label='regex'; code=$regexCode; raw=$regexRaw})) {
  $lab = $q.label
  Add-Check 'representation' ("[{0}] EventID == 1 represented" -f $lab) ([bool]([regex]::IsMatch($q.code, 'EventID\s*==\s*1\b')))
  Add-Check 'representation' ("[{0}] uses the Event table" -f $lab) ([bool]([regex]::IsMatch($q.code, '(?m)^\s*Event\s*$')) -or [bool]([regex]::IsMatch($q.code, '(?i)\bEvent\b\s*\|')))
  Add-Check 'representation' ("[{0}] Sysmon source represented" -f $lab) ([bool]([regex]::IsMatch($q.code, 'Microsoft-Windows-Sysmon')))
  Add-Check 'representation' ("[{0}] powershell.exe represented" -f $lab) ([bool]([regex]::IsMatch($q.code, '(?i)powershell\.exe')))
  Add-Check 'representation' ("[{0}] pwsh.exe represented" -f $lab) ([bool]([regex]::IsMatch($q.code, '(?i)pwsh\.exe')))
  Add-Check 'representation' ("[{0}] Image suffix test used" -f $lab) ([bool]([regex]::IsMatch($q.code, '(?i)Image\s+endswith')))
  Add-Check 'representation' ("[{0}] encoded-command switch logic represented" -f $lab) ([bool]([regex]::IsMatch($q.code, '(?i)-EncodedCommand|encodedcommand')))
}

# The primary file must be the faithful, portable form.
Add-Check 'representation' '[portable] uses the Sigma "contains" operator for the switch' ([bool]([regex]::IsMatch($primaryCode, '(?i)CommandLine\s+contains\s+"-EncodedCommand"')))
Add-Check 'representation' '[portable] does NOT introduce the short-switch regex' (-not [bool]([regex]::IsMatch($primaryCode, '(?i)matches\s+regex')))
# The regex file must be the closer, token-exact translation.
Add-Check 'representation' '[regex] uses KQL "matches regex"' ([bool]([regex]::IsMatch($regexCode, '(?i)CommandLine\s+matches\s+regex')))
$regexHasAlternation = [bool]([regex]::IsMatch($regexCode, '(?i)\(\?i\)\\s-\(e\|en\|enc\|encodedcommand\)\(\\s\|\$\)'))
Add-Check 'representation' '[regex] reproduces the original short-switch alternation verbatim' $regexHasAlternation
Add-Check 'representation' '[regex] retains case-insensitive (?i) flag' ([bool]([regex]::IsMatch($regexCode, '\(\?i\)')))
Add-Check 'representation' '[regex] retains the token boundary (\s|$)' ([bool]([regex]::IsMatch($regexCode, '\(\\s\|\$\)')))
# The two forms must be distinguishable.
Add-Check 'representation' 'the two forms are textually distinguishable (portable != regex)' ($primaryCode.Trim() -ne $regexCode.Trim())

# --------------------------------------------------------------- forbidden logic
Section 'Forbidden logic is absent from the query LOGIC'
$forbidden = @(
  @{ t='FromBase64String (other detection)';        x='FromBase64String' }
  @{ t='Convert]:: (other detection)';              x='Convert]::' }
  @{ t='GetString / decode helper (other detection)'; x='GetString' }
  @{ t='other detection id';                        x='DET-003' }
  @{ t='other detection file';                      x='detect_base64_reconstruction' }
  @{ t='environment-specific baseline (BASE-01)';   x='BASE-01' }
  @{ t='Phase 6 baseline token';                    x='baseline' }
  @{ t='PowerShell Event ID 4104';                  x='4104' }
  @{ t='ScriptBlockText field';                     x='ScriptBlockText' }
  @{ t='Base64 payload-extraction regex';           x='A-Za-z0-9+/=' }
  @{ t='base64 literal';                            x='base64' }
)
foreach ($f in $forbidden) {
  Add-Check 'forbidden-logic' ("[portable] absent from logic: {0}" -f $f.t) (-not $primaryCode.Contains($f.x))
  Add-Check 'forbidden-logic' ("[regex]    absent from logic: {0}" -f $f.t) (-not $regexCode.Contains($f.x))
}
# Stronger: these tokens must not appear ANYWHERE in the query files, comments included.
foreach ($tok in @('FromBase64String','BASE-01','4104','DET-003')) {
  Add-Check 'forbidden-logic' ("token '{0}' absent from the whole primary file (incl. comments)" -f $tok) (-not $primaryRaw.Contains($tok))
}

# --------------------------------------------------------------- 4104 dependency
Section 'PowerShell 4104 is corroboration only (not required)'
Add-Check 'no-4104' 'primary query does not mention 4104 at all' (-not $primaryRaw.Contains('4104'))
Add-Check 'no-4104' 'primary query has no join/union against a second event source' (-not [bool]([regex]::IsMatch($primaryCode, '(?im)^\s*(union|join)\b')))
Add-Check 'no-4104' 'primary query fires on a single Sysmon Event ID 1 condition' ([bool]([regex]::IsMatch($primaryCode, 'EventID\s*==\s*1\b')))

# --------------------------------------------------------------- claim boundary
Section 'No affirmative production / live-Sentinel execution claim'
# Explicit affirmative-claim phrases. Each hit must be neutralised by a negation
# marker on the same or the preceding line.
$claimPhrases = @(
  'deployed to microsoft sentinel','deployed to sentinel','deployed in sentinel',
  'deployed to production','deployed in production','running in production','runs in production',
  'validated in sentinel','validated against sentinel','validated in production','validated against production',
  'tested in production','tested against production','sentinel validation','production validation',
  'live sentinel validation','live validation','production-ready','production ready',
  'production deployment','production soc experience','in production use','production siem deployment',
  'sentinel deployment','deployed in a live','running in a live','executed in sentinel','executed in production'
)
$negations = @('not','no ','never','cannot','without','nor ','none','isn''t','was not','absence','not a','refused','out of scope')
$claimFails = New-Object System.Collections.ArrayList
$claimScope = @{ 'query-portable'=$primaryRaw; 'query-regex'=$regexRaw; 'notes'=$notesText; 'readme'=$readmeText }
foreach ($k in $claimScope.Keys) {
  $lines = $claimScope[$k] -split "`n"
  for ($i = 0; $i -lt $lines.Count; $i++) {
    $low = $lines[$i].ToLowerInvariant()
    $hit = $false
    foreach ($ph in $claimPhrases) { if ($low.Contains($ph)) { $hit = $true; break } }
    if (-not $hit) { continue }
    $window = $lines[$i].ToLowerInvariant()
    if ($i -gt 0) { $window = $lines[$i-1].ToLowerInvariant() + ' ' + $window }
    $negated = $false
    foreach ($n in $negations) { if ($window.Contains($n)) { $negated = $true; break } }
    if (-not $negated) { $null = $claimFails.Add(("{0}:{1}: {2}" -f $k, ($i+1), $lines[$i].Trim())) }
  }
}
Add-Check 'claims' 'no affirmative production/Sentinel execution claim in queries/notes/readme' ($claimFails.Count -eq 0) (($claimFails | Select-Object -First 3) -join ' | ')

# Positive requirement: the docs must explicitly disclaim live execution.
$disclaimerRx = '(?i)(no production|not deployed|not been deployed|not executed|not run against|no live|not been executed|no kql parser|never been run)'
Add-Check 'claims' 'KQL_NOTES.md explicitly disclaims production/live validation' ([bool]([regex]::IsMatch($notesText, $disclaimerRx)))
Add-Check 'claims' 'README.md explicitly disclaims production/live validation' ([bool]([regex]::IsMatch($readmeText, $disclaimerRx)))

# --------------------------------------------------------------- documentation
Section 'Documentation of assumptions and limitations'
$docChecks = @(
  @{ n='notes: source table assumption section';            p='(?i)source table assumption' }
  @{ n='notes: explains why the Event table is used';       p='(?i)Event table is used|Why the `Event` table|Why the .Event. table' }
  @{ n='notes: Event ID 1 meaning (Process Create)';        p='(?i)Event ID 1.{0,40}Process Create|Process Create.{0,40}Event ID 1' }
  @{ n='notes: portable Sigma-to-KQL representation';       p='(?i)Sigma.{0,20}KQL|portable Sigma' }
  @{ n='notes: regex representation of original logic';     p='\(\?i\)\\s-\(e\|en\|enc\|encodedcommand\)' }
  @{ n='notes: difference between Sigma form and regex';    p='(?i)difference between the Sigma form' }
  @{ n='notes: why BASE-01 is not a KQL exclusion';         p='(?i)BASE-01.{0,30}not (a )?(KQL |portable )?exclusion|not a KQL exclusion' }
  @{ n='notes: why 4104 is corroboration only';             p='(?i)4104.{0,30}corroboration|corroboration only' }
  @{ n='notes: the other detection blind spot';             p='(?i)blind spot' }
  @{ n='notes: other detection stays separate';             p='(?i)deliberately not merged|not merged' }
  @{ n='notes: lab FP history 38 of 39';                    p='(?i)38 of (those|the) 39|38 of 39' }
  @{ n='notes: states no production/live Sentinel validation'; p=$disclaimerRx }
)
foreach ($d in $docChecks) {
  Add-Check 'documentation' $d.n ([bool]([regex]::IsMatch($notesText, $d.p)))
}
Add-Check 'documentation' 'README describes the assumed source schema' ([bool]([regex]::IsMatch($readmeText, '(?i)assumed source schema|assumed schema|assumption')))
Add-Check 'documentation' 'README distinguishes portable vs regex forms' ([bool]([regex]::IsMatch($readmeText, '(?i)portable.{0,60}regex|regex.{0,60}portable')))
Add-Check 'documentation' 'README states DeviceProcessEvents is a different source model' ([bool]([regex]::IsMatch($readmeText, '(?i)DeviceProcessEvents')) -and [bool]([regex]::IsMatch($readmeText, '(?i)not the lab''s Sysmon|different source model|not the lab.s Sysmon')))
Add-Check 'documentation' 'README states limitations' ([bool]([regex]::IsMatch($readmeText, '(?i)limitation|honest scope|not executed')))
Add-Check 'documentation' 'notes state assumptions' ([bool]([regex]::IsMatch($notesText, '(?i)assumption')))

# --------------------------------------------------------------- manifest
Section 'SHA256 manifest validity'
if (Test-Path -LiteralPath $manPath) {
  $manLines = Get-Content -LiteralPath $manPath
  $entries = New-Object System.Collections.ArrayList
  foreach ($line in $manLines) {
    $m = [regex]::Match($line, '^([0-9a-f]{64})  (.+)$')
    if ($m.Success) { $null = $entries.Add(@{ hash=$m.Groups[1].Value; rel=$m.Groups[2].Value.Trim() }) }
  }
  Add-Check 'manifest' 'manifest contains hash entries' ($entries.Count -gt 0) ("{0} entries" -f $entries.Count)
  $manBad = 0
  foreach ($e in $entries) {
    $full = Join-Path $KqlDir $e.rel
    if (-not (Test-Path -LiteralPath $full)) { $manBad++; Add-Check 'manifest' ("covers file: {0}" -f $e.rel) $false 'file missing'; continue }
    $actual = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $e.hash.ToLower()) { $manBad++; Add-Check 'manifest' ("hash matches: {0}" -f $e.rel) $false ("man={0} file={1}" -f $e.hash.Substring(0,16), $actual.Substring(0,16)) }
  }
  Add-Check 'manifest' ("all {0} manifest entries verify" -f $entries.Count) ($manBad -eq 0)
  # coverage: every artefact except the manifest itself and the report must be listed
  $covered = @($entries | ForEach-Object { $_.rel })
  foreach ($art in @('SOC002-DET-001-encoded-powershell.kql','SOC002-DET-001-encoded-powershell-regex.kql','KQL_NOTES.md','README.md','validate_kql.ps1','PRE_KQL_HASHES.txt')) {
    Add-Check 'manifest' ("manifest covers artefact: {0}" -f $art) ($covered -contains $art)
  }
} else {
  Add-Check 'manifest' 'SHA256_MANIFEST.txt present' $false 'missing'
}

# --------------------------------------------------------------- integrity
Section 'Phase 5-9 integrity (pre vs post)'
if (Test-Path -LiteralPath $prePath) {
  Add-Check 'integrity' 'pre-change baseline available' $true 'PRE_KQL_HASHES.txt'
  $preLines = Get-Content -LiteralPath $prePath
  $checked = 0; $bad = 0
  foreach ($line in $preLines) {
    $m = [regex]::Match($line, '^([0-9a-f]{64})  (.+)$')
    if (-not $m.Success) { continue }
    $expect = $m.Groups[1].Value
    $rel    = $m.Groups[2].Value.Trim()
    if ($rel -eq '-') { continue }   # section C digest line, not a file
    $full = Join-Path $RepoRoot $rel
    $checked++
    if (-not (Test-Path -LiteralPath $full)) { $bad++; Add-Check 'integrity' ("unchanged: {0}" -f $rel) $false 'file missing'; continue }
    $actual = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $expect) { $bad++; Add-Check 'integrity' ("unchanged: {0}" -f $rel) $false ("pre={0} post={1}" -f $expect.Substring(0,16), $actual.Substring(0,16)) }
  }
  Add-Check 'integrity' ("all {0} curated Phase 5-9 files byte-identical" -f $checked) ($bad -eq 0)

  # recursive Phase 5-9 tree digest, recomputed with the exact method of the baseline
  $preTree = ($preLines | Where-Object { $_ -match '^[0-9a-f]{64}  -$' } | Select-Object -First 1)
  if ($preTree) {
    $expectedDigest = ($preTree -split '\s+')[0]
    $roots = @('phase5','phase6','phase7','phase8','phase9') | ForEach-Object { Join-Path $RepoRoot $_ } | Where-Object { Test-Path $_ }
    $rels = New-Object System.Collections.ArrayList
    foreach ($r in $roots) {
      foreach ($f in (Get-ChildItem -LiteralPath $r -Recurse -File -Force)) {
        $rel = [IO.Path]::GetRelativePath($RepoRoot, $f.FullName) -replace '\\','/'
        $null = $rels.Add($rel)
      }
    }
    $sorted = [string[]]$rels.ToArray()
    # ordinal (byte) order == LC_ALL=C sort, as used to build the baseline digest
    [System.Array]::Sort($sorted, [System.StringComparer]::Ordinal)
    $sb = New-Object System.Text.StringBuilder
    foreach ($rel in $sorted) {
      $h = (Get-FileHash -LiteralPath (Join-Path $RepoRoot $rel) -Algorithm SHA256).Hash.ToLower()
      $null = $sb.Append(("{0}  {1}`n" -f $h, $rel))
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $digest = ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($sb.ToString())) | ForEach-Object { $_.ToString('x2') }) -join ''
    Add-Check 'integrity' ("recursive Phase 5-9 tree digest matches baseline ({0} files)" -f $sorted.Count) ($digest -eq $expectedDigest) ("pre={0} post={1}" -f $expectedDigest.Substring(0,16), $digest.Substring(0,16))
  } else {
    Add-Check 'integrity' 'recursive tree digest line present in baseline' $false 'no "digest  -" line found'
  }
} else {
  Add-Check 'integrity' 'pre-change baseline available' $false 'PRE_KQL_HASHES.txt missing'
}

# --------------------------------------------------------------- summary
Section 'Summary'
$total = $script:Results.Count
$failed = @($script:Results | Where-Object { -not $_.Pass })
$passed = $total - $failed.Count
Write-Host ("  checks  : {0}" -f $total)
Write-Host ("  passed  : {0}" -f $passed)
Write-Host ("  failed  : {0}" -f $failed.Count)
if ($failed.Count -gt 0) {
  Write-Host '  failing checks:'
  foreach ($f in $failed) { Write-Host ("    - [{0}] {1} {2}" -f $f.Area, $f.Name, $f.Detail) }
}
Write-Host ''
Write-Host '  KQL backend execution : NOT PERFORMED (no local KQL parser/backend; static checks only)'
Write-Host ''
if ($failed.Count -eq 0) { Write-Host 'RESULT: PASS' ; exit 0 } else { Write-Host 'RESULT: FAIL' ; exit 1 }
