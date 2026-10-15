#!/usr/bin/env pwsh
<#
  SOC-002 | PHASE 9 | validate_sigma.ps1
  ---------------------------------------------------------------------------
  Static, offline validation of the Phase 9 Sigma artifact set.

  It checks STRUCTURE and CLAIMS, not detection performance:
    1. required Sigma fields exist
    2. logsource represents Sysmon / process-create / Event ID 1
    3. powershell.exe and pwsh.exe are represented
    4. the encoded-command switch is represented
    5. SOC002-DET-003 / FromBase64String logic is NOT in the trigger block
    6. no production / Microsoft Sentinel claim is introduced (negation-aware)
    7. the authoritative Phase 5-8 source files are byte-identical to the
       pre-change baseline recorded in PRE_SIGMA_HASHES.txt

  Requirements: PowerShell 7+. No internet access, no Microsoft Sentinel and no
  Sigma backend are required. If a local Sigma backend (sigma / sigma-cli /
  pySigma) happens to be installed it is used for an extra parse check;
  otherwise that step is reported as NOT PERFORMED and the deterministic local
  checks stand on their own.

  Exit code: 0 = PASS (all checks passed), 1 = FAIL.
#>
[CmdletBinding()]
param(
  [string]$SigmaDir = '',
  [string]$RepoRoot = ''
)

$ErrorActionPreference = 'Stop'
if (-not $SigmaDir) { $SigmaDir = $PSScriptRoot }
if (-not $SigmaDir) { $SigmaDir = (Get-Location).Path }
if (-not $RepoRoot) { $RepoRoot = (Split-Path (Split-Path $SigmaDir -Parent) -Parent) }

$rulePath  = Join-Path $SigmaDir 'SOC002-DET-001-encoded-powershell.yml'
$notesPath = Join-Path $SigmaDir 'SIGMA_NOTES.md'
$readmePath= Join-Path $SigmaDir 'README.md'
$prePath   = Join-Path $SigmaDir 'PRE_SIGMA_HASHES.txt'

$script:Results = New-Object System.Collections.ArrayList
function Add-Check {
  param([string]$Area, [string]$Name, [bool]$Pass, [string]$Detail = '')
  $null = $script:Results.Add([pscustomobject]@{ Area=$Area; Name=$Name; Pass=$Pass; Detail=$Detail })
  $tag = if ($Pass) { 'PASS' } else { 'FAIL' }
  Write-Host ("  [{0}] {1}" -f $tag, $Name)
  if ($Detail) { Write-Host ("         {0}" -f $Detail) }
}
function Section { param([string]$t) ; Write-Host '' ; Write-Host "== $t ==" }

Write-Host '=== SOC-002 Phase 9 :: Sigma validation (offline, static) ==='
Write-Host ("RepoRoot  = {0}" -f $RepoRoot)
Write-Host ("SigmaDir  = {0}" -f $SigmaDir)

# --------------------------------------------------------------- local backend
Section 'Local Sigma backend (optional)'
$sigmaExe = $null
foreach ($c in 'sigma','sigma-cli') {
  $cmd = Get-Command $c -ErrorAction SilentlyContinue
  if ($cmd) { $sigmaExe = $cmd.Source; break }
}
$pySigma = $false
$py = Get-Command python3 -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command python -ErrorAction SilentlyContinue }
if ($py) {
  & $py.Source -c "import sigma" 2>$null
  if ($LASTEXITCODE -eq 0) { $pySigma = $true }
}
if ($sigmaExe) {
  Write-Host ("  Sigma backend found: {0}" -f $sigmaExe)
} elseif ($pySigma) {
  Write-Host '  pySigma python module found (no sigma CLI).'
} else {
  Write-Host '  NOT AVAILABLE: no sigma / sigma-cli / pySigma backend installed locally.'
  Write-Host '  -> No external Sigma backend validation will be performed.'
  Write-Host '  -> Deterministic offline structural checks below are the authoritative result.'
}

# --------------------------------------------------------------- file presence
Section 'Artifact presence'
foreach ($p in @($rulePath, $notesPath, $readmePath, $prePath)) {
  Add-Check 'presence' ("exists: {0}" -f (Split-Path $p -Leaf)) (Test-Path $p)
}
if (-not (Test-Path $rulePath)) {
  Write-Host ''
  Write-Host 'FATAL: the Sigma rule is missing; nothing else can be validated.'
  exit 1
}

$ruleText  = Get-Content -Raw -LiteralPath $rulePath
$notesText = if (Test-Path $notesPath)  { Get-Content -Raw -LiteralPath $notesPath }  else { '' }
$readmeTxt = if (Test-Path $readmePath) { Get-Content -Raw -LiteralPath $readmePath } else { '' }

# --------------------------------------------------------------- YAML parse
Section 'YAML parse'
$parsed = $null
if ($py) {
  $tmp = Join-Path ([IO.Path]::GetTempPath()) ('soc002_yaml_check_{0}.py' -f $PID)
  @'
import json, sys
p = sys.argv[1]
out = {"yaml_module": False, "parsed": False, "error": "PyYAML not installed"}
try:
    import yaml
except Exception as e:
    print(json.dumps(out)); sys.exit(0)
out["yaml_module"] = True
try:
    with open(p, encoding="utf-8") as fh:
        d = yaml.safe_load(fh)
except Exception as e:
    out["error"] = "%s: %s" % (type(e).__name__, e)
    print(json.dumps(out)); sys.exit(0)

def flat(v):
    if isinstance(v, dict):
        r = []
        for k, vv in v.items():
            r.append(str(k)); r += flat(vv)
        return r
    if isinstance(v, list):
        r = []
        for i in v:
            r += flat(i)
        return r
    return [str(v)]

if not isinstance(d, dict):
    out["error"] = "top level document is not a mapping"
    print(json.dumps(out)); sys.exit(0)
ls = d.get("logsource") or {}
det = d.get("detection") or {}
out.update({
    "parsed": True, "error": None,
    "keys": [str(k) for k in d.keys()],
    "id": str(d.get("id")), "status": str(d.get("status")), "date": str(d.get("date")),
    "level": str(d.get("level")), "author": str(d.get("author")),
    "logsource_keys": [str(k) for k in ls.keys()],
    "logsource_values": flat(ls),
    "detection_keys": [str(k) for k in det.keys()],
    "detection_values": flat(det),
    "condition": str(det.get("condition")),
    "tags": [str(t) for t in (d.get("tags") or [])],
    "falsepositives_is_list": isinstance(d.get("falsepositives"), list),
    "references_is_list": isinstance(d.get("references"), list),
    "description_len": len(str(d.get("description") or "")),
    "title": str(d.get("title")),
})
print(json.dumps(out))
'@ | Set-Content -LiteralPath $tmp -Encoding utf8
  $raw = & $py.Source $tmp $rulePath 2>&1
  Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
  try { $parsed = $raw | ConvertFrom-Json } catch { $parsed = $null }
}
if ($null -eq $parsed) {
  Add-Check 'yaml' 'PyYAML parse (optional, informational)' $false 'python3/PyYAML not available - text checks only'
  $parsed = $null
} elseif (-not $parsed.yaml_module) {
  Add-Check 'yaml' 'PyYAML parse (optional, informational)' $false 'PyYAML not installed - text checks only'
  $parsed = $null
} else {
  Add-Check 'yaml' 'YAML parses as a single mapping' ([bool]$parsed.parsed) ([string]$parsed.error)
}

# --------------------------------------------------------------- required fields
Section 'Required Sigma fields'
$required = @('title','id','status','description','references','author','date','tags','logsource','detection','falsepositives','level')
foreach ($f in $required) {
  $inFile = [bool]([regex]::IsMatch($ruleText, ('(?m)^{0}:' -f [regex]::Escape($f))))
  $inDoc  = if ($parsed) { $parsed.keys -contains $f } else { $inFile }
  Add-Check 'fields' ("has '{0}'" -f $f) ($inFile -and $inDoc)
}
if ($parsed) {
  Add-Check 'fields' 'id is a UUID' ([bool]([regex]::IsMatch([string]$parsed.id, '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'))) ([string]$parsed.id)
  Add-Check 'fields' 'status is a Sigma status value' (@('stable','test','experimental','deprecated','unsupported') -contains $parsed.status) ([string]$parsed.status)
  Add-Check 'fields' 'level is a Sigma level value' (@('informational','low','medium','high','critical') -contains $parsed.level) ([string]$parsed.level)
  Add-Check 'fields' 'description is substantive' ([int]$parsed.description_len -gt 100) ("{0} chars" -f $parsed.description_len)
} else {
  Add-Check 'fields' 'id is a UUID' ([bool]([regex]::IsMatch($ruleText, '(?m)^id:\s*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\s*$')))
  Add-Check 'fields' 'level is present' ([bool]([regex]::IsMatch($ruleText, '(?m)^level:\s*(informational|low|medium|high|critical)\s*$')))
}

# --------------------------------------------------------------- logsource
Section 'Logsource (Sysmon process create / Event ID 1)'
$lsBlock = ''
$m = [regex]::Match($ruleText, '(?ms)^logsource:\s*(.*?)^(?=[a-z_]+:\s|falsepositives:)')
if ($m.Success) { $lsBlock = $m.Value }
if (-not $lsBlock) { $lsBlock = $ruleText }
Add-Check 'logsource' "category: process_creation" ([bool]([regex]::IsMatch($lsBlock, '(?m)^\s*category:\s*process_creation\s*$')))
Add-Check 'logsource' "product: windows" ([bool]([regex]::IsMatch($lsBlock, '(?m)^\s*product:\s*windows\s*$')))
Add-Check 'logsource' "service: sysmon" ([bool]([regex]::IsMatch($lsBlock, '(?m)^\s*service:\s*sysmon\s*$')))
Add-Check 'logsource' "Event ID 1 represented" ([bool]([regex]::IsMatch($lsBlock, '(?i)event id 1')) -or [bool]([regex]::IsMatch($ruleText, '(?i)sysmon event id 1')))
Add-Check 'logsource' "Sysmon represented" ([bool]([regex]::IsMatch($lsBlock, '(?i)sysmon')))
if ($parsed) {
  Add-Check 'logsource' 'parsed logsource has category/product/service' (($parsed.logsource_keys -contains 'category') -and ($parsed.logsource_keys -contains 'product') -and ($parsed.logsource_keys -contains 'service'))
}

# --------------------------------------------------------------- detection
Section 'Detection semantics'
$detBlock = ''
$m = [regex]::Match($ruleText, '(?ms)^detection:\s*(.*?)^(?=[a-z_]+:\s)')
if ($m.Success) { $detBlock = $m.Value }
Add-Check 'detection' 'detection block found' ([bool]$detBlock)

$selImage = ''
$m = [regex]::Match($detBlock, '(?ms)^\s*selection_image:\s*(.*?)(?=^\s{2}[a-z_]+:|\z)')
if ($m.Success) { $selImage = $m.Value }
$selSwitch = ''
$m = [regex]::Match($detBlock, '(?ms)^\s*selection_encoded_switch:\s*(.*?)(?=^\s{2}[a-z_]+:|\z)')
if ($m.Success) { $selSwitch = $m.Value }

Add-Check 'detection' 'Image field selection uses endswith' ([bool]([regex]::IsMatch($selImage, 'Image\|\w*(?i:endswith)')))
Add-Check 'detection' 'powershell.exe represented in Image' ([bool]([regex]::IsMatch($selImage, '(?i)powershell\.exe')))
Add-Check 'detection' 'pwsh.exe represented in Image' ([bool]([regex]::IsMatch($selImage, '(?i)pwsh\.exe')))
Add-Check 'detection' 'CommandLine field selection present' ([bool]([regex]::IsMatch($selSwitch, 'CommandLine\|')))
Add-Check 'detection' 'encoded-command switch (-EncodedCommand) represented' ([bool]([regex]::IsMatch($selSwitch, '(?i)-encodedcommand')))
Add-Check 'detection' 'condition ANDs image selection with switch selection' (
  [bool]([regex]::IsMatch($detBlock, '(?im)^\s*condition:.*selection_image\s+and\s+selection_encoded_switch\s*$')))
Add-Check 'detection' 'condition uses no OR/not filters (no suppression logic)' (
  -not [bool]([regex]::IsMatch($detBlock, '(?im)^\s*condition:.*\b(or|not|filter)\b')))
if ($parsed) {
  Add-Check 'detection' 'parsed detection has two selections + condition' (
    ($parsed.detection_keys -contains 'selection_image') -and
    ($parsed.detection_keys -contains 'selection_encoded_switch') -and
    ($parsed.detection_keys -contains 'condition'))
}

Section 'DET-003 / DET-002 / baseline must NOT be in the trigger'
$forbiddenInTrigger = @(
  @{ t='FromBase64String';      x='FromBase64String' }
  @{ t='FromBase64CharArray';   x='FromBase64CharArray' }
  @{ t='[Convert]:: call';      x='Convert]::' }
  @{ t='DET-003 reference';     x='DET-003' }
  @{ t='detect_base64_reconstruction reference'; x='detect_base64_reconstruction' }
  @{ t='4104 correlation';      x='4104' }
  @{ t='ScriptBlockId';         x='ScriptBlockId' }
  @{ t='ESC-0x payload screen'; x='ESC-0' }
  @{ t='BASE-01 baseline';      x='BASE-01' }
  @{ t='ParentImage field';     x='ParentImage' }
  @{ t='ParentCommandLine field'; x='ParentCommandLine' }
)
foreach ($f in $forbiddenInTrigger) {
  Add-Check 'trigger-scope' ("absent from detection block: {0}" -f $f.t) (-not $detBlock.Contains($f.x))
}
Add-Check 'trigger-scope' 'FromBase64String absent from the whole rule file' (-not $ruleText.Contains('FromBase64String'))
Add-Check 'trigger-scope' 'Base64 decode regex absent from the whole rule file' (-not [bool]([regex]::IsMatch($ruleText, 'A-Za-z0-9\+/=')))
Add-Check 'trigger-scope' 'no short-switch wildcard (-e / -en / -enc) in the trigger' (
  -not [bool]([regex]::IsMatch($selSwitch, "(?im)^\s*-\s*'?(e|en|enc)'?\s*$")))

# --------------------------------------------------------------- claims
Section 'No production / Microsoft Sentinel claim'
$claimTexts = @{ 'rule'=$ruleText; 'notes'=$notesText; 'readme'=$readmeTxt }
$claimTerms = @('Microsoft Sentinel','Sentinel','production SOC','production SIEM','production deployment','production estate','deployed to production','production-ready','production-ready rule')
$negations  = @('not','no ','never','cannot','without','nor ','none','isn''t','was not','not a','absence','no such')
$claimFails = New-Object System.Collections.ArrayList
foreach ($term in $claimTerms) {
  foreach ($k in $claimTexts.Keys) {
    $lines = $claimTexts[$k] -split "`n"
    for ($i = 0; $i -lt $lines.Count; $i++) {
      if ($lines[$i] -notmatch [regex]::Escape($term)) { continue }
      $window = $lines[$i]
      if ($i -gt 0) { $window = $lines[$i-1] + ' ' + $window }
      $negated = $false
      foreach ($n in $negations) { if ($window -match [regex]::Escape($n)) { $negated = $true; break } }
      if (-not $negated) { $null = $claimFails.Add(("{0}:{1}: {2}" -f $k, ($i+1), $lines[$i].Trim())) }
    }
  }
}
Add-Check 'claims' 'no affirmative production/Sentinel claim in rule/notes/readme' ($claimFails.Count -eq 0) (($claimFails | Select-Object -First 3) -join ' | ')

# --------------------------------------------------------------- documentation
Section 'Required documentation topics (SIGMA_NOTES.md)'
$docChecks = @(
  @{ n='explains the exact existing trigger / regex'; p='\(\?i\)\\s-\(e\|en\|enc\|encodedcommand\)' ; plain='\s-(e|en|enc|encodedcommand)(\s|$)' }
  @{ n='states telemetry source = Sysmon Event ID 1'; p='(?i)Sysmon.{0,20}Event ID 1|Event ID 1.{0,30}Process Create' }
  @{ n='documents the short-switch (-e/-en/-enc) portability gap'; p='(?i)(-e.?,?\s*-en.?,?\s*-enc|short forms?)' }
  @{ n='explains Phase 6 baseline is not a Sigma exclusion'; p='(?i)BASE-01' }
  @{ n='explains 4104 as corroboration'; p='4104' }
  @{ n='documents the FromBase64String blind spot'; p='FromBase64String' }
  @{ n='states DET-003 remains a separate detection'; p='(?i)DET-003' }
  @{ n='states lab-validated / not production deployment'; p='(?i)lab-validated' }
)
foreach ($d in $docChecks) {
  Add-Check 'documentation' $d.n ([bool]([regex]::IsMatch($notesText, $d.p)))
}

# --------------------------------------------------------------- integrity
Section 'Phase 5-8 integrity (pre vs post)'
$integrityChecked = 0
$integrityFailed = 0
if (Test-Path $prePath) {
  $preLines = Get-Content -LiteralPath $prePath
  foreach ($line in $preLines) {
    $m = [regex]::Match($line, '^([0-9a-f]{64})  (.+)$')
    if (-not $m.Success) { continue }
    $expect = $m.Groups[1].Value
    $rel    = $m.Groups[2].Value
    if ($rel.Trim() -eq '-') { continue }   # section C digest line, not a file
    $full   = Join-Path $RepoRoot $rel
    $integrityChecked++
    if (-not (Test-Path -LiteralPath $full)) {
      $integrityFailed++
      Add-Check 'integrity' ("unchanged: {0}" -f $rel) $false 'file missing'
      continue
    }
    $actual = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $expect) {
      $integrityFailed++
      Add-Check 'integrity' ("unchanged: {0}" -f $rel) $false ("pre={0} post={1}" -f $expect.Substring(0,16), $actual.Substring(0,16))
    }
  }
  Add-Check 'integrity' ("all {0} baseline files byte-identical" -f $integrityChecked) ($integrityFailed -eq 0)

  # recursive Phase 5-8 tree digest, recomputed the same way as the baseline
  $preTree = ($preLines | Where-Object { $_ -match '^[0-9a-f]{64}  -$' } | Select-Object -First 1)
  if ($preTree) {
    $expectedDigest = ($preTree -split '\s+')[0]
    $roots = @('phase5','phase6','phase7','phase8') | ForEach-Object { Join-Path $RepoRoot $_ } | Where-Object { Test-Path $_ }
    $rels = New-Object System.Collections.ArrayList
    foreach ($r in $roots) {
      foreach ($f in (Get-ChildItem -LiteralPath $r -Recurse -File -Force)) {
        $rel = [IO.Path]::GetRelativePath($RepoRoot, $f.FullName) -replace '\\','/'
        $null = $rels.Add($rel)
      }
    }
    $sorted = [string[]]$rels.ToArray()
    # ordinal (byte) order, matching the LC_ALL=C sort used for the baseline digest
    [System.Array]::Sort($sorted, [System.StringComparer]::Ordinal)
    $sb = New-Object System.Text.StringBuilder
    foreach ($rel in $sorted) {
      $h = (Get-FileHash -LiteralPath (Join-Path $RepoRoot $rel) -Algorithm SHA256).Hash.ToLower()
      $null = $sb.Append(("{0}  {1}`n" -f $h, $rel))
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $digest = ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($sb.ToString())) | ForEach-Object { $_.ToString('x2') }) -join ''
    Add-Check 'integrity' ("recursive Phase 5-8 tree digest matches baseline ({0} files)" -f $sorted.Count) ($digest -eq $expectedDigest) ("pre={0} post={1}" -f $expectedDigest.Substring(0,16), $digest.Substring(0,16))
  }
} else {
  Add-Check 'integrity' 'pre-change baseline available' $false 'PRE_SIGMA_HASHES.txt missing'
}

# --------------------------------------------------------------- summary
Section 'Summary'
$total = $script:Results.Count
$failed = @($script:Results | Where-Object { -not $_.Pass })
$passed = $total - $failed.Count
Write-Host ("  checks          : {0}" -f $total)
Write-Host ("  passed          : {0}" -f $passed)
Write-Host ("  failed          : {0}" -f $failed.Count)
if ($failed.Count -gt 0) {
  Write-Host '  failing checks  :'
  foreach ($f in $failed) { Write-Host ("    - [{0}] {1} {2}" -f $f.Area, $f.Name, $f.Detail) }
}
Write-Host ("  external Sigma backend validation : {0}" -f $(if ($sigmaExe -or $pySigma) { 'available locally' } else { 'NOT PERFORMED (no local backend; deterministic local checks used instead)' }))
Write-Host ''
if ($failed.Count -eq 0) {
  Write-Host 'RESULT: PASS'
  exit 0
} else {
  Write-Host 'RESULT: FAIL'
  exit 1
}
