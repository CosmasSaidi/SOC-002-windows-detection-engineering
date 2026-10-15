# SOC-002 — Phase 9 Sigma Validation Report

**Scope** — Sigma representation of the existing, lab-validated detection `SOC002-DET-001`
(Encoded PowerShell execution, Sysmon Event ID 1).
**Phase type** — closure / representation. No new detection logic, no new lab activity,
no modification to any Phase 5–8 artifact.
**Status** — **PASS** (61 of 61 checks passed).

---

## 1. Files created

All under `phase9/sigma/`:

| File | SHA256 |
|---|---|
| `SOC002-DET-001-encoded-powershell.yml` | `335e405109119c67983e3c026b35fba5e76cd2e84c1664fce82343ff22c375c1` |
| `SIGMA_NOTES.md` | `ac33ebbcf281ddcd0c0b7d2dbb0118e29e77460d2f1ddaf1ba42fac88144b586` |
| `README.md` | `6fa0d07e9955ba7b07b96dea5864f03a953d850ade4ee599688a3c4567a68ea8` |
| `validate_sigma.ps1` | `f9e908bcf32711ce131e026c1adcf1054e1cb165a1dcd5f09367edb10dc3c561` |
| `PRE_SIGMA_HASHES.txt` | `8a2b38052aa51804ca84d4808d3b0b24afcc5957987b18d8f4f91ea576ff9292` |
| `SIGMA_VALIDATION_REPORT.md` | this file |
| `SHA256_MANIFEST.txt` | `7288ebb82d698df0e0cdf72aa3c1e1291960349087257d21caaf8c7402c24b3a` |

`SHA256_MANIFEST.txt` covers the five artifacts above and excludes itself plus this report
by construction (the report records the manifest hash, so the two cross-reference each
other rather than hash each other). Verification:

```
(cd phase9/sigma && sha256sum -c SHA256_MANIFEST.txt)   ->  5x OK
```

The Sigma rule carries the stable UUID `9e77668f-116f-459b-80bf-4b6c4ba02ae7`, generated
once for this rule only.

No Git repository operations were performed. The working tree at `.` is
not a Git repository (`git rev-parse` → "not a git repository"), so no commit, branch,
index or other Git state could be or was modified. No infrastructure VM was touched; no
lab activity was re-run.

## 2. Authoritative source files (derivation basis)

| Source | SHA256 |
|---|---|
| `phase5/detections/detect_encoded_powershell.ps1` | `6e0651dc43f781e9d71bc2ebc6b7c74d4d882a30799a61372945cceda0d5efca` |
| `phase6/detections/detect_encoded_powershell_v2.ps1` | `c9b73426134571dfa6a26df3cb39e4d6030ce5886720cf7679de575845b0d16c` |
| `phase6/detections/lib_soc002_v2.ps1` | `3c332445bfb69045e2ad3b135c8184086d91979d8fc03c1bbead79d17b69d09f` |
| `phase6/detections/lib_soc002_windows.ps1` (holds the trigger function) | `3404a8bf210fde3ac1418f1fd7dae15251bc8f3dae6ae717c453ffaa28ed4c7d` |
| `phase5/evidence/raw/sysmon1-recid3535-ws001.xml` | `8f053aa127cf5b38dec10d3b1405840ab5533a2bd3199dfd0b1133d5c78b3bad` |
| `phase5/evidence/DETECTION_LIMITATIONS.txt` | `a357b12e1330e3b52c1a757a28283b95564a0b9961dbab31f4b18d93ce3e88de` |
| `phase6/evidence/TUNING_RATIONALE.txt` | `b71641f9609d1f59335f06e054ee2403af65d3dac950f9663ac73f240b198da3` |

Full baseline (16 files: the DET-001 sources above, the 4688/4104 evidence, the DET-002 /
DET-003 detections, the Phase 7/8 reports and the recursive tree digest) is in
`PRE_SIGMA_HASHES.txt`.

**Field semantics confirmed from the sources.** The detector reads Sysmon Event ID 1
`EventData` fields `Image` and `CommandLine` (the collector renders no `Message` text, so
the XML `Data` fields are parsed directly). The trigger is
`Image -match '(?i)(powershell|pwsh)\.exe'` **and**
`CommandLine -match '(?i)\s-(e|en|enc|encodedcommand)(\s|$)'`. The Base64 regex
(`(?i)-(?:e|en|enc|encodedcommand)\s+"?([A-Za-z0-9+/=]{16,})`) is used only to extract the
payload for read-only display, and 4104 is used only for corroboration by executing PID
and time window. Phase 6 re-declares the identical switch/image patterns in
`lib_soc002_v2.ps1` and states the trigger is unchanged from Phase 5.

## 3. Validation results

Tooling: `pwsh 7.5.4`, `phase9/sigma/validate_sigma.ps1`, run offline.

```
== Local Sigma backend (optional) ==
  NOT AVAILABLE: no sigma / sigma-cli / pySigma backend installed locally.
  -> No external Sigma backend validation will be performed.
  -> Deterministic offline structural checks below are the authoritative result.
```

No external Sigma backend (sigma CLI / pySigma) exists in this environment, so no backend
conversion or backend-native validation was performed and none is claimed. The result below
is from deterministic local checks: a YAML parse (PyYAML) plus regex/structural assertions
over the rule text and the documentation, and SHA256 re-verification of the Phase 5–8 tree.

| Area | Checks | Result |
|---|---|---|
| Artifact presence (rule, notes, README, baseline) | 4 | PASS |
| YAML parses as a single mapping | 1 | PASS |
| Required Sigma fields (`title`, `id`, `status`, `description`, `references`, `author`, `date`, `tags`, `logsource`, `detection`, `falsepositives`, `level`) | 12 | PASS |
| Field values (`id` is a UUID; `status`/`level` are legal values; description substantive — 1264 chars) | 4 | PASS |
| Logsource: `category: process_creation`, `product: windows`, `service: sysmon`, Sysmon, Event ID 1 | 6 | PASS |
| Detection: `Image|endswith` present, `powershell.exe` + `pwsh.exe` present, `CommandLine|contains` present, `-EncodedCommand` present, condition ANDs both selections, no OR/NOT/filter, two selections + condition | 9 | PASS |
| Trigger scope: DET-003 / DET-002 / baseline artifacts absent from the trigger | 14 | PASS |
| Claims: no affirmative production / Microsoft Sentinel claim (negation-aware scan of rule + notes + README) | 1 | PASS |
| Documentation topics present in `SIGMA_NOTES.md` | 8 | PASS |
| Phase 5–8 integrity (pre vs post) | 2 | PASS |
| **Total** | **61** | **61 PASS / 0 FAIL** |

Trigger-scope specifics that passed: `FromBase64String`, `FromBase64CharArray`,
`[Convert]::`, `DET-003`, `detect_base64_reconstruction`, `4104`, `ScriptBlockId`,
`ESC-0x`, `BASE-01`, `ParentImage`, `ParentCommandLine` are **absent from the detection
block**; `FromBase64String` and the Base64 extraction regex are absent from the **entire**
rule file; and no weak short-switch wildcard (`-e` / `-en` / `-enc`) was written into the
trigger.

### Semantic spot-check against preserved evidence

Re-expressing the rule's two conditions literally (Python, offline) over the preserved
Phase 5 evidence:

| Case | Sigma selection | Phase 5 trigger regex (`CommandLine` sub-regex) |
|---|---|---|
| Sysmon Ev1 RecId 3535 — controlled test | **fires** | matches |
| Security 4688 RecId 15141 — same process | **fires** | matches |
| WinRS wrapper parent (benign, expected FP) | fires | matches |
| `-Command` + `[Convert]::FromBase64String` (Phase 7 blind spot) | no fire | no match |
| `-ExecutionPolicy Bypass` only | no fire | no match |
| `-Encoding UTF8` inside a command | no fire | no match |
| short form `-enc` (real encoded command) | **no fire** | matches |
| non-PowerShell image carrying the switch text | no fire | (image gate fails in the detector too) |

This demonstrates four things: the rule fires on the controlled, lab-validated event; it does
not fire on the DET-003 blind-spot command form (so DET-003 is not merged in); it does not
fire on `-ExecutionPolicy` / `-Encoding` (so no weak short-switch wildcard was used); and it
does not fire on the short `-enc` form (the documented portability gap, section 6).

## 4. Exact Sigma detection semantics

```yaml
logsource:
  category: process_creation
  product: windows
  service: sysmon
detection:
  selection_image:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_encoded_switch:
    CommandLine|contains:
      - '-EncodedCommand'
      - '-encodedcommand'
  condition: selection_image and selection_encoded_switch
```

- `category: process_creation` + `service: sysmon` = **Sysmon Event ID 1 (Process Create)**;
  the `definition` field states this explicitly, including the channel name. Security 4688 is
  not declared because it is only an optional, non-primary fallback in the PowerShell
  implementation.
- `Image` and `CommandLine` are the same field names the detector reads from the Sysmon XML.
- Match = created process is `powershell.exe` or `pwsh.exe` **AND** its command line carries
  the encoded-command switch. `condition: selection_image and selection_encoded_switch` — one
  AND, no filters, no exclusions, no suppression of any kind.
- `level: medium` mirrors the detector's MEDIUM "triage, not proof of compromise" severity;
  `status: experimental` reflects that this representation is not deployed anywhere.
- Tags: `attack.execution`, `attack.t1059.001` (PowerShell), `attack.defense_evasion`,
  `attack.t1027` (obfuscated information), consistent with encoded-command execution.

## 5. Pre / post integrity

Baseline `PRE_SIGMA_HASHES.txt` was written **before** any Phase 9 artifact existed. After
creation, every file was re-hashed:

| Verification | Pre | Post | Result |
|---|---|---|---|
| 16 authoritative/related source files (section A + B) | recorded in `PRE_SIGMA_HASHES.txt` | identical | **unchanged** |
| Recursive Phase 5–8 tree digest (225 files) | `26e3e636c24dde731d32e3a070956a9e326d4743f5f4e922441d8daf1eb9b702` | `26e3e636c24dde731d32e3a070956a9e326d4743f5f4e922441d8daf1eb9b702` | **unchanged** |

The tree digest covers every file under `phase5/`, `phase6/`, `phase7/` and `phase8/`
(evidence, detections, reports, manifests, case artifacts), not just the referenced files, so
no Phase 5–8 artifact was modified, added or removed. The digest is recomputed inside
`validate_sigma.ps1` and is part of the PASS result above.

## 6. Portability caveats

| Existing PowerShell behaviour | Sigma status |
|---|---|
| Case-insensitive switch match (`(?i)`) | Preserved — Sigma string matching is case-insensitive by default; both spellings listed for backends that are case-sensitive in practice. |
| Long form `-EncodedCommand` | Preserved. |
| Short forms `-e` / `-en` / `-enc` | **Not represented.** Portable `contains` cannot express a token-exact short switch: `-e` would match `-ErrorAction`/`-ExecutionPolicy`, `-en` would match `-Enabled`, `-enc` would match `-Encoding`. Rather than inventing a weak wildcard that fires on unrelated command lines, the gap is documented in `SIGMA_NOTES.md` and demonstrated by the spot-check above. |
| Whitespace required before the switch, token boundary after it | Not enforced by `contains`; a command line merely quoting the literal switch text would fire in Sigma but not in the original regex. The Sigma rule is therefore marginally **broader** in that edge case — not narrower — except for the short forms above. |
| Unanchored `Image` substring match (`(powershell\|pwsh)\.exe`) | Deliberately narrowed to the standard `Image\|endswith '\powershell.exe' / '\pwsh.exe'` idiom. The original would also match e.g. `mypowershell.exe`. |
| Base64 extraction + read-only decode | Out of scope — enrichment, not a detection condition. |
| 4104 executing-PID correlation | Out of scope — corroboration layer; a Sigma rule is a single-event match. |

**This rule is therefore not a byte-for-byte equivalent of the PowerShell trigger.** It is
token-equivalent for the long form, and it is honest about the two places where it differs
(token-exact short switches; unanchored `Image` substring). `SIGMA_NOTES.md` records the
original regex verbatim and documents that a backend supporting the `re` modifier can
substitute `CommandLine|re: '(?i)\s-(e|en|enc|encodedcommand)(\s|$)'` to close the
short-switch gap; that modifier is not used in the portable rule because support is
backend-dependent and a rule that fails to convert is worse than a documented gap.

## 7. False-positive limitations

- **Measured, not theoretical:** 39 hits in a 60-minute window on a single workstation, of
  which 38 were the lab operator's own WinRM administration (`phase5/evidence/t6_detection_broad60_dc1.txt`).
  The WinRS client delivers every remote command as `cmd.exe /C powershell -encodedcommand <b64>`,
  so one administrator produces alert-per-command volume.
- Legitimate encoded PowerShell is common: management/RMM agents, orchestration and
  configuration management, deployment and scheduled-task wrappers.
- All 39 lab hits shared the same user, host and Microsoft binary hash, which is precisely why
  tuning on user/host/hash/time was refused in Phase 6.
- Expect volume before precision: scope the rule per environment and pair it with process
  lineage and payload decode before treating a hit as suspicious.

## 8. Blind-spot limitations

- **Only the CLI switch is covered.** PowerShell that reconstructs a payload in-process —
  `powershell.exe -Command "$b='<base64>'; [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b))"` —
  carries no encoded-command switch and is **not** detected by DET-001. Phase 7 confirmed this
  blind spot; Phase 8 built `SOC002-DET-003` (`phase8/detections/detect_base64_reconstruction.ps1`)
  as a separate detection for it.
- DET-003 is deliberately **not** merged into this Sigma rule: different question, different
  indicator, independently auditable coverage. The validator enforces this (the
  `FromBase64String` family must not appear anywhere in the rule file).
- Other inherited gaps from `phase5/evidence/DETECTION_LIMITATIONS.txt`: only
  `powershell.exe`/`pwsh.exe` images are covered (no alternate hosts, no `pwsh` variants beyond
  the image name); if Sysmon Event ID 1 is absent the primary signal disappears; 4688 is not
  the primary source; 4104 fragmentation and ScriptBlockLogging availability affect
  corroboration (not the trigger); command-line visibility depends on the Phase 4 enablers.
- Phase 6 `BASE-01` is **not** encoded here as a global exclusion. It is lab-contextual tuning
  that requires the parent command line and the decoded payload — data a single-event
  process-creation rule does not have — and encoding "cmd.exe running the WinRS wrapper ⇒
  benign" globally would suppress the transport real operator tooling uses. Even inside Phase 6
  the baseline is narrow and the general `powershell.exe` / `-EncodedCommand` suppressions are
  reported as `0`.

## 9. Claim boundaries

- Lab-validated Sigma **representation** of an existing detection, derived by reading the
  preserved Phase 5/6 sources and evidence. Not a new detection, not a re-implementation, not a
  measurement of coverage.
- **Not** executed in Microsoft Sentinel or any other production SIEM; no backend conversion,
  deployment or tuning was performed; no SOC production experience is claimed.
- Where something could not be verified in the lab (backend conversion, short-switch
  semantics), it is recorded as not performed / not represented rather than assumed.

## 10. Final status

**PASS** — the Sigma rule exists, faithfully represents the DET-001 primary Sysmon Process
Create trigger, contains no DET-003 logic and no Phase 6 baseline exclusion, the Phase 5–8
files are provably unchanged, the validation report and SHA256 manifest exist, and all
limitations are explicitly documented.
