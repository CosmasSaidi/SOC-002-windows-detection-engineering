# SIGMA_NOTES — SOC002-DET-001 (Encoded PowerShell) in Sigma

Companion notes for `SOC002-DET-001-encoded-powershell.yml`.
Phase 9 is a **closure** artifact set: it represents an existing, already-validated
detection in a portable format. No new detection logic was developed here, and no
Phase 5–8 artifact was modified.

## 1. What DET-001 detects

`SOC002-DET-001` ("Encoded PowerShell execution observed — investigation required")
flags the **creation of a PowerShell process whose command line carries an
encoded-command switch**. That is the whole detection.

It is a triage signal. It says *an analyst should look at this event*; it does **not**
say the process is malicious and it does **not** prove compromise. In the SOC-002 lab
the same indicator is produced by ordinary WinRM administration, so the wording of the
detection output is deliberately "INVESTIGATION REQUIRED", never "malicious".

## 2. Telemetry source

- **Primary:** Sysmon **Event ID 1 / Process Create**
  (channel `Microsoft-Windows-Sysmon/Operational`, forwarded to the collector's
  `ForwardedEvents` log).
- **Fields used:** `Image` (created process path) and `CommandLine` (full command line).
  Evidence: `phase5/evidence/raw/sysmon1-recid3535-ws001.xml`.
- **Corroborating (not primary):** PowerShell **Event ID 4104** (Script Block Logging).
- **Optional fallback (not primary, not represented in the Sigma rule):** Security
  Event ID 4688, used by the PowerShell implementation only when no Sysmon Event 1
  exists for the process (`-Include4688Fallback`).

## 3. The exact existing trigger

Phase 5 and Phase 6 use the same two conditions (Phase 6 explicitly did **not** change
them — see `phase6/README.md` and `phase6/evidence/TUNING_RATIONALE.txt`):

```powershell
$imgRx = '(?i)(powershell|pwsh)\.exe'                    # Image
$encRx = '(?i)\s-(e|en|enc|encodedcommand)(\s|$)'         # CommandLine
```

Match = `Image` matches `imgRx` **and** `CommandLine` matches `encRx`.

Two properties of `$encRx` matter for the Sigma port:

1. It is **case-insensitive** (`(?i)`).
2. It is **token-exact**: a whitespace must precede the switch, and the switch text must
   be followed by whitespace or the end of the string. `-e`, `-en`, `-enc` and
   `-EncodedCommand` are alternative spellings of the *whole* token — `enc` in
   `-EncodedCommand` is not matched as a substring, and `-Encoding` / `-ExecutionPolicy`
   are **not** matched by the short alternatives because the character after the token
   is not whitespace.

Note also that `$imgRx` is an **unanchored substring** match on `Image`, so it would
also match a path such as `C:\tools\mypowershell.exe`.

The Base64 extraction regex (`(?i)-(?:e|en|enc|encodedcommand)\s+"?([A-Za-z0-9+/=]{16,})`)
is **enrichment/decoding** used to display the payload to the analyst. It is *not* part
of the trigger and is *not* represented in the Sigma rule.

## 4. Sigma representation

```yaml
logsource:
  category: process_creation
  product: windows
  service: sysmon
detection:
  selection_image:
    Image|endswith: ['\powershell.exe', '\pwsh.exe']
  selection_encoded_switch:
    CommandLine|contains: ['-EncodedCommand', '-encodedcommand']
  condition: selection_image and selection_encoded_switch
```

`category: process_creation` + `service: sysmon` maps to Sysmon Event ID 1. `Image` and
`CommandLine` are the canonical Sigma process-creation field names and are exactly the
field names present in the preserved Sysmon XML evidence, so no field renaming is
required for a Sysmon-based backend.

Both casings of the long switch are listed because Sigma's default string matching is
case-insensitive per the specification, but some backends are configured case-sensitive
in practice; listing both spellings costs nothing and removes that dependency.

## 5. What was preserved

- The **primary telemetry** (Sysmon Event ID 1 / Process Create) and the two fields used.
- The **process scope**: only `powershell.exe` / `pwsh.exe` images.
- The **trigger**: the encoded-command switch in the command line, and only that.
- The **severity/interpretation**: `level: medium` mirrors the PowerShell detector's
  MEDIUM "triage, not proof of compromise" classification.
- The **separation of concerns**: Base64 decoding stays enrichment, 4104 stays
  corroboration, and DET-003 stays a separate detection.

## 6. What cannot be represented exactly

| Existing PowerShell behaviour | Sigma-portable status |
|---|---|
| Case-insensitive switch match (`(?i)`) | **Preserved** — Sigma string matching is case-insensitive by default; both spellings listed anyway. |
| Long form `-EncodedCommand` | **Preserved** — `CommandLine\|contains: '-EncodedCommand'`. |
| Short forms `-e`, `-en`, `-enc` | **NOT represented.** Portable `contains` cannot express a token-exact short switch. `'-e'` would match `-ErrorAction`/`-ExecutionPolicy`; `'-en'` would match `-Enabled`; `'-enc'` would match `-Encoding` (e.g. `powershell.exe -Command "Get-Content x -Encoding UTF8"`). Writing those as broad wildcards would be a weak rule that fires on unrelated command lines, so they are documented as a gap rather than invented. |
| Whitespace required *before* the switch | **Not enforced.** `contains` matches the switch anywhere in the string, so a command line that merely quotes the literal text (e.g. `powershell.exe -Command "Write-Output '-EncodedCommand'"`) would fire in Sigma but not in the PowerShell regex. This makes the Sigma rule marginally *broader* than the original in that edge case — it is not narrower. |
| Unanchored `Image` substring match (`(powershell\|pwsh)\.exe`) | **Deliberately narrowed** to `Image\|endswith '\powershell.exe' / '\pwsh.exe'`, the standard Sigma idiom for this field. The original would also match oddities such as `mypowershell.exe`; the Sigma form follows the intent (the PowerShell binaries) rather than the literal substring. |
| Base64 payload extraction + read-only decode | **Out of scope** — enrichment for the analyst, not a detection condition. |
| 4104 process-time correlation | **Out of scope** — corroboration layer; a Sigma rule is a single-event match. |

For backends that support the `re` modifier, the exact original condition can be
substituted verbatim:

```yaml
  selection_encoded_switch_re:
    CommandLine|re: '(?i)\s-(e|en|enc|encodedcommand)(\s|$)'
```

This is deliberately **not** used as the primary detection because `re` support is
backend-dependent and a portable rule must not fail to convert. If it is substituted,
the resulting rule is token-equivalent to the PowerShell trigger; if it is not, the
short-switch gap in the table above applies.

## 7. Why Phase 6 baseline logic is NOT encoded as a global Sigma exclusion

Phase 6 added `BASE-01`, a narrow baseline: *the parent is `cmd.exe` **and** that parent's
command line is the WinRS transport wrapper `cmd.exe /C powershell -encodedcommand <b64>`
**and** the decoded payload contains none of the `ESC-01..08` high-risk constructs.*

That is **lab-contextual tuning**, not part of the detection's trigger:

- It is derived from this lab's own operating pattern (an operator driving hosts over
  WinRM), `phase5/evidence/t6_detection_broad60_dc1.txt`, which is a property of the lab,
  not of Windows.
- It requires the **parent process command line** and a **decoded payload** — data a
  single-event Sigma process-creation rule does not have. A Sigma rule cannot evaluate
  the payload screen, so any "lossless" port is impossible.
- Encoding "parent cmd.exe running a WinRS wrapper ⇒ benign" as a global exclusion would
  teach a portable rule to ignore exactly the transport that a real operator's tooling
  uses, and would contradict the hardening rationale in
  `phase6/evidence/TUNING_RATIONALE.txt`.

Phase 6 is therefore referenced as context for expected false positives (section 9), not
copied as a suppression rule. Phase 6 also explicitly refuses a general
`powershell.exe` rule and a general `-EncodedCommand` rule (`Suppressed by a general
powerShell/EncodedCommand rule = 0` in its output) — so even in its own implementation
the baseline is narrow, and it is not a "turn the rule off on this host/user/hash"
construct.

## 8. Why 4104 is corroboration, not the Sigma trigger

- The detection's **primary** condition is a process-creation fact. 4104 is a *different
  log, a different event, and a different process-identity mapping* (executing PID +
  time window), which is why the PowerShell implementation performs an explicit
  correlation step and reports `Corroboration = NONE FOUND` when it cannot resolve it.
- 4104 is **not always present**: it depends on Script Block Logging being enabled and
  the log being forwarded. The Sysmon alert still stands when 4104 is missing; tying the
  trigger to 4104 would turn an availability gap into a detection gap.
- 4104 is **noisy and fragmented** (long scripts split across
  `MessageNumber`/`MessageTotal`), which the Phase 5 limitations file records as a
  weakness of text-marker matching.
- A Sigma rule is a single-event match; 4104 is naturally a companion/correlation rule
  (`SOC002-CORR-001` in Phase 6), not part of DET-001's selection.

## 9. Known false-positive behaviour from the SOC-002 lab (measured, not theoretical)

- **39 hits in a 60-minute window on one workstation for one real event.** 38 were the
  lab operator's own administration delivered by the WinRS client as
  `cmd.exe /C powershell -encodedcommand <base64>`; 1 was the controlled test.
  (`phase5/evidence/t6_detection_broad60_dc1.txt`)
- The same account, the same host and the same Microsoft binary hash appeared in all 39
  hits — which is exactly why Phase 6 refused host/user/hash/time-of-day tuning.
- Legitimate encoded PowerShell is common in the wild too: management/RMM agents,
  orchestration and configuration management, and the WinRM channel itself.
- Consequence: expect volume before precision. Scope the rule, and pair it with lineage
  context (DET-002) and payload decode before treating a hit as suspicious.

## 10. Known blind spot (unchanged, and deliberately not merged here)

`SOC002-DET-001` only keys on the **CLI switch**. PowerShell that reconstructs a payload
in-process is **not** covered:

```powershell
powershell.exe -NoProfile -NonInteractive -Command "$b='<base64>'; $t=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)); ..."
```

There is no `-EncodedCommand` / `-enc` / `-en` / `-e` on that command line, so DET-001
does not fire. Phase 7 confirmed the blind spot, and Phase 8 built a **separate**
detection, `SOC002-DET-003` (`phase8/detections/detect_base64_reconstruction.ps1`),
which keys on the `.NET` reconstruction call (`[Convert]::FromBase64String`,
`[System.Convert]::FromBase64String`, `FromBase64String(`, `FromBase64CharArray(`).

DET-003 is **not** merged into this Sigma rule: the two detections answer different
questions, their coverage claims are independently auditable, and merging them would
silently broaden DET-001 into something it never was. The `FromBase64String` family
appears nowhere in the rule file — only in these notes, as an explicitly excluded blind
spot.

## 11. Status of this representation

This is a **lab-validated Sigma representation** of an existing detection. It was
derived by reading the preserved Phase 5/6 detector sources and the preserved Phase 5
evidence, and was checked structurally by `validate_sigma.ps1` (offline, deterministic
checks over the YAML/text).

It has **not** been executed in Microsoft Sentinel, in any other production SIEM, or
against a live production estate. No backend conversion, deployment, or SOC operating
experience is claimed. Where a claim could not be verified in the lab, it is marked as
not verified rather than assumed.
