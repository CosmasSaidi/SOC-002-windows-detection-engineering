# SOC-002 — Detection Engineering

This document follows the evolution of the two detections the lab built:
`SOC002-DET-001` (encoded PowerShell) and `SOC002-DET-003` (PowerShell Base64
reconstruction). It is grounded in the preserved detection sources and phase
reports; no new detection logic is described here.

## Detection inventory

| ID | Name | Role | Source of record |
|---|---|---|---|
| `SOC002-DET-001` | Encoded PowerShell Execution Observed — Investigation Required | Primary triage detection | `phase5/detections/detect_encoded_powershell.ps1` |
| `SOC002-DET-001 v2` | Same trigger, classification added | Hardened primary | `phase6/detections/detect_encoded_powershell_v2.ps1` + `lib_soc002_v2.ps1` |
| `SOC002-DET-002` | PowerShell Process Lineage (WinRM-administered chain) | Context only | `phase6/detections/detect_powershell_lineage.ps1` |
| `SOC002-CORR-001` | DET-001 × DET-002 correlation | Correlation | `phase6/detections/correlate_det001_det002.ps1` |
| `SOC002-DET-003` | PowerShell Base64 Reconstruction / Decode Behaviour | Complementary detection | `phase8/detections/detect_base64_reconstruction.ps1` + `lib_soc002_phase8.ps1` |
| `SOC002-CORR-002` | DET-003 correlation | Correlation | emitted by the Phase 8 library |

---

## Part 1 — `SOC002-DET-001` (Encoded PowerShell)

### 1.1 What it detects

The creation of a PowerShell process whose **command line carries an
encoded-command switch**. That is the entire trigger.

```
Sysmon Event ID 1
  AND Image      matches (?i)(powershell|pwsh)\.exe
  AND CommandLine matches (?i)\s-(e|en|enc|encodedcommand)(\s|$)
```

Two properties of the switch regex matter:

- it is **case-insensitive** (`-EncodedCommand`, `-encodedcommand`, …); and
- it is **token-exact** — whitespace must precede the switch and whitespace or
  end-of-string must follow it. `-Encoding`, `-ExecutionPolicy` and `-Enabled`
  are therefore *not* matched by the short alternatives.

### 1.2 Telemetry source

- **Primary:** Sysmon **Event ID 1 / Process Create**
  (`Microsoft-Windows-Sysmon/Operational`, forwarded to the collector's
  `ForwardedEvents`). Fields: `Image`, `CommandLine`, `ProcessGuid`, `ProcessId`,
  `User`, `LogonId`, `ParentImage`, `ParentCommandLine`, `Hashes`.
  Evidence: `phase5/evidence/raw/sysmon1-recid3535-ws001.xml`.
- **Corroborating:** PowerShell **Event ID 4104** (`ScriptBlockText`,
  `ScriptBlockId`, executing PID).
- **Optional fallback:** Security **Event ID 4688** (`-Include4688Fallback`),
  used only when no Sysmon Event 1 exists for the process (weaker lineage — 4688
  carries no `ParentProcessGuid`).

### 1.3 The PowerShell image

`powershell.exe` and `pwsh.exe` are the only in-scope images. `$imgRx` is an
**unanchored substring** match, so a path such as `C:\tools\mypowershell.exe`
would also match — a documented weakness the Sigma port narrows with
`Image|endswith` (see `phase9/sigma/SIGMA_NOTES.md` §3).

### 1.4 The encoded-command switch

`-EncodedCommand` and its short forms `-e` / `-en` / `-enc` are the whole
detection. Because the indicator is a *command-line shape*, anything that reaches
the same outcome without that shape is invisible (§3.4).

### 1.5 4104 corroboration

The detector performs a **read-only** Base64 decode of the encoded argument and
then looks for a 4104 block from the **same executing PID** in a small window
(−5 s … +45 s), or carrying a known marker. Corroboration is deliberately
**not mandatory**: the Sysmon alert stands when 4104 is absent, reported as
`Corroboration = NONE FOUND`. Making 4104 mandatory would turn an availability
gap into a detection gap. 4104 is also noisy and can be fragmented across
`MessageNumber`/`MessageTotal > 1`.

### 1.6 Alerting

Each hit is printed as a structured block headed
`Encoded PowerShell execution observed — INVESTIGATION REQUIRED`, severity
**MEDIUM** ("triage, not proof of compromise"). The block carries host, user,
`LogonId`, `ProcessGuid`, process and parent, binary hashes, the command line, the
decoded script, and any corroboration. The detection never says "malicious".

### 1.7 Why the detection was noisy

Measured in Phase 5 (`phase5/evidence/t6_detection_broad60_dc1.txt`):

- **39 candidates in a 60-minute window on one workstation.**
- Immediate parent of **38 of 39** = `cmd.exe` running the WinRS wrapper
  `cmd.exe /C powershell -encodedcommand <base64>`.
- Immediate parent of **1 of 39** = `powershell.exe` — the controlled test.
- All 39 shared the same account, host and Microsoft binary hash.

The lab is operated over WinRM, and the WinRS client delivers **every** remote
command as an encoded PowerShell one-liner. The noise is therefore **structural**:
one administrator produces alert-per-command volume. Critically, the one event
worth investigating did **not** have the benign shape, so coarse tuning would have
hidden it.

### 1.8 Tuning — `SOC002-DET-001 v2`

Phase 6 changed **only classification and context**. The trigger is byte-for-byte
the same, so coverage does not silently shrink.

- **`BASE-01` — the narrow WinRS transport baseline.** Matched only when the
  parent process **image leaf is exactly `cmd.exe`** **and** that parent's
  **command line** matches the WinRS wrapper:

  ```
  ^\s*"?[^"]*cmd\.exe"?\s+/c\s+("?[^\s"]*powershell(?:\.exe)?"?\s+)?-(e|en|enc|encodedcommand)(\s|$)
  ```

  `cmd.exe /C <anything else>` is **not** baselined.
- **`ESC-01..08` — the fail-safe payload screen.** The decoded payload of every
  baseline-matched event is scanned for high-risk constructs (reflection/AMSI,
  download/execute stagers, a second decode layer, execution-policy/AV tampering,
  persistence primitives, credential-access tooling, account/directory
  modification, nested encoded commands). **Any hit overrides the baseline** and
  clears the event back to `INVESTIGATION`.
- **Lineage gating.** The baseline reaches `BASELINE-TRANSPORT-CONFIRMED` (INFO)
  only when the ancestry resolves to a WinRM host (`winrshost.exe` /
  `wsmprovhost.exe`); otherwise it drops to `BASELINE-TRANSPORT-PATTERN` (LOW)
  and the gap is printed in the record.

Measured effect: live, `ESC-03` (a second decode layer) re-opened 2 of the 38
baselined events — the Sysmon configuration work that legitimately uses
`[Convert]::FromBase64String`. Phase 6 deliberately does **not** suppress them.

Phase 6 also measured and refused wider tuning. `TUNING_RATIONALE.txt` records
refusals by user (`SOC002\Administrator` — the attacker's likely account too),
`LogonId` (changes per session), source host, parent image name alone, parent
`powershell.exe` (that is the controlled event's shape), binary hash, integrity
level, and time-of-day. There is no general "allow `powershell.exe`" rule and no
general "allow `-EncodedCommand`" rule — both are printed as `0 suppressed` so
the absence is auditable.

### 1.9 Why `BASE-01` is not a universal exclusion

`BASE-01` is **lab-contextual tuning, not a portable rule**, for four reasons:

1. It is derived from this lab's own operating pattern (an operator driving hosts
   over WinRM), which is a property of the *lab*, not of Windows.
2. It requires the **parent command line** and a **decoded payload** — data a
   single-event process-creation rule does not have. A Sigma/KQL port of the
   trigger cannot evaluate the payload screen.
3. Encoding "parent `cmd.exe` running a WinRS wrapper ⇒ benign" as a **global
   exclusion** would teach a portable rule to ignore exactly the transport a real
   operator's tooling uses.
4. It is **evadable by mimicry**: an adversary who can already execute commands
   remotely could deliver a payload as `cmd.exe /C powershell -encodedcommand …`
   and meet the baseline. The `ESC-01..08` keyword screen is the compensating
   control, and it is a keyword screen, not a proof.

For these reasons `BASE-01` is **explicitly excluded** from the Sigma rule and
both KQL files — it is documented there as context, never written as a
suppression.

### 1.10 `SOC002-DET-001` limitations

- A **triage** signal: does not prove compromise, intent, or that anything was
  run.
- Only the CLI-switch shape is covered (§3.4).
- Only `powershell.exe` / `pwsh.exe` images; the image match is unanchored.
- If Sysmon Event 1 is absent, the primary signal disappears (mitigated only by
  the weaker 4688 fallback).
- If 4104 is absent, the analyst loses the "what did it do" view.
- Command-line visibility depends entirely on the Phase 4 enablers (4688
  command-line auditing, Script Block Logging).
- Bounded local/collector retention can silently miss events in long windows.
- Forwarded events in `ForwardedEvents` carry **no rendered `Message` text**, so
  rules must parse the `EventData` XML.

---

## Part 2 — `SOC002-DET-003` (PowerShell Base64 Reconstruction / Decode Behaviour)

### 2.1 What it detects

A **`.NET` Base64 reconstruction call** in PowerShell text — not the word
"Base64", and not a command-line switch.

| ID | Pattern (case-insensitive) | Meaning |
|---|---|---|
| REC-01 | `[Convert]::FromBase64String` | type-accelerator decode call |
| REC-02 | `[System.Convert]::FromBase64String` | fully-qualified decode call |
| REC-03 | `FromBase64String(` | unqualified call form |
| REC-04 | `FromBase64CharArray(` | unqualified call form |
| REC-05 | `[Convert]::FromBase64CharArray` | alternative decode call |

Text searched: Sysmon Event 1 `CommandLine`, Security 4688 `CommandLine`,
PowerShell 4104 `ScriptBlockText` — locally and at DC1 `ForwardedEvents`.

The literal word `Base64` **never triggers** the detection. A reconstruction call
appearing only inside a **comment** is recorded as `COMMENT-MENTION`, not a
trigger — the suppression is explicit, never silent.

### 2.2 Why it was created as a separate detector

Because Phase 7 measured a real gap: the behaviour it targets is fully visible in
four telemetry views yet invisible to DET-001 v2. The lab's design rule, stated in
`phase8/evidence/DET003_DESIGN.md`, is that a **new behavioural form gets a new,
independently auditable detection** — never a quiet widening of an existing one.

### 2.3 What `SOC002-DET-001` misses

DET-001 keys on the **encoded-command CLI switch**. PowerShell that reconstructs
a payload *inside the process* carries no such switch:

```powershell
powershell.exe -NoProfile -NonInteractive -Command "$b='<base64>';
  $t=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)); ..."
```

Phase 7 (`SOC002-CASE-0002`) confirmed this by controlled test: the payload
process (PID 1428, marker `SOC002-PHASE7-BLINDSPOT-TEST`) never became a DET-001
candidate; DET-002 recorded it as context only; CORR-001 correlated nothing.
Phase 8 then confirmed that **DET-003 identifies that exact payload** in all four
preserved Phase 7 evidence views and in one controlled live run.

### 2.4 Context model (never a trigger by itself)

| Flag | Condition | Effect |
|---|---|---|
| `CTX-EXEC-ADJACENT` | execution/loader primitive co-occurs (`Invoke-Expression`, `iex`, `Start-Process`, `Add-Type`, call operator, dot-source) | raises severity to **MEDIUM** |
| `CTX-STRING-ROUNDTRIP` | decoded bytes turned back into a string (`[Text.Encoding]::…GetString`) | informational |
| `CTX-REMOTE-RETRIEVAL` | network retrieval primitive co-occurs (`DownloadString`, `WebClient`, `Invoke-WebRequest`, `iwr`, `Start-BitsTransfer`) | raises severity to **MEDIUM** |
| `CTX-PLUMBING` | in-lab file staging idiom (`[IO.File]::*`, `Set-Content`, …) | documented false-positive source, reported not hidden |

Severity is `LOW` (`RECONSTRUCTION-OBSERVED`) or `MEDIUM`
(`RECONSTRUCTION-WITH-EXECUTION-ADJACENT`). Neither is a verdict; DET-003 raises
the question "who decoded what, and did it feed an execution or a retrieval?".

### 2.5 Why `DET-003` was NOT merged into `DET-001`

The two detections address **different behavioural forms**, and merging them
would destroy the independence that makes each auditable:

- DET-001's trigger is a **command-line shape** (an encoded-command *switch*).
- DET-003's trigger is a **code behaviour** (a Base64 reconstruction *call* that
  may appear in a command line or in a script block).

Measured consequence (`phase8/evidence/t14_det001_vs_det003.txt`): the two are
**disjoint** on the observed cases — neither is a superset of the other. In
Phase 7 the blind spots *complemented* each other: the payload was
DET-001-miss / DET-003-hit, and the WinRS transport was the reverse. Folding
DET-003 into DET-001 would:

- silently broaden DET-001 into something it never was, invalidating the Phase 5/6
  coverage claim and the Phase 9/10 representations derived from it;
- allow a change in one behaviour to affect the coverage claim of the other; and
- remove the ability to say, honestly, that DET-001 covers the switch and DET-003
  covers the call.

`phase8/evidence/t14_det001_vs_det003.txt` and `phase9/sigma/SIGMA_NOTES.md` §10
both record this decision; the Sigma and KQL validators enforce it by failing if
`FromBase64String`-family logic appears in the DET-001 artifacts.

### 2.6 `SOC002-DET-003` limitations

- **Text-only trigger.** Fragment-assembled method names, custom decoders,
  `certutil -decode`, compiled binaries and non-PowerShell hosts are `NOT
  VERIFIED` as detectable.
- **Decode-and-execute is inferred** from text proximity (`CTX-EXEC-ADJACENT`),
  not observed.
- **Here-strings** are not comment-stripped.
- **PID reuse** is handled only within a ±120 s tolerance.
- **Operator plumbing inflates volume**: the lab's own file transfer uses
  `[Convert]::FromBase64String` and appears as a `CTX-PLUMBING` candidate. In the
  live 60-minute DC1 run, 7 of 13 candidates were operator plumbing and 6 were the
  two controlled payloads — observed behaviour on a tiny sample, explicitly **not
  a false-positive rate**.
- One host, one representation, one live run; no rate and no generalisation.

---

## Summary

DET-001 covers an **encoded-command switch on the command line**. DET-003 covers
a **Base64 reconstruction call in PowerShell text**. They are deliberately kept
as two separately auditable coverage claims because they detect two different
behavioural forms, they are disjoint on every observed case, and neither is a
superset of the other.
