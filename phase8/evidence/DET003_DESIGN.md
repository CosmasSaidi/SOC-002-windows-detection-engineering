# SOC002-DET-003 — Design & Rationale

**Detection** `SOC002-DET-003` · **Title** PowerShell Base64 Reconstruction / Decode Behaviour
**Data sources** Sysmon Event 1 (ProcessCreate), Security 4688 (Process Creation), PowerShell 4104 (ScriptBlockLogging) — on `SOC002-WS001` locally and on `SOC002-DC1` `ForwardedEvents` centrally.
**Relationship to existing detections** Complementary and **separate**. `SOC002-DET-001 v2` is **not** modified or extended. `SOC002-DET-002` remains CONTEXT only.

---

## 1. Why this detection exists

Phase 7 (`SOC002-CASE-0002`) confirmed by measurement that `SOC002-DET-001 v2`
triggers on the **encoded-command CLI switch** (`-EncodedCommand` / `-enc` / `-e` / `-en`).
A PowerShell process that instead reconstructs data with
`-Command "[Convert]::FromBase64String(...)"` is fully visible in Security 4688,
Sysmon Event 1, PowerShell 4104 and DC1 `ForwardedEvents`, yet never becomes a
DET-001 candidate. DET-003 covers exactly that behaviour, as a **second,
independently auditable** detection.

## 2. Trigger conditions (exact)

A telemetry record becomes a DET-003 candidate when the PowerShell text it
carries contains a **.NET Base64 reconstruction call**:

| ID | Pattern (case-insensitive) | Meaning |
|----|----------------------------|---------|
| REC-01 | `[Convert]::FromBase64String` | type-accelerator decode call |
| REC-02 | `[System.Convert]::FromBase64String` | fully-qualified decode call |
| REC-03 | `FromBase64String(` | unqualified call form |
| REC-04 | `FromBase64CharArray(` | unqualified call form |
| REC-05 | `[Convert]::FromBase64CharArray` / `[System.Convert]::FromBase64CharArray` | alt decode call |

The text searched is: Sysmon Event 1 `CommandLine`, Security 4688 `CommandLine`,
PowerShell 4104 `ScriptBlockText`.

**The literal word `Base64` never triggers the detection.** It is recorded only
to explain a non-trigger ("word present, no decode call").

### Comment suppression
A reconstruction call appearing **only inside a comment** (`#` line comment or
`#>`… block comment) is **not** a trigger. It is reported as a
`COMMENT-MENTION` so the suppression is explicit, never silent. (Block comments
and single/double-quoted strings are respected; here-strings are a documented
limitation.)

## 3. Why each trigger was selected

- **`FromBase64String` / `FromBase64CharArray`** are the minimal, stable,
  unambiguous .NET APIs for base64 reconstruction. They are what produces
  "decode behaviour" without any encoded-command switch.
- **Keying on the *call form*, not the word**, is what keeps precision: it
  avoids the classic keyword-rule failure where every comment, help string and
  variable named `Base64` fires.
- **Two methods, five labelled forms** keep coverage of realistic write styles
  (type accelerator vs fully-qualified vs bare) while staying small enough to
  audit line by line.
- **Both 4688 and Sysmon Event 1 and 4104** are used because each may be the
  only surviving copy in a given environment, and 4104 often holds the text even
  when the command line does not.

## 4. Context model (computed, never a trigger by itself)

| Flag | Condition | Effect |
|------|-----------|--------|
| `CTX-EXEC-ADJACENT` | execution/loader primitive co-occurs (`Invoke-Expression`, `iex`, `Start-Process`, `Add-Type`, call operator, dot-source) | raises severity to **MEDIUM** |
| `CTX-STRING-ROUNDTRIP` | decoded bytes turned back into a string (`[Text.Encoding]::…GetString`) | informational |
| `CTX-REMOTE-RETRIEVAL` | network retrieval primitive co-occurs (`DownloadString`, `WebClient`, `Invoke-WebRequest`, `iwr`, `Start-BitsTransfer`) | raises severity to **MEDIUM** |
| `CTX-PLUMBING` | in-lab file staging/transfer idiom (`[IO.File]::*`, `Set-Content`, …) alongside the decode | **documented false-positive source**, reported not hidden |

Severity/class:

- **LOW** — `RECONSTRUCTION-OBSERVED` (decode only).
- **MEDIUM** — `RECONSTRUCTION-WITH-EXECUTION-ADJACENT` (decode + execution/retrieval adjacency).

Neither severity is a verdict.

## 5. Expected false positives

1. **The SOC team's own tooling.** The lab's WinRM file transfer uses
   `[Convert]::FromBase64String`; every push/collection therefore trips DET-003
   (usually `CTX-PLUMBING`, LOW). This is measured, not hypothetical — see the
   live capture and `t12_false_positive_considerations.txt`.
2. **Legitimate scripts** that decode configuration, certificates, blobs,
   registry values or API responses with the same .NET API.
3. **Other administration** running through the sanctioned WinRM channel
   (the same channel whose use DET-002 describes as context).

## 6. Limitations

See `t13_limitations.txt`. Load-bearing ones: the trigger is text-based (a
reconstruction built from fragments, a custom decoder, `certutil -decode`, or a
non-PowerShell host are **not** covered); here-strings are not comment-stripped;
PID-reuse is handled only within a ±120 s tolerance; and no rate is claimed from
a small synthetic sample.

## 7. Context required for investigation

A DET-003 record is only usable for triage when read with:
the operator/account and `LogonId`, the parent process and full chain
(DET-002), the surrounding command/script text, whether an execution primitive
co-occurs, and whether the host/channel is the sanctioned management path.
DET-003 supplies the **what**; DET-002 supplies the **how**; authorisation and
payload content decide the reading.

## 8. What DET-003 never does

It never executes, invokes, evaluates, or decodes-and-runs anything. It matches
text and reports context. It never asserts maliciousness.
