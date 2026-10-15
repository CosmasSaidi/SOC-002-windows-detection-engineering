# SOC002-CASE-0003

**Title** — Phase 8 complementary detection: `SOC002-DET-003` identifies the
PowerShell Base64 reconstruction behaviour that the `SOC002-DET-001 v2` blind
spot missed

| | |
|---|---|
| Case ID | `SOC002-CASE-0003` |
| Status | `CLOSED` |
| Host | `SOC002-WS001.soc002.local` (192.168.56.102) |
| Collector | `SOC002-DC1` (192.168.56.10), `ForwardedEvents` |
| Account | `SOC002\Administrator` (existing authorised lab admin context) |
| LogonId | `0x695d72` |
| Payload process | `powershell.exe` PID **1268**, parent `powershell.exe` PID 5468 (WinRS transport) |
| Transport chain | `winrshost.exe`(4008) → `cmd.exe`(5652) → `powershell.exe`(5468) → `powershell.exe`(1268) |
| Marker | `SOC002-PHASE8-DET003-TEST` |
| Controlled window (UTC) | `2026-10-14T23:35:06Z .. 2026-10-14T23:35:09Z` |
| Session window (UTC) | `2026-10-14T23:34:45Z .. 2026-10-14T23:37:00Z` |
| Final classification | **CONTROLLED TEST ACTIVITY / AUTHORISED BENIGN** |
| Detection outcome | `DET-003 = IDENTIFIED (REC-01)`; `DET-001 v2 = MISS`; `DET-002 = CONTEXT`; `CORR-002 = CONNECTED` |
| Detections modified in Phase 8 | **No** (DET-001 v2 byte-identical; see §12) |

---

## 1. Detection objective

Build and validate a **complementary** detection — `SOC002-DET-003`, PowerShell
Base64 Reconstruction / Decode Behaviour — that identifies PowerShell telemetry
containing a `.NET` Base64 **reconstruction call** (e.g.
`[Convert]::FromBase64String(...)`), independently of DET-001 v2's
encoded-command CLI switch, and that never alerts on the literal word "Base64".

## 2. Phase 7 blind spot (SOC002-CASE-0002)

Phase 7 confirmed that a PowerShell process using
`-Command "[Convert]::FromBase64String(...)"` (no `-EncodedCommand`/`-enc`/`-e`/`-en`)
is fully visible in 4688, Sysmon Event 1 and 4104 — and at DC1 `ForwardedEvents` —
yet is **not** a DET-001 v2 candidate. Phase 7 recorded `OUTCOME B — blind spot
confirmed`, with DET-002 surfacing the process as lineage context only.
The Phase 7 event is the primary validation target for this case.

## 3. DET-003 design (summary — full detail in `evidence/DET003_DESIGN.md`)

- **Trigger:** a `FromBase64String` / `FromBase64CharArray` reconstruction
  **call** (labelled REC-01..REC-05) in Sysmon Event 1 `CommandLine`, Security
  4688 `CommandLine`, or PowerShell 4104 `ScriptBlockText`.
- **Not a trigger:** the literal word `Base64`; a decode call that appears only
  inside a comment (recorded as a visible non-trigger).
- **Context (never a trigger alone):** `CTX-EXEC-ADJACENT`, `CTX-STRING-ROUNDTRIP`,
  `CTX-REMOTE-RETRIEVAL`, `CTX-PLUMBING`.
- **Severity:** LOW (`RECONSTRUCTION-OBSERVED`) or MEDIUM
  (`RECONSTRUCTION-WITH-EXECUTION-ADJACENT`). Never a verdict.
- DET-003 is a **separate** file set; DET-001 v2 is untouched.

## 4. Observed telemetry (live controlled run)

`OBSERVED` — one controlled execution, 23:35:06–08Z. The payload child command
line carries `-Command` + `[Convert]::FromBase64String` and **no** encoded-command
switch.

| Source | RecordId | Key fields |
|---|---|---|
| Security 4688 | **16123** | NewPID 1268, Creator 5468, `SOC002\Administrator`, `LogonId 0x695d72` |
| Sysmon Event 1 | **4600** | PID 1268, `ProcessGuid {edcef402-11ab-6ad0-5706-000000000700}`, PPID 5468, hashes present |
| PowerShell 4104 | **77450** | ExecPID 1268, `ScriptBlockId 50aa4a2f-00ff-4f0f-b0d4-2f5f2543ccae` |
| DC1 ForwardedEvents | same 16123 / 4600 / 77450 | identical RecordIDs reached the collector via WEF |
| Sysmon Event 3 | none by the payload | no network connection initiated by the payload |

A separate DET-003 hit (`4104` RecId **77434**, ExecPID 1996) is the operator's
own staging script, which carries the payload text as a literal; it is labelled
`CTX-PLUMBING` and is **not** the activity under test.

## 5. Detection result

**DET-003 IDENTIFIED the reconstruction.** In all four preserved Phase 7 views
(WS001 local + DC1 ForwardedEvents, controlled + session) and in the live run,
DET-003 flagged PID 1268/1428 with `REC-01 [Convert]::FromBase64String`.

Live-run matrix (`OBSERVED`):

| Process | DET-001 v2 | DET-003 |
|---|---|---|
| `powershell.exe` PID 5468 (WinRS transport, `-encodedcommand`) | **TRIGGER** | miss |
| `powershell.exe` PID 1268 (payload, `-Command` + decode) | **miss** | **TRIGGER (REC-01, LOW)** |

## 6. Correlation result

`OBSERVED` — `SOC002-CORR-002` connected DET-003 with Sysmon Event 1, Security
4688, the PowerShell 4104 block, and the DET-002 lineage
(`powershell.exe(1268) <- powershell.exe(5468) <- cmd.exe(5652) <- winrshost.exe(4008) <- svchost.exe(716)`),
using PID + ProcessGuid agreement with a ±120 s tolerance.

`OBSERVED` — correlation **gaps are printed, not hidden** (e.g. a 4104-sourced
record whose script block is not separately linked). No gap was forced closed.

## 7. Investigation

The DET-003 record tells the analyst **what** (a base64 reconstruction call was
observed) and, with DET-002, **how** it was delivered (through the sanctioned
WinRM management path). It does **not** assert intent. For this case the activity
decoded a fixed blob to plain text and printed it. Nothing decoded was executed.

## 8. Classification

**CONTROLLED TEST ACTIVITY / AUTHORISED BENIGN.** One benign execution that did
exactly what the Phase 8 design required: reconstructed a harmless marker and
printed it. No persistence, no configuration change, no credential access, no
privilege escalation, no lateral movement, no payload network contact, no
permanent file (temp body removed). **The finding of value is the detection
behaviour, not the activity.**

## 9. Limitations

See `evidence/t13_limitations.txt`. Load-bearing: text-only trigger; decode-and-
execute is INFERRED from text proximity, not observed; here-strings are not
comment-stripped; PID reuse handled only within ±120 s; one host, one
representation, one run; operator plumbing inflates volume; no false-positive
rate is claimed; this is not production validation.

## 10. Recommended next step

1. Decide explicitly whether `CORR-001` should correlate on DET-002 lineage
   alone, given DET-003 now supplies a switch-free signal (Phase 7 §18 item 2).
2. Consider whether the operator's own staging traffic (`CTX-PLUMBING`) should be
   handled by a separately auditable enrichment rather than left as raw volume.
3. Keep DET-001 v2 and DET-003 as two separately auditable coverage claims; do
   not fold DET-003 into DET-001's trigger.
4. Do **not** broaden the `BASE-01` baseline to depth-3 powershell-in-powershell
   (Phase 7 §17): it would hide the very activity DET-003 exists to surface.

## 11. OBSERVED / INFERRED / NOT VERIFIED

Full lists in `evidence/t11_investigation_notes.txt` and `case.json`. The
load-bearing ones:

**OBSERVED** — one benign execution; marker printed; RC 0; child command line has
`-Command` + decode and no encoded switch; 4688/Sysmon1/4104 captured it locally
and the same RecordIDs reached DC1; DET-003 flagged the payload in all four
preserved Phase 7 views and in the live run; the WinRS transport was DET-001-hit
/ DET-003-miss; correlation linked Sysmon1 + 4688 + 4104 + DET-002 lineage; no
payload network contact; temp body removed.

**INFERRED** — DET-003 closes the specific Phase 7 gap because it keys on the
decode call rather than the CLI switch; the two detections are disjoint on the
observed cases, so neither is a superset of the other.

**NOT VERIFIED** — generalisation to other reconstruction styles, fragment-built
decoders, `certutil -decode`, non-PowerShell hosts, decode-then-execute in
practice, behaviour outside this lab, and any false-positive rate.

## 12. Evidence integrity

- DET-001 v2 and the Phase 6 detection stack are **byte-identical** before and
  after Phase 8 (`evidence/t15_integrity.txt`; hashes in `SHA256_MANIFEST.txt`).
- Phase 5/6/7 trees re-hashed after Phase 8: **0 changed, 0 missing**.
- Replay inputs are the preserved, unmodified `phase7/evidence/raw/` files.
- No credentials or secrets appear in this case, its JSON, or any Phase 8 artefact.
- SHA256 manifest for the whole Phase 8 tree: `phase8/SHA256_MANIFEST.txt`.

## 13. Evidence and provenance

- `phase8/evidence/DET003_DESIGN.md` — design/rationale
- `phase8/evidence/replay_inputs.txt` — replay inputs + hashes
- `phase8/evidence/replay_1..4_*` — replay result on preserved Phase 7 evidence
- `phase8/evidence/t05_benign_comparison.txt` — benign comparison suite
- `phase8/evidence/t06_phase7_detection_result.*` — Phase 7 detection result
- `phase8/evidence/t07_live_validation.txt` — live validation transcript
- `phase8/evidence/t08*`,`t09*` — local (WS001) and central (DC1) telemetry + DET-003 results
- `phase8/evidence/t10_correlation.txt` — correlation evidence
- `phase8/evidence/t11..t13` — investigation notes, false positives, limitations
- `phase8/evidence/t14_det001_vs_det003.txt` — DET-001 vs DET-003 comparison
- `phase8/PHASE8_REPORT.md` — the phase report
