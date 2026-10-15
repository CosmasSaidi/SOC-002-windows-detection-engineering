# SOC-002 Phase 7 — Blind-Spot Validation Report

**Case** `SOC002-CASE-0002` · **Host** `SOC002-WS001.soc002.local` ·
**Collector** `SOC002-DC1` · **Result** `OUTCOME B — blind spot confirmed` ·
**Detections modified** none

---

## 1. Executive summary

Phase 6 documented that `SOC002-DET-001 v2` triggers on the *encoded-command CLI
switch*, and that an alternative representation such as
`-Command [Convert]::FromBase64String(...)` was therefore uncovered. Phase 7
tested exactly that limitation with **one** controlled, benign execution on
`SOC002-WS001` and then ran the **unmodified** Phase 6 detection stack over the
result.

The result is unambiguous:

| Question | Answer |
|---|---|
| Did `SOC002-DET-001 v2` detect the activity? | **No** — the payload process never became a candidate |
| Did `SOC002-DET-002` detect the activity? | **No** — it recorded the payload process as *lineage context*, with `Encoded switch = absent` |
| Did `SOC002-CORR-001` correlate the activity? | **No** — it iterates DET-001 candidates, so it inherits the blind spot |
| Was the known Phase 6 blind spot confirmed? | **Yes** |

Nothing was changed to influence the outcome. Local telemetry (Security 4688,
Sysmon Event 1, PowerShell 4104) and the corresponding central `ForwardedEvents`
copies were captured for the whole window, and Phase 5/Phase 6 evidence is
byte-for-byte intact.

## 2. Objective

Perform one controlled, benign **true-positive validation** against the existing
hardened detection stack, aimed at the single documented Phase 6 blind spot:
PowerShell that reconstructs data with `[Convert]::FromBase64String(...)` inside a
`-Command` script, i.e. **without** `-EncodedCommand` / `-enc` / `-e` / `-en`.

This is a detection-validation exercise (controlled adversary-emulation of a
*technique shape*), not an attack, and not production validation.

## 3. Controlled activity

Exactly one execution. The payload process was started normally and its command
line carries **no encoded-command switch**:

```
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command
  "$b='<base64>';$t=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b));Write-Output $t; ..."

delivered by:
$c=[IO.File]::ReadAllText('C:\Windows\Temp\soc002-phase7\phase7_child_command.txt');
powershell.exe -NoProfile -NonInteractive -Command $c
```

The blob decodes to **242 bytes of plain text** (the marker plus a purpose line)
and is only printed — never executed, invoked or piped, with no second decode
layer, no `Invoke-Expression`, no download, no file write, no persistence and no
configuration change.

Program output (`OBSERVED`, `evidence/t3_controlled_execution_ws001.txt`):

```
SOC002-PHASE7-BLINDSPOT-TEST
SOC002 PHASE 7 CONTROLLED BLIND-SPOT VALIDATION
Marker: SOC002-PHASE7-BLINDSPOT-TEST
HOST=SOC002-WS001
USER=SOC002\Administrator
CHILD_PID=1428
START_UTC=2026-10-14T23:06:42.488Z
```

Exit code 0. Delivery used the lab's existing authorised WinRM administrator
channel (`SOC002\Administrator`).

## 4. Exact timeline (UTC)

| UTC | Event |
|---|---|
| `23:02:43Z` | pre-state hashes of Phase 5 and Phase 6 taken; pre-flight check run |
| `23:03:09Z` | Phase 7 staging begins (detection stack pushed to DC1) |
| `23:04:16Z` | staging ends; payload staged on WS001, hash verified on-host |
| `23:04:27.966Z` | **first delivery attempt** — refused by WS001's Restricted execution policy; **payload did not run** |
| `23:06:23Z` | payload staged on WS001 (SHA256 `4AC23816…EDA365`) |
| `23:06:41.685Z` | WinRS transport `cmd.exe` PID 1808 created (`cmd.exe /C powershell -encodedcommand <b64>`) |
| `23:06:41.712Z` | transport `powershell.exe` PID 2936 created — the only DET-001 candidate, baselined |
| `23:06:42.046Z` | **payload `powershell.exe` PID 1428 created** — `-Command` + `[Convert]::FromBase64String` |
| `23:06:42.488Z` | payload prints the marker (child `START_UTC`) |
| `23:06:42.951Z` | execution returns, exit code 0 |
| `23:10:35Z` | central `ForwardedEvents` collection confirms the same 14 events |
| `23:17:49Z` | post-run integrity re-check and lab temp cleanup |

## 5. Local telemetry (SOC002-WS001)

`OBSERVED` — controlled window `23:06:30Z .. 23:07:30Z`, 17 events
(`evidence/t4_local_telemetry_ws001_controlled.txt`):

| Source | Count | Record IDs | Evidence |
|---|---|---|---|
| Security 4688 | 5 | 15754–15758 | `CommandLine` populated; creator chain intact |
| Sysmon Event 1 | 5 | 4138–4142 | full `CommandLine`, `ProcessGuid`, `ParentProcessGuid`, `Hashes`, `LogonId` |
| PowerShell 4104 | 4 | 74338, 74343, 74350, 74354 | `ScriptBlockId` per executing PID |
| Sysmon Event 3 | 3 | 4144–4146 | network (see below) |

Measurement prerequisites verified present and left untouched: `4688`
CommandLine policy = 1, ScriptBlockLogging = 1, Sysmon operational = enabled,
PowerShell operational = enabled, WEF subscription active.

Network — the payload and the transport initiated **nothing**: the three Event 3
records are two inbound connections to `WS001:5985` from the operator host and
one `lsass.exe` (PID 628) connection to DC1 for domain authentication.

## 6. Central telemetry (SOC002-DC1)

`OBSERVED` — `ForwardedEvents` for the same window contains **the same 17 events
with identical RecordIDs** (`evidence/t5_central_telemetry_dc1_controlled.txt`).
WEF delivery is therefore confirmed for all four sources, and the central record
set is a faithful copy of the local one rather than a partial subset.

## 7. SOC002-DET-001 v2 result

`OBSERVED` (`evidence/t6_det001_controlled.txt`), collection window
`23:06:30Z .. 23:07:30Z`:

```
Candidate alerts (encoded PowerShell matched)  = 1
Retained investigation candidates              = 0
Suppressed by narrow baseline (BASE-01)        = 1
Escalated back by payload screen (ESC-*)       = 0
```

The single candidate is the **WinRS transport** powershell (PID 2936), classified
`BASELINE-TRANSPORT-CONFIRMED` (INFO) because its parent is the WinRS wrapper
`cmd.exe /C powershell -encodedcommand <b64>`. **The payload process (PID 1428)
was never a candidate.**

Applying the unmodified Phase 6 library directly to the payload's exact command
line returns no match (`evidence/t1_preflight_blindspot_check.txt`), while the
Phase 5 encoded control line returns a match:

| Command line | Image matches | Encoded-switch trigger |
|---|---|---|
| Phase 5 control `powershell.exe -NoProfile -EncodedCommand <b64>` | yes | **True** |
| Phase 7 subject `… -Command "$b=…FromBase64String…"` | yes | **False** |

## 8. SOC002-DET-002 result

`OBSERVED` (`evidence/t6_det002_controlled.txt`): 2 process-create records
examined, 2 with a WinRM host in the ancestry, 1 of the exact `LIN-01` shape, 0
unresolved. One of the two is **the payload process**:

```
Process        = powershell.exe (PID 1428)
Chain          = powershell.exe(1428) <- powershell.exe(2936) <- cmd.exe(1808) <- winrshost.exe(2992) <- svchost.exe(716)
Shape LIN-01   = not matched
Encoded switch = absent
Severity       = CONTEXT
```

This is a second, independent telemetry source surfacing the payload — and
`Encoded switch = absent` is the only field-level discriminator the current stack
exposes. It is explicitly **not** a DET-001 detection and carries no verdict;
DET-002 fires for every WinRM-delivered PowerShell process in this lab.

## 9. SOC002-CORR-001 result

`OBSERVED` (`evidence/t6_corr001_controlled.txt`): 1 DET-001 signal, 1 of those
with a DET-002 lineage record, 0 explanation gaps, 1 correlation record — **for
the transport process (PID 2936) only**. The payload process is absent because
`CORR-001` iterates DET-001 candidates.

**Structural finding:** the correlation layer cannot see anything the trigger
never produced, even when DET-002 already has a record for it.

## 10. Baseline comparison against Phase 5/6

`OBSERVED` (`evidence/t7_baseline_comparison.txt`):

| Field | Phase 6 baseline (Phase 5 run) | Phase 7 controlled run |
|---|---|---|
| Host / account | `SOC002-WS001` / `SOC002\Administrator` | identical |
| Delivery path | WinRM/WinRS rooted at `winrshost.exe` | identical |
| Tree depth to payload | 3 | 3 |
| Payload parent image | `powershell.exe` (the transport) | identical |
| Transport binary SHA256 | same image as the payload process | `B4E7BC24…85C4` (both powershell.exe) |
| Transport cmd.exe | `cmd.exe /C powershell -encodedcommand <b64>` | identical |
| **Payload command form** | `-EncodedCommand <b64>` | `-Command "…[Convert]::FromBase64String…"` |

Everything matches except the payload command-line form — precisely the field
`DET-001` keys on. The two runs are **not distinguishable at the level the
baseline inspects**; they are distinguishable only at the one field the trigger
reads.

## 11. Detection blind-spot result

**CONFIRMED — OUTCOME B.** `SOC002-DET-001 v2` produced no candidate for the
payload process in either the controlled window or the wider session window,
because its trigger requires an encoded-command CLI switch and the command line
has none. The activity was detected by nothing; it was *observed* by DET-002 as
context and *not* correlated by CORR-001.

No detection was changed to achieve this result, and none will be until a later
phase.

## 12. Investigation

- **Exactly one execution**, exit code 0, marker reproduced; the reconstructed
  content is plain text and was never executed.
- **One failed first attempt** is recorded honestly: a staged `.ps1` invoked with
  `&` was refused by WS001's Restricted execution policy (`RC=1`). The payload
  did **not** run and no child PowerShell process was created (confirmed from the
  session Sysmon evidence). No policy was changed in response — weakening a
  control was not an option, so the delivery mechanism was adapted instead.
- **Delivery constraints were documented, not worked around.** WS001's effective
  execution policy is Restricted, and a WinRS transport command line is bounded
  (~8 KB), so the 6 KB collection body could not be sent inline. Script *content*
  delivery is the lab's normal mode (it is what the WinRS `-EncodedCommand`
  transport has always done), so the payload was staged and executed as content.
  No `-ExecutionPolicy` switch was used anywhere.
- **Session-window context:** 25 candidates / 22 baselined / 3 INVESTIGATION. All
  three INVESTIGATION records are the **operator's own staged-file transfers**
  (`[Convert]::FromBase64String($b)` in the upload decode step trips `ESC-03`).
  This is the exact precision cost Phase 6 measured and accepted; **none of the
  three is the payload process.**
- DET-001's output contains **no reference to the Phase 7 marker** at all, so no
  alert in this phase can be mistaken for a detection of the payload.

## 13. Classification

**CONTROLLED TEST ACTIVITY / AUTHORISED BENIGN.**

The activity performed exactly what the design specified and nothing more. The
detection stack was run unchanged and behaved exactly as its own documentation
predicted. **The finding of value is the detection gap, not the activity.**

## 14. Evidence inventory

| Requirement | File |
|---|---|
| Exact controlled command | `scripts/phase7_child_command.txt`, `scripts/execute_phase7_once.py`, `evidence/phase7_payload_metadata.json` |
| Exact UTC execution time | `evidence/t3_controlled_execution_ws001.txt`, `evidence/t8_process_lineage.txt` |
| Generated marker | `evidence/t3_controlled_execution_ws001.txt`, `evidence/phase7_payload_decoded.txt` |
| Local 4688 | `evidence/t4_local_telemetry_ws001_controlled.txt` (A) |
| Local Sysmon 1 | same file (B) |
| Local 4104 | same file (C) |
| Central ForwardedEvents | `evidence/t5_central_telemetry_dc1_controlled.txt` |
| DET-001 v2 output | `evidence/t6_det001_controlled.txt`, `evidence/t6_detection_stack_controlled.txt` |
| DET-002 output | `evidence/t6_det002_controlled.txt` |
| CORR-001 output | `evidence/t6_corr001_controlled.txt` |
| Process lineage | `evidence/t8_process_lineage.txt` |
| Phase 6 comparison | `evidence/t7_baseline_comparison.txt` |
| Detection result | `evidence/t9_detection_result.json` / `.txt` |
| Investigation notes | `evidence/t10_investigation_notes.txt` |
| Limitations | `evidence/t11_limitations.txt` |
| SHA256 manifest | `SHA256_MANIFEST.txt` |
| Case | `cases/SOC002-CASE-0002/CASE.md`, `case.json` |
| Raw captured events | `evidence/raw/` (+ session windows `t4b`, `t5b`) |
| Cleanup / preservation | `evidence/t9_integrity_and_cleanup.txt` |
| Exclusivity / containment checks | `evidence/t12_exclusivity_checks.txt` |

## 15. SHA256 integrity information

`SHA256_MANIFEST.txt` hashes every Phase 7 file (excluding itself) and records:

- **Phase 5 preservation:** 88 files re-hashed after the run — **0 changed, 0
  missing**.
- **Phase 6 preservation:** 34 files re-hashed — **0 changed**.
- **Detection stack as used:** the five Phase 6 detection files were hashed
  locally before staging, re-verified on WS001 and re-printed by the runner on
  DC1 at detection time; all three sets agree. This is what backs the claim that
  no detection logic was modified.

## 16. Limitations

Full list in `evidence/t11_limitations.txt`. The load-bearing ones:

1. **One run, one host, one representation.** No rate is measured and no
   generalisation to other representations is claimed.
2. **Only the CLI-switch dimension was varied.** Call operator with a decoded
   string, `Invoke-Expression`, compressed/hex blobs, multi-stage decoding —
   all `NOT VERIFIED`.
3. **Plain text, not decode-and-execute.** Nothing is claimed about detecting a
   command that reconstructs *and then executes* content.
4. **The operator's own tooling trips ESC-03.** Ordinary file staging is
   indistinguishable from "something decoding base64", which inflates DET-001
   alert volume in any operator session.
5. **CORR-001 inherits the trigger's blind spot** by construction.
6. **DET-002 is high-volume context.** It flagged the payload, but it would
   equally flag any neighbouring administrative call.
7. **Telemetry dependencies and 4104 content.** The chain depends on the Phase 4
   enablers; the payload's 4104 block carries the base64 blob, not the
   reconstructed marker.
8. **No adversary, not production.** Absence of other activity is *not observed*,
   not *disproved*.

## 17. Baseline-drift observations

- `OBSERVED`: all **22** WinRS transport wrappers in the session window still
  matched `BASE-01` and resolved to a `winrshost.exe` ancestor — the baseline
  behaves exactly as Phase 6 documented. **No pattern drift.**
- `OBSERVED`: the payload ran one level *below* the baselined transport
  powershell — the same position the Phase 5 controlled test occupied.
- `INFERRED`: `BASE-01` did **not** hide the Phase 7 activity. It never had to
  decide about it, because no candidate was created for the payload process.
- **Recorded consideration, deliberately not acted on:** broadening `BASE-01` to
  cover depth-3 `powershell.exe`-in-`powershell.exe` would hide exactly the
  activity Phase 7 just demonstrated. The baseline is therefore left unchanged
  and the finding is handed to the next phase.

## 18. Recommended next phase

**Phase 8 — Detection engineering for the in-PowerShell decode gap (not
started here).**

1. Add a **second, complementary** detection for in-PowerShell base64
   reconstruction (`[Convert]::FromBase64String`, `FromBase64CharArray`) and for
   decode-then-execute adjacency. Do **not** extend the DET-001 trigger, so
   DET-001's own coverage claim stays auditable.
2. Decide explicitly whether `CORR-001` should be able to correlate on DET-002
   lineage alone, given that it currently cannot see anything the trigger misses.
3. Re-run **this exact controlled test unchanged** after the Phase 8 work so the
   before/after comparison is honest, and re-use the Phase 7 baseline-drift check
   to confirm no regression.
4. Keep the operator's own staging traffic in view — the `ESC-03` escalations
   caused by ordinary file transfers are a measurable precision cost that will
   grow with tooling use.

Phase 7 stops here. No Phase 8 work was begun.
