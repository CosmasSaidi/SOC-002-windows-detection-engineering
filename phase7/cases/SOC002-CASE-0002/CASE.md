# SOC002-CASE-0002

**Title** — Phase 7 controlled blind-spot validation: DET-001 v2 does not cover
`-Command` with `[Convert]::FromBase64String(...)`

| | |
|---|---|
| Case ID | `SOC002-CASE-0002` |
| Status | `CLOSED` |
| Host | `SOC002-WS001.soc002.local` (192.168.56.102) |
| Collector | `SOC002-DC1` (192.168.56.10), ForwardedEvents |
| Account | `SOC002\Administrator` (existing authorised lab admin context) |
| LogonId | `0x644e0e` |
| Payload process | `powershell.exe` PID **1428**, parent `powershell.exe` PID 2936 (WinRS transport) |
| Marker | `SOC002-PHASE7-BLINDSPOT-TEST` |
| Controlled window (UTC) | `2026-10-14T23:06:30Z .. 2026-10-14T23:07:30Z` |
| Session window (UTC) | `2026-10-14T23:03:00Z .. 2026-10-14T23:09:30Z` |
| Final classification | **CONTROLLED TEST ACTIVITY / AUTHORISED BENIGN** |
| Detection outcome | **OUTCOME B — blind spot confirmed** |
| Detections modified in Phase 7 | **No** |

---

## 1. What was executed

One controlled execution, and only one. A PowerShell process was started
normally and reconstructed a harmless plain-text marker from a base64 blob using
`[Convert]::FromBase64String(...)` inside a `-Command` script. No
`-EncodedCommand`, `-enc`, `-e` or `-en` switch appears anywhere in that command
line.

The payload process command line (`OBSERVED`, Sysmon Event 1 RecId 4142 /
Security 4688 RecId 15758):

```
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command
  "$b='<base64>';$t=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b));Write-Output $t;
   Write-Output ('HOST='+$env:COMPUTERNAME); ... ('START_UTC='+(Get-Date)...)"

```

It was delivered through the lab's existing authorised WinRM administrator
channel by a one-line loader, which itself contains no encoded-command switch:

```
$c=[IO.File]::ReadAllText('C:\Windows\Temp\soc002-phase7\phase7_child_command.txt');
powershell.exe -NoProfile -NonInteractive -Command $c
```

Program output (`OBSERVED`, `evidence/t3_controlled_execution_ws001.txt`):

```
SOC002-PHASE7-BLINDSPOT-TEST
SOC002 PHASE 7 CONTROLLED BLIND-SPOT VALIDATION
Marker: SOC002-PHASE7-BLINDSPOT-TEST
Purpose: harmless marker reconstruction only. No persistence, no network,
no configuration change, no arbitrary code execution.

HOST=SOC002-WS001
USER=SOC002\Administrator
CHILD_PID=1428
START_UTC=2026-10-14T23:06:42.488Z
```

Exit code 0. Executed exactly once.

## 2. Why it was executed

Phase 6 documented a specific limitation: `SOC002-DET-001 v2` triggers on the
encoded-command CLI switch, so an alternative representation such as
`-Command [Convert]::FromBase64String(...)` is not covered. Phase 7 exists to
validate that limitation against one real, benign action — a true-positive
validation of the detection stack, not a new attack scenario.

## 3. What the telemetry observed

`OBSERVED` — the controlled window produced 14 events on WS001:

| Source | Records | RecordIds |
|---|---|---|
| Security 4688 | 5 | 15754, 15755, 15756, 15757, 15758 |
| Sysmon Event 1 | 5 | 4138, 4139, 4140, 4141, 4142 |
| PowerShell 4104 | 4 | 74338, 74343, 74350, 74354 |
| Sysmon Event 3 | 3 | 4144, 4145, 4146 |

The **same 14 events, with identical RecordIDs**, arrived in DC1
`ForwardedEvents` through WEF. Process lineage (`OBSERVED`,
`evidence/t8_process_lineage.txt`):

```
depth 0  winrshost.exe   PID 2992  <- svchost.exe 716
depth 1  conhost.exe     PID 3404  <- winrshost.exe
depth 1  cmd.exe         PID 1808  <- winrshost.exe   "cmd.exe /C powershell -encodedcommand <b64>"
depth 2  powershell.exe  PID 2936  <- cmd.exe         "powershell  -encodedcommand <b64>"       <- transport
depth 3  powershell.exe  PID 1428  <- powershell.exe  "... -Command "<...FromBase64String...>""  <- PAYLOAD
```

Network (`OBSERVED`, Sysmon Event 3): two inbound connections to
`WS001:5985` from the operator host, and one `lsass.exe` (PID 628) connection to
DC1 for domain authentication. Neither the payload nor the transport initiated
any network connection.

## 4. Was DET-001 v2 satisfied?

**No.** `OBSERVED` (`evidence/t6_det001_controlled.txt`):

- candidates matching the encoded-switch trigger: **1**
- of which **INVESTIGATION**: **0**
- baselined by `BASE-01` as INFO: **1** — and that one candidate is the *WinRS
  transport* powershell (PID 2936), not the payload
- payload-screen (`ESC-*`) escalations: **0**
- the payload process (PID 1428) was **never a candidate**

A static check of the payload's exact command line against the unmodified Phase 6
library returns no match (`evidence/t1_preflight_blindspot_check.txt`). The
trigger keys on `(?i)\s-(e|en|enc|encodedcommand)(\s|$)`, which the payload
command line does not contain.

`OBSERVED` — in the wider session window DET-001 v2 produced 3 INVESTIGATION
records, and all three are the **operator's own staged-file transfers**: the
upload decode step contains `[Convert]::FromBase64String($b)`, which trips
`ESC-03` and overrides the baseline. This is precisely the precision cost Phase 6
already measured and accepted. **None of the three is the payload process.**

## 5. Was DET-002 satisfied — and did it detect the activity?

DET-002 produced **context**, not a detection. `OBSERVED`
(`evidence/t6_det002_controlled.txt`): a lineage record for the payload process:

```
Process   = powershell.exe (PID 1428)
Chain     = powershell.exe(1428) <- powershell.exe(2936) <- cmd.exe(1808) <- winrshost.exe(2992) <- svchost.exe(716)
Shape LIN-01  = not matched
Encoded switch = absent
Severity  = CONTEXT
```

This is a second, independent telemetry source that surfaced the payload process
— and `Encoded switch = absent` is the only field-level discriminator the current
stack exposes. It is **not** a DET-001 detection, and DET-002 does not assert
maliciousness: it fires for every WinRM-delivered PowerShell process in this lab.

## 6. Was CORR-001 correlated?

**No.** `OBSERVED` (`evidence/t6_corr001_controlled.txt`): one correlation record,
for the *transport* process (PID 2936). The payload process is absent because
`CORR-001` iterates `DET-001` candidates only — **the correlation layer inherits
the trigger's blind spot by construction.**

## 7. Baseline comparison against the Phase 5/6 WinRM baseline

`OBSERVED` (`evidence/t7_baseline_comparison.txt`):

| Field | Phase 6 baseline (Phase 5 run) | Phase 7 controlled run |
|---|---|---|
| Host / account | `SOC002-WS001` / `SOC002\Administrator` | identical |
| Delivery path | WinRM/WinRS via `winrshost.exe` | identical |
| Tree depth to payload | 3 | 3 |
| Payload parent | `powershell.exe` (transport) | identical |
| Binary hash of both powershell.exe | same image | `B4E7BC24…85C4` for both |
| **Payload command form** | `-EncodedCommand <b64>` | `-Command "<…FromBase64String…>"` |

The two runs are identical except for the payload command-line form — the single
field DET-001 keys on. That is why the baseline shape alone cannot separate them,
and why the difference matters.

## 8. Was the known blind spot confirmed?

**Yes — OUTCOME B.** The Phase 7 activity was not detected by DET-001 v2, was not
correlated by CORR-001, and was surfaced only as context by DET-002. The blind
spot is confirmed by measurement on live, controlled activity rather than by
reasoning over preserved evidence.

No detection was modified to change this result.

## 9. Baseline-drift observations

- `OBSERVED`: all 22 WinRS transport wrappers in the session window matched
  `BASE-01` and resolved to a `winrshost.exe` ancestor — the baseline still
  behaves as Phase 6 documented.
- `OBSERVED`: the Phase 7 payload ran one level *below* the baselined transport
  powershell, exactly where the Phase 5 controlled test ran.
- `INFERRED`: `BASE-01` did not hide the Phase 7 activity. It never made a
  decision about it, because no candidate was created for the payload process.
- **Consideration recorded for the next phase:** broadening `BASE-01` to cover
  depth-3 `powershell.exe`-in-`powershell.exe` would hide exactly this activity.
  It is explicitly **not** done in Phase 7.

## 10. OBSERVED / INFERRED / NOT VERIFIED

Full lists are in `case.json` and `evidence/t10_investigation_notes.txt`;
the load-bearing ones are:

**OBSERVED**
- One execution; marker printed; exit code 0; command line carries `-Command` +
  `[Convert]::FromBase64String` and no encoded-command switch.
- 4688, Sysmon 1 and 4104 captured it locally; the same events reached DC1 via WEF.
- DET-001 v2 produced no candidate for the payload process in either window.
- DET-002 produced a lineage record for it with `Encoded switch = absent`.
- CORR-001 produced no record for it.
- The payload and transport initiated no network activity.
- The first delivery attempt was blocked by WS001's Restricted execution policy
  and nothing ran; no policy was changed.

**INFERRED**
- DET-001 v2's coverage is bounded by the encoded-command CLI switch, not by
  whether a base64 reconstruction happened.
- CORR-001 cannot see anything the trigger never produced.
- DET-002 is currently the only existing component that surfaces this behaviour,
  and only as context.

**NOT VERIFIED**
- Whether other switch-free representations (call operator, `Invoke-Expression`,
  compressed/hex blobs, multi-stage decoding) are equally invisible.
- Whether reconstruct-and-**execute** behaviour would be detected — the decoded
  content here is plain text and is never executed.
- Any behaviour outside this lab, at scale, or where WinRM is not the sanctioned
  management channel.
- Whether an adversary would choose this representation at all.

## 11. Classification and conclusion

**CONTROLLED TEST ACTIVITY / AUTHORISED BENIGN.**

The activity did exactly what the Phase 7 design required and nothing more: it
decoded a fixed base64 blob to plain text and printed it. No persistence, no
configuration change, no credential access, no privilege escalation, no lateral
movement, no payload network contact. The detection stack was run unchanged and
behaved exactly as its own documentation predicted.

**The finding of value is the detection gap, not the activity.**

## 12. Recommended follow-up

1. **Phase 8 — detection engineering (not performed here):** add a *second*
   detection for in-PowerShell base64 reconstruction and decode-then-execute
   adjacency. Do not extend the DET-001 trigger; keep the two coverage claims
   separately auditable.
2. Decide explicitly whether `CORR-001` should be able to correlate on DET-002
   lineage alone.
3. Keep the operator's own staging traffic in view — the `ESC-03` escalations
   caused by ordinary file transfers are a measurable precision cost.
4. Do **not** broaden `BASE-01` to depth-3 powershell-in-powershell.
5. Re-run this exact controlled test unchanged after any Phase 8 work, so the
   before/after comparison is honest.

## 13. Evidence and provenance

- Evidence inventory and SHA256: `phase7/SHA256_MANIFEST.txt`
- Detection outputs: `phase7/evidence/t6_det001_controlled.txt`,
  `…t6_det002_controlled.txt`, `…t6_corr001_controlled.txt`, `…t6_detection_stack_session.txt`
- Raw captured events: `phase7/evidence/raw/`
- Phase 5 and Phase 6 evidence: byte-for-byte unchanged (88 and 34 files re-hashed).
- No credentials or secrets are recorded in this case.
