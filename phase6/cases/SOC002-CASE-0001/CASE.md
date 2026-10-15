# SOC002-CASE-0001 — Encoded PowerShell on SOC002-WS001

| Field | Value |
|---|---|
| Case ID | `SOC002-CASE-0001` |
| Status | CLOSED |
| Opened | 2026-10-15 (Phase 5 triage; formalised in Phase 6) |
| Analyst | SOC-002 lab operator (single-analyst lab) |
| Classification | **CONTROLLED TEST ACTIVITY / AUTHORISED BENIGN** |
| Severity as raised | MEDIUM (investigation candidate, not proof of compromise) |
| Detection(s) | `SOC002-DET-001` (Phase 5 original) and `SOC002-DET-001 v2` (Phase 6) |
| Correlation record | `SOC002-CORR-001` → `CORR-SOC002-WS001-1500-20261014T215948Z` |
| Phase 6 lineage record | `SOC002-DET-002` → `LINEAGE 013` (Shape `LIN-01`: **not matched**) |

> This case is the Phase 5 controlled detection, re-opened as case-management
> material in Phase 6. The Phase 5 evidence is unchanged; Phase 6 only adds
> structure, tuning and correlation. No new activity was executed.

## 1. Alert IDs

| Alert / record | ID | Source |
|---|---|---|
| DET-001 candidate (Phase 5 broad run) | `[ALERT 010]` in `phase5/evidence/t6_detection_broad60_dc1.txt` | Phase 5 detection output |
| DET-001 candidate (Phase 5 tight run) | `[ALERT 001]` in `phase5/evidence/t6_detection_tight_dc1.txt` | Phase 5 detection output |
| Phase 6 replay candidate (retained) | `[ALERT 001]` in `phase6/evidence/t6_phase6_det001_v2_replay.txt` | Phase 6 replay over Phase 5 evidence |
| Phase 6 live candidate (retained) | `[ALERT 001]` in `phase6/evidence/t6_phase6_det001_v2_live_dc1.txt` | Phase 6 live run on DC1 |
| Sysmon Event 1 (primary signal) | `RecordId 3535`, ProcessGuid `{edcef402-fb54-6acf-ef04-000000000700}` | WS001 / DC1 ForwardedEvents |
| Security 4688 (process creation) | `RecordId 15141`, NewProcessId `0x5dc` (1500) | WS001 / DC1 ForwardedEvents |
| PowerShell 4104 (corroboration, payload) | `RecordId 72974`, ExecPID 1500, ScriptBlockId `039b9c99-15fb-488d-8046-46e868aa9a39` | WS001 / DC1 ForwardedEvents |
| PowerShell 4104 (runner block, separate) | `RecordId 72965`, ExecPID 4576, ScriptBlockId `e02842dc-7c5f-4bde-b18d-6ad4d161aa11` | WS001 |
| PowerShell 4104 (`$global:?` noise block) | `RecordId 72981`, ExecPID 1500 | WS001 |
| Phase 6 DET-002 lineage | `LINEAGE 013` | `phase6/evidence/t6_phase6_det002_lineage_live_dc1.txt` |
| Phase 6 correlation | `CORR-SOC002-WS001-1500-20261014T215948Z` | `phase6/evidence/t6_phase6_correlation_live_dc1.txt` |

## 2. Affected host and identity

| Field | Value | Label |
|---|---|---|
| Host | `SOC002-WS001.soc002.local` (192.168.56.102) | OBSERVED |
| Collector | `SOC002-DC1` (192.168.56.10), log `ForwardedEvents` | OBSERVED |
| User | `SOC002\Administrator` | OBSERVED |
| LogonId | `0x5c764d` (Sysmon `LogonId`; 4688 `SubjectLogonId` agrees) | OBSERVED |
| Process | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` PID 1500 | OBSERVED |
| Integrity | High (`S-1-16-12288`), TokenElevationType `%%1936` (Full) | OBSERVED |
| Binary hash | `SHA256=B4E7BC24BF3F5C3DA2EB6E9EC5EC10F90099DEFA91B820F2F3FC70DD9E4785C4` (unmodified Microsoft binary) | OBSERVED |

No credential material appears in this case by design.

## 3. Timestamps

All times are the lab's local clock (Africa/Nairobi, UTC+3); UTC is shown for
correlation with the event logs.

| Local (EAT) | UTC | Event | Label |
|---|---|---|---|
| 00:59:47.459 | 2026-10-14T21:59:47.459Z | Sysmon Ev1 RecId 3531 — `winrshost.exe` (5800) created by `svchost.exe` (716); remote WinRM shell host | OBSERVED |
| 00:59:47.547 | 2026-10-14T21:59:47.547Z | 4688 — `cmd.exe` (3596) created by `winrshost.exe` (5800) | OBSERVED |
| 00:59:47.574 | 2026-10-14T21:59:47.574Z | 4688 — `powershell.exe` (4576) created by `cmd.exe` (3596) — the operator/runner shell | OBSERVED |
| 00:59:48.071 | 2026-10-14T21:59:48.071Z | 4688 RecId 15141 — `powershell.exe` (1500) created by `powershell.exe` (4576) — **the controlled event** | OBSERVED |
| 00:59:48.080 | 2026-10-14T21:59:48.080Z | Sysmon Ev1 RecId 3535 — the controlled event, `-EncodedCommand` present — **primary DET-001 signal** | OBSERVED |
| 00:59:48.392 | 2026-10-14T21:59:48.392Z | PowerShell 4104 RecId 72974 — decoded ScriptBlockText, ExecPID 1500 | OBSERVED |
| 00:59:51.567 | 2026-10-14T21:59:51.567Z | Payload stdout captured (marker + `START_UTC` + `END_UTC`), process exit code 0, elapsed 3706 ms (matches `Start-Sleep -Seconds 3`) | OBSERVED |
| 00:04:46 … 01:05:46 | 2026-10-14T21:04:46Z … 22:05:46Z | Phase 5 broad 60-minute window: 39 DET-001 candidates in total for context | OBSERVED |

## 4. Evidence references

Phase 5 (original, preserved, not modified by Phase 6):

- `phase5/evidence/INVESTIGATION_NOTES.txt` — analyst reasoning for this case
- `phase5/evidence/CORRELATION_TIMELINE.txt` — multi-source correlation timeline
- `phase5/evidence/t6_detection_tight_dc1.txt` — the single-alert tight run
- `phase5/evidence/t6_detection_broad60_dc1.txt` — the 39-alert broad run
- `phase5/evidence/t6_detection_output_dc1.txt` — full detection output
- `phase5/evidence/DETECTION_LIMITATIONS.txt` — why the original rule was noisy
- `phase5/evidence/ATTACK_MAPPING.txt` — evidence-bounded ATT&CK mapping
- `phase5/evidence/DECODED_TEST_COMMAND.txt` — the decoded payload in full
- `phase5/evidence/raw/sysmon1-recid3535-ws001.xml` (and `-dc1.xml`) — raw Sysmon Event 1
- `phase5/evidence/raw/security4688-recid15141-ws001.xml` (and `-dc1.xml`) — raw 4688
- `phase5/evidence/raw/powershell4104-recid72974-ws001.xml` (and `-dc1.xml`) — raw 4104
- `phase5/evidence/t3z_ancestry_ws001.txt` — the process-creation ancestry next to the event
- `phase5/evidence/MANIFEST.txt` — Phase 5 integrity manifest

Phase 6 (this phase; derived, additive):

- `phase6/evidence/t6_phase6_det001_v2_live_dc1.txt` — live DET-001 v2 classification
- `phase6/evidence/t6_phase6_det001_v2_replay.txt` — replay over Phase 5 evidence
- `phase6/evidence/t6_phase6_det002_lineage_live_dc1.txt` — DET-002 lineage records
- `phase6/evidence/t6_phase6_correlation_live_dc1.txt` — CORR-001 correlation records
- `phase6/evidence/t6_comparison_phase5_vs_phase6.txt` — measured before/after
- `phase6/evidence/t2_false_positive_baseline.txt` — why the 38 benign alerts happened
- `phase6/evidence/t7_failure_modes.txt` — what breaks when telemetry is missing
- `phase6/evidence/TUNING_RATIONALE.txt` — what was tuned, and what was refused
- `phase6/evidence/SHA256_MANIFEST.txt` — hashes of every Phase 6 artefact

## 5. Detection references

| Detection | File | Version | Role in this case |
|---|---|---|---|
| `SOC002-DET-001` | `phase5/detections/detect_encoded_powershell.ps1` | Phase 5 (original, preserved) | Raised the original alert; lists every candidate with no classification |
| `SOC002-DET-001 v2` | `phase6/detections/detect_encoded_powershell_v2.ps1` | phase6-v2.0 | Same trigger, adds classification: this event is retained as `INVESTIGATION` because the parent is `powershell.exe`, not the WinRS wrapper |
| `SOC002-DET-002` | `phase6/detections/detect_powershell_lineage.ps1` | phase6-v2.0 | Adds the process lineage as context (`LINEAGE 013`) |
| `SOC002-CORR-001` | `phase6/detections/correlate_det001_det002.ps1` | phase6-v2.0 | Joins DET-001 and DET-002 for this process |
| shared logic | `phase6/detections/lib_soc002_v2.ps1` | phase6-v2.0 | The decision library used by all of the above **and** by the offline replay |

## 6. Investigation summary

A single encoded PowerShell execution ran on `SOC002-WS001` at
`2026-10-15 00:59:48` local. Three independent sources captured the same
process creation and agree on every identifier: Sysmon Event 1 (RecId 3535),
Security 4688 (RecId 15141) and PowerShell 4104 (RecId 72974), and the same
records were available centrally on `SOC002-DC1` `ForwardedEvents`.

The command line was `powershell.exe -NoProfile -EncodedCommand <base64>`. The
payload decodes to a self-labelled, harmless test script (a marker string,
host/user output, a 3-second sleep, and a completion line); the identical text
appears independently in the 4104 ScriptBlockText. No network connection came
from the process (Sysmon Event 3 filtered on its ProcessGuid = 0 events), no
task was registered and no service was installed in the window.

The process lineage is `powershell.exe (1500) <- powershell.exe (4576) <-
cmd.exe (3596) <- winrshost.exe (5800) <- svchost.exe (716) <- services.exe (604)`.
`winrshost.exe` is the WinRM shell host: in this lab WinRM is the sanctioned
management channel, and the operator drives every host through it. The nested
`powershell.exe -> powershell.exe` hop is the operator's runner executing the
encoded command.

Phase 6 re-triage keeps this event as an **investigation candidate** rather than
baselining it, and that is deliberate: its parent is `powershell.exe`, not the
`cmd.exe /C powershell -encodedcommand <b64>` WinRS wrapper that the narrow
baseline (`BASE-01`) recognises. The event is therefore *outside* the baseline
shape and is handed to a human - which is the correct outcome for a nested
interpreter running an encoded payload, even when the answer turns out to be
"authorised lab test".

## 7. Observed facts

1. OBSERVED — Sysmon Ev1 RecId 3535, Security 4688 RecId 15141 and PowerShell 4104 RecId 72974 describe the same process creation: `powershell.exe` PID 1500, ProcessGuid `{edcef402-fb54-6acf-ef04-000000000700}`, created 2026-10-14T21:59:48.071–.080Z.
2. OBSERVED — the executing account was `SOC002\Administrator`, LogonId `0x5c764d`, at High integrity with a full token.
3. OBSERVED — the command line contained `-EncodedCommand` with a UTF-16LE base64 payload and no other switches.
4. OBSERVED — the payload decodes to a script that only writes output and sleeps; the same text is present in the 4104 ScriptBlockText.
5. OBSERVED — `ProcessId 1500` of the 4104 (`System/Execution/@ProcessID`) equals the Sysmon PID, tying the decoded text to the execution.
6. OBSERVED — the parent is `powershell.exe` (4576), whose parent is `cmd.exe` (3596) created by `winrshost.exe` (5800).
7. OBSERVED — the binary is the unmodified Microsoft `powershell.exe` (SHA256 `B4E7BC24…4785C4`).
8. OBSERVED — Sysmon Event 3 filtered on ProcessGuid `{edcef402-fb54-…}` over 2 hours = 0 network events; TaskScheduler 106 = 0 and System 7045 = 0 in the window.
9. OBSERVED — the process exited with code 0 after 3706 ms, having printed the marker and timestamps.
10. OBSERVED — the identical records were present on the collector (`SOC002-DC1` `ForwardedEvents`), i.e. the detection could be run centrally.
11. OBSERVED (Phase 6) — in the same 62-minute collector window, Sysmon Event 1 encoded-PowerShell candidates stop entirely between 00:07:38 and 00:41:10 (2012 s) while Security 4688 continues to record encoded PowerShell (4 and 13 candidates in the 00:20 and 00:30 buckets).

## 8. Inferred facts

1. INFERRED — the execution was delivered remotely over WinRM and initiated by the lab operator, because the lineage root is `winrshost.exe`, the account is the lab's administrative account, and the payload is a lab-authored test script. This inference is consistent with, but not proven by, the process tree alone.
2. INFERRED — the encoded argument was produced by the WinRS transport used by the operator's tooling (`pywinrm`), which passes `cmd.exe /C powershell -encodedcommand <b64>`; that wrapper shape is what produces the 38 sibling alerts.
3. INFERRED — the outage in the Sysmon Event 1 stream (Observed fact 11) is a collection or retention effect rather than genuine inactivity, because Security 4688 shows continued activity in exactly those minutes. The mechanism is not established.
4. INFERRED — the near-identical contiguous timestamps and the shared ProcessGuid make it effectively certain the three sources describe one process creation and not three coincidences.

## 9. Not-verified items

1. NOT VERIFIED — who was physically at the keyboard and whether a second person could have used the same account. The lab is single-operator, but that is a design assumption, not telemetry.
2. NOT VERIFIED — that the absence of persistence is exhaustive. Security 4697/4698 are set to "No Auditing" on WS001, so their silence proves nothing; only TaskScheduler 106 and System 7045 were available.
3. NOT VERIFIED — the root cause of the Sysmon Event 1 gap (local log rollover vs collector-side drop/backlog). Determining it requires changing WEF/Sysmon configuration, which Phase 6 was instructed not to touch.
4. NOT VERIFIED — that the payload cannot have had an effect that produces no event at all (e.g. in-memory only). Absence of evidence in the available channels is not proof of absence.
5. NOT VERIFIED — how this detection behaves against real adversary telemetry. No adversary activity exists in this lab, and none was generated.
6. NOT VERIFIED — the exact text beyond the truncation point in the Phase 5 preserved output. The full text *is* available in the Phase 5 raw XML and the decoded test command file, but the Phase 5 broad-run report truncated it.

## 10. Final classification

**CONTROLLED TEST ACTIVITY / AUTHORISED BENIGN.**

Authority for this classification: the decoded payload is a self-labelled
harmless test script that was echoed independently by PowerShell 4104, the
execution was delivered through the lab's sanctioned WinRM management channel
by the lab's administrative account, and no network, persistence, escalation or
lateral-movement behaviour was observed from the process.

This classification is scoped to this event. It does **not** say that encoded
PowerShell is benign in general, and it does **not** baseline the
`powershell.exe -> powershell.exe` lineage: the same shape remains an
investigation candidate whenever it is seen.

## 11. Analyst conclusion

The alert was correct to fire. A nested PowerShell interpreter running a base64
`-EncodedCommand` is exactly the sort of thing a SOC should look at, and in this
case looking at it is what established that it was the lab testing its own
detection. The value of the detection is not that it decides - it is that it
delivers the decoded payload and the process lineage in one place so the decision
is fast. Phase 6 makes that hand-off explicit: this event is retained as an
`INVESTIGATION` candidate with severity MEDIUM, correlation `SOC002-CORR-001`
attaches the WinRM-rooted lineage, and nothing in the chain asserts malice.

## 12. Recommended follow-up

1. Extend the trigger to encoded payloads that never use the CLI switch
   (`-Command` with `[Convert]::FromBase64String(...)`), which the current rule
   does not see.
2. Add `pwsh.exe` to the encoded-payload surface in the same change, and verify
   it with a controlled test in the next phase.
3. Investigate and, if possible, close the Sysmon Event 1 continuity gap
   (Observed fact 11) - it is a real coverage hole, not a false positive, and it
   is currently mitigated only by the `-Include4688Fallback` path.
4. Decide whether 4688-rooted lineage should be allowed to reach the
   `BASELINE-TRANSPORT-CONFIRMED` tier at all, or remain capped at the weaker
   pattern tier as it is today.
5. Carry this case forward as the regression fixture for the next phase: any
   future tuning must keep this event as a retained investigation candidate.
