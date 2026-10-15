# SOC-002 — Investigation and Cases

SOC-002 contains three documented cases. In each one the activity was
**controlled, authorised and benign**; the classification in every case is
**CONTROLLED TEST ACTIVITY / AUTHORISED BENIGN**. No controlled activity is
described as malicious, and none of the cases is presented as a real compromise.

Evidence labels used throughout:

- **OBSERVED** — read directly from a telemetry field or host output.
- **INFERRED** — a conclusion drawn from several observations.
- **NOT VERIFIED** — not tested, or not auditable in this lab.

Case material (structured `CASE.md` + `case.json`) lives under the original phase
trees; this document summarises it without rewriting it.

---

## `SOC002-CASE-0001` — Encoded PowerShell on SOC002-WS001 (Phase 5, formalised in Phase 6)

**Source:** `phase6/cases/SOC002-CASE-0001/CASE.md`, `.../case.json`
**Status:** CLOSED · **Severity as raised:** MEDIUM (investigation candidate, not proof of compromise)

### Objective

Triage the first `SOC002-DET-001` alert: was this execution malicious, or an
authorised/benign action? The detection deliberately says "investigation
required", so the case exists to answer that question from evidence.

### Controlled activity

`OBSERVED` — one benign encoded-PowerShell execution on `SOC002-WS001`:

- Command: `powershell.exe -NoProfile -EncodedCommand <base64>` (base64 payload
  1688 chars).
- Marker: `SOC002-PHASE5-ENCODED-POWERSHELL`.
- Delivery: the authorised WinRM administrative channel as `SOC002\Administrator`.
- Execution: `2026-10-14T21:59:48.553Z … 21:59:51.567Z`; exit code 0; elapsed
  3706 ms (matching the payload's `Start-Sleep -Seconds 3`).
- Decoded payload (`phase5/evidence/DECODED_TEST_COMMAND.txt`): sets a marker
  variable, writes the marker/host/user/`START_UTC`, sleeps 3 s, writes
  `END_UTC` and `BENIGN_CONTROLLED_TEST_COMPLETE`. It performs **no** file write,
  registry change, service/task creation, credential access, download or decode
  of external data.

### Telemetry observed

`OBSERVED` — one process creation, described consistently by three sources:

| Source | Record | Key fields |
|---|---|---|
| Sysmon Event 1 (primary) | RecId 3535 | `ProcessGuid {edcef402-fb54-6acf-ef04-000000000700}`, `ProcessId 1500`, `Image ...\powershell.exe`, `CommandLine ... -EncodedCommand <b64>`, `User SOC002\Administrator`, `LogonId 0x5c764d`, parent `powershell.exe (4576)`, integrity High, `Hashes SHA256=B4E7BC24…4785C4` |
| Security 4688 | RecId 15141 | `NewProcessId 0x5dc` (1500), `CommandLine` populated, `Subject SOC002\Administrator`, `TokenElevationType %%1936` (Full) |
| PowerShell 4104 (corroboration) | RecId 72974 | `ExecPID 1500` (exact match), `ScriptBlockId 039b9c99-15fb-488d-8046-46e868aa9a39`, `MessageNumber 1/1`, `ScriptBlockText` == decoded script |

The same records (same `RecordId`, same fields) were present on `SOC002-DC1`
`ForwardedEvents` (`phase5/evidence/raw/*-dc1.xml`). Sysmon Event 3 filtered on
the encoded process's `ProcessGuid` over a 2-hour window = **0 events**: the
payload made no network connection. Process chain (`OBSERVED`):
`svchost.exe (716) → winrshost.exe (5800) → cmd.exe (3596) → powershell.exe (4576) → powershell.exe (1500)`.

### Detection outcome

- `SOC002-DET-001` fired. Scoped to the event, the tight run produced **1 alert,
  corroborated** (`phase5/evidence/t6_detection_tight_dc1.txt`).
- Over the 60-minute window it produced **39 alerts** for that one real event; 38
  were the operator's own WinRM administration
  (`phase5/evidence/t6_detection_broad60_dc1.txt`).
- Phase 6 re-assessment (`SOC002-DET-001 v2`) retained the event as
  **INVESTIGATION** (MEDIUM). It sits outside the `BASE-01` shape because its
  parent is `powershell.exe`, not the `cmd.exe` WinRS wrapper.
- `SOC002-CORR-001` attached the WinRM-rooted lineage
  (`CORR-SOC002-WS001-1500-20261014T215948Z`); `SOC002-DET-002` recorded
  `LINEAGE 013` with shape `LIN-01` **not matched** (immediate grandparent is
  `powershell.exe`, not `cmd.exe`).

### Investigation conclusion

**CONTROLLED TEST ACTIVITY / AUTHORISED BENIGN.** Reasoning (`OBSERVED` unless
noted):

- the decoded payload is a self-labelled harmless test script, independently
  echoed by 4104;
- execution was delivered through the lab's sanctioned WinRM management channel;
- no network activity from the affected process (Sysmon Ev3 = 0);
- no persistence: TaskScheduler Operational 106 = 0 and System 7045 = 0 in the
  window;
- no privilege escalation: the token was already elevated (High integrity, Full
  token) inherited from the Administrator logon;
- no lateral movement from WS001.

`INFERRED`: the parent chain is the classic signature of a remote WinRM session,
so the execution was initiated remotely over WinRM as `SOC002\Administrator` by
the lab operator — which is how the lab is operated and is authorised here.

The classification is **scoped to this event only**. It does not assert that
encoded PowerShell is benign in general, and it does not baseline the
`powershell.exe → powershell.exe` lineage.

### Evidence

- `phase5/evidence/INVESTIGATION_NOTES.txt` — the 12 analyst questions and answers
- `phase5/evidence/CORRELATION_TIMELINE.txt` — multi-source timeline
- `phase5/evidence/DECODED_TEST_COMMAND.txt` — verbatim decoded script + base64 + hash
- `phase5/evidence/raw/*-ws001.xml` / `*-dc1.xml` — raw source and centralised events
- `phase5/evidence/t6_detection_tight_dc1.txt`, `t6_detection_broad60_dc1.txt`
- `phase6/evidence/t6_phase6_det001_v2_{replay,live_dc1}.txt`, `t6_phase6_correlation_live_dc1.txt`, `t6_phase6_det002_lineage_live_dc1.txt`
- `phase6/cases/SOC002-CASE-0001/`

### Limitations

- **Auditing gap:** Security 4697/4698 are set to **No Auditing** on WS001, so
  their absence proves nothing; the persistence conclusion rests on
  TaskScheduler 106 and System 7045.
- **Single-operator assumption:** "who was physically present" is an assumption,
  not telemetry.
- **Detection scope:** the alert fired on the encoded-command switch; the
  detection is a triage signal, not a compromise verdict.
- **No adversary telemetry** exists; behaviour against a real intrusion is
  `NOT VERIFIED`.
- Phase 6 measured a **2012-second hole** in the collector's Sysmon Event 1
  stream within the broad window (Security 4688 kept recording). Root cause
  `NOT VERIFIED`.

---

## `SOC002-CASE-0002` — Phase 7 blind-spot validation

**Source:** `phase7/cases/SOC002-CASE-0002/CASE.md`, `.../case.json`
**Status:** CLOSED · **Result:** `OUTCOME B — blind spot confirmed` · **Detections modified:** none

### Objective

Validate one documented Phase 6 limitation with a single controlled, benign
execution: PowerShell that reconstructs data with
`[Convert]::FromBase64String(...)` inside a `-Command` script, i.e. **without**
`-EncodedCommand` / `-enc` / `-e` / `-en`. This is a detection-validation
exercise (controlled emulation of a *technique shape*), not an attack and not
production validation.

### Controlled activity

`OBSERVED` — exactly one execution on `SOC002-WS001`, marker
`SOC002-PHASE7-BLINDSPOT-TEST`:

- Payload process command line (Sysmon Ev1 RecId 4142 / Security 4688 RecId
  15758):
  `"C:\...\powershell.exe" -NoProfile -NonInteractive -Command "$b='<base64>';$t=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b));Write-Output $t; ..."`
  — **no encoded-command switch anywhere**.
- Delivered by a one-line loader from a staged text file, over the authorised
  WinRM administrator channel.
- The blob decodes to **242 bytes of plain text** and is only printed — never
  executed, invoked or piped.
- Payload process: `powershell.exe` PID **1428**, parent `powershell.exe` PID 2936
  (the WinRS transport). `LogonId 0x644e0e`.
- Executed at `2026-10-14T23:06:42.046Z`; exit code 0.
- `OBSERVED` — a first delivery attempt (`23:04:27Z`) was refused by WS001's
  Restricted execution policy; the payload did **not** run, and no policy was
  changed (`-ExecutionPolicy Bypass` was not used at any point).

### Telemetry observed

`OBSERVED` — the controlled window (`23:06:30Z … 23:07:30Z`) produced 14 events on
WS001:

| Source | Count | Record IDs |
|---|---|---|
| Security 4688 | 5 | 15754–15758 |
| Sysmon Event 1 | 5 | 4138–4142 |
| PowerShell 4104 | 4 | 74338, 74343, 74350, 74354 |
| Sysmon Event 3 | 3 | 4144–4146 |

The **same 14 events with identical RecordIDs** arrived in DC1 `ForwardedEvents`.
Lineage (`phase7/evidence/t8_process_lineage.txt`):

```
depth 0  winrshost.exe   PID 2992  <- svchost.exe 716
depth 1  cmd.exe         PID 1808  <- winrshost.exe   "cmd.exe /C powershell -encodedcommand <b64>"
depth 2  powershell.exe  PID 2936  <- cmd.exe         "powershell -encodedcommand <b64>"        <- transport
depth 3  powershell.exe  PID 1428  <- powershell.exe  "... -Command "<...FromBase64String...>"" <- PAYLOAD
```

Network: two inbound connections to `WS001:5985` from the operator host and one
`lsass.exe` connection to DC1 for domain authentication. Neither the payload nor
the transport initiated any connection.

### Detection outcome

**OUTCOME B — blind spot confirmed.** The unmodified Phase 6 stack was run over
the result:

| Detection | Result |
|---|---|
| `SOC002-DET-001 v2` | **MISS** — 1 candidate matched the trigger and it was the *WinRS transport* (PID 2936), baselined by `BASE-01` as INFO; payload-screen (`ESC-*`) escalations: 0; the payload (PID 1428) was **never a candidate** |
| `SOC002-DET-002` | CONTEXT — recorded the payload as lineage context with `Encoded switch = absent` |
| `SOC002-CORR-001` | no correlation — it iterates DET-001 candidates and therefore inherits the blind spot |

A static check of the payload's command line against the unmodified Phase 6
library returns no match (`phase7/evidence/t1_preflight_blindspot_check.txt`). In
the wider session window, DET-001 v2 produced 3 INVESTIGATION records — all three
were the **operator's own staged-file transfers**, which contain
`[Convert]::FromBase64String($b)` and trip `ESC-03`.

### Investigation conclusion

**CONTROLLED TEST ACTIVITY / AUTHORISED BENIGN.** One benign execution that did
exactly what the design required: reconstructed a harmless marker and printed it.
No persistence, no configuration change, no credential access, no privilege
escalation, no lateral movement, no payload network contact, and the temporary
staging body was removed. The finding of value is the **detection behaviour**, not
the activity.

The investigation notes record the reasoning explicitly: the marker never appears
in raw telemetry (it exists only inside the base64 blob and in process stdout),
exactly one payload-shaped process creation occurred, and persistence-shaped
process creation in the session window = 0.

Baseline-drift observation (`OBSERVED`): all 22 WinRS transport wrappers in the
session window still matched `BASE-01` and resolved to a `winrshost.exe` ancestor —
no pattern drift. `BASE-01` did **not** hide the Phase 7 activity; it never had to
decide about it, because no candidate was created for the payload process.

### Evidence

- `phase7/PHASE7_REPORT.md`, `phase7/README.md`
- `phase7/evidence/t3_controlled_execution_ws001.txt` — execution output
- `phase7/evidence/t4_local_telemetry_ws001_controlled.txt`, `t5_central_telemetry_dc1_controlled.txt`
- `phase7/evidence/t6_det001_controlled.txt`, `t6_det002_controlled.txt`, `t6_corr001_controlled.txt`
- `phase7/evidence/t7_baseline_comparison.txt`, `t8_process_lineage.txt`, `t9_detection_result.*`
- `phase7/evidence/t10_investigation_notes.txt`, `t11_limitations.txt`, `t12_exclusivity_checks.txt`
- `phase7/evidence/raw/` — preserved raw XML used as the Phase 8 replay input
- `phase7/cases/SOC002-CASE-0002/`

### Limitations

- **One run, one host, one representation.** No rate is measured and no
  generalisation is claimed.
- Only the **CLI-switch dimension** was varied; other decode paths (call operator,
  `Invoke-Expression`, compressed/hex blobs, multi-stage decoding) are
  `NOT VERIFIED`.
- **Plain text, not decode-and-execute.** Nothing is claimed about detecting a
  command that reconstructs *and then executes* content.
- The operator's own tooling trips `ESC-03`, inflating DET-001 volume in any
  operator session.
- **`CORR-001` inherits the trigger's blind spot** by construction.
- **`DET-002` is high-volume context** and would flag any neighbouring
  administrative call.
- The payload's 4104 block carries the base64 blob, not the reconstructed marker.
- **No adversary, not production.** Absence of other activity is *not observed*,
  not *disproved*.

---

## `SOC002-CASE-0003` — Phase 8 `SOC002-DET-003` validation

**Source:** `phase8/cases/SOC002-CASE-0003/CASE.md`, `.../case.json`
**Status:** CLOSED · **Result:** `DET-003 IDENTIFIED the Phase 7 blind spot`

### Objective

Build a **separate, complementary** detection for the confirmed Phase 7 gap and
validate it against (a) the preserved Phase 7 evidence and (b) one controlled,
benign live run — without modifying `SOC002-DET-001 v2`.

### Controlled activity

`OBSERVED` — one harmless live execution on `SOC002-WS001` at
`2026-10-14T23:35:06Z … 23:35:08Z`:

- Marker: `SOC002-PHASE8-DET003-TEST`.
- Child command line: `powershell.exe -NoProfile -NonInteractive -Command "$b='<base64>';$t=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b));Write-Output $t"`.
- **No encoded-command switch**; reconstructs with `[Convert]::FromBase64String`.
- Decoded content: 151 bytes of plain text (marker + purpose line), only printed,
  never executed.
- Payload body SHA256 `C1735EFC…F58FD2`; payload process PID **1268**,
  `LogonId 0x695d72`; delivered over the authorised WinRM channel as
  `SOC002\Administrator`.
- Exit code 0; no network contact, no persistence, no configuration change, no
  permanent files (temp body removed, `TMP_REMOVED=True`).

Replay target (`OBSERVED`): the preserved, unmodified `phase7/evidence/raw/`
files — i.e. the exact Phase 7 blind-spot event (payload PID 1428).

### Telemetry observed

`OBSERVED` — DET-003 flagged the live payload in three local sources, all PID
1268, and the same RecordIDs arrived at DC1 via WEF:

| Source | Record | Details |
|---|---|---|
| Security 4688 | RecId 16123 | `2026-10-14T23:35:07.263Z`, PID 1268, `LogonId 0x695d72` |
| Sysmon Event 1 | RecId 4600 | `2026-10-14T23:35:07.272Z`, PID 1268, `ProcessGuid {edcef402-11ab-6ad0-5706-000000000700}` |
| PowerShell 4104 | RecId 77450 | `2026-10-14T23:35:07.598Z`, `ExecPID 1268`, `ScriptBlockId 50aa4a2f-00ff-4f0f-b0d4-2f5f2543ccae` |

A separate DET-003 hit (4104 RecId 77434, ExecPID 1996) is the operator's own
staging script carrying the payload text as a literal — labelled `CTX-PLUMBING`
and explicitly not the activity under test.

### Detection outcome

- **Replay:** DET-003 flagged the Phase 7 payload (PID 1428) in **all four**
  preserved Phase 7 views (WS001 local + DC1 `ForwardedEvents`, controlled +
  session windows), with `REC-01 [Convert]::FromBase64String`, severity LOW.
- **Contrast:** in every view the Phase 7 payload was DET-001-miss / DET-003-hit,
  and the WinRS transport (PID 2936) was DET-001-hit / DET-003-miss — the two
  detections are **disjoint** here.
- **Live:** the payload PID 1268 was DET-003 **TRIGGER (REC-01, LOW)** and
  DET-001 v2 **miss**, while the transport PID 5468 was the reverse.
- **Precision:** the trigger does **not** fire on the word "Base64" and
  **suppresses** comment-only mentions (benign comparison suite
  `phase8/evidence/t05_benign_comparison.txt`).
- **Correlation:** `SOC002-CORR-002` linked DET-003 with Sysmon Event 1, Security
  4688, the PowerShell 4104 block and the DET-002 lineage, using PID +
  `ProcessGuid` agreement with a ±120 s tolerance. Correlation gaps are printed,
  never forced.

### Investigation conclusion

**CONTROLLED TEST ACTIVITY / AUTHORISED BENIGN.** One benign execution that
reconstructed a harmless marker and printed it. The DET-003 record raises the
question *who ran a base64 reconstruction, where did it come from, and did the
reconstructed data feed an execution or a retrieval?* — not *is this malicious?*.
For this case the operator is the authorised lab admin, the delivery path is the
sanctioned WinRM channel, the decoded content is a harmless marker, and nothing
decoded was executed. **The finding of value is the detection behaviour, not the
activity.**

### Evidence

- `phase8/PHASE8_REPORT.md`, `phase8/README.md`
- `phase8/evidence/DET003_DESIGN.md`, `t14_det001_vs_det003.txt`
- `phase8/evidence/replay_1..4_*` (4 preserved Phase 7 views) + `replay_inputs.txt`
- `phase8/evidence/t05_benign_comparison.txt` — benign comparison suite
- `phase8/evidence/t07_live_validation.txt`, `t08*`, `t09*`, `t10_correlation.txt`
- `phase8/evidence/t11_investigation_notes.txt`, `t12_false_positive_considerations.txt`, `t13_limitations.txt`, `t15_integrity.txt`
- `phase8/cases/SOC002-CASE-0003/`

### Limitations

- **Text-only trigger:** fragment-assembled names, custom decoders,
  `certutil -decode`, compiled binaries and non-PowerShell hosts are not covered.
- **Decode-and-execute is inferred** from text proximity, not observed.
- **Here-strings** are not comment-stripped.
- **PID reuse** handled only within ±120 s.
- **Operator plumbing inflates volume:** in the live 60-minute DC1 run, 7 of 13
  DET-003 candidates were operator plumbing and 6 were the two controlled
  payloads — observed behaviour on a tiny sample, **not a false-positive rate**.
- **One host, one representation, one live run**; no rate, no generalisation.
- **No adversary, not production.** Absence of other activity is *not observed*,
  not *disproved*.

---

## Cross-case notes

- All three cases are **controlled, authorised and benign**; the value is the
  measured detection behaviour, not the activity.
- The three cases form a deliberate arc: **detect** (CASE-0001) → **break**
  (CASE-0002) → **fix, separately** (CASE-0003).
- The Phase 7 payload is retained as a **fixed regression fixture** for future
  work, and both the Phase 7 and Phase 8 payloads remain available as regression
  targets.
- No credentials or secrets appear in any case artifact by design.
