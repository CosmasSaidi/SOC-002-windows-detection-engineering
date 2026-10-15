# SOC-002 Phase 8 — DET-003: PowerShell Base64 Reconstruction / Decode Behaviour

**Case** `SOC002-CASE-0003` · **Host** `SOC002-WS001.soc002.local` ·
**Collector** `SOC002-DC1` · **Result** `DET-003 IDENTIFIED the Phase 7 blind spot` ·
**DET-001 v2 modified** no (byte-identical) · **Phase 5/6/7 modified** no

---

## 1. Executive summary

Phase 7 (`SOC002-CASE-0002`) measured a documented gap: `SOC002-DET-001 v2`
triggers on the **encoded-command CLI switch**, so PowerShell run as
`-Command "[Convert]::FromBase64String(...)"` — visible in Security 4688, Sysmon
Event 1, PowerShell 4104 and DC1 `ForwardedEvents` — never becomes a DET-001
candidate. Phase 8 builds a **separate, complementary** detection for exactly
that behaviour: `SOC002-DET-003`, PowerShell Base64 Reconstruction / Decode
Behaviour.

| Question | Answer |
|---|---|
| Is DET-003 implemented separately from DET-001? | **Yes** — its own library + detector; DET-001 untouched |
| Is DET-001 v2 unchanged? | **Yes** — `c9b73426…d16c` before and after |
| Was the Phase 7 blind spot replay-tested? | **Yes** — all four preserved views |
| Did DET-003 identify the previously-missed payload? | **Yes** — `REC-01 [Convert]::FromBase64String` |
| Does it alert on the word "Base64"? | **No** — only on a reconstruction *call* |
| Was correlation tested without forcing a verdict? | **Yes** — CORR-002 links, gaps printed |
| Was a live validation performed? | **Yes** — one harmless run, detected |
| Were prior phases preserved? | **Yes** — 88/34/51 files re-hashed, 0 changed |

Nothing was changed to influence the result, and no verdict of maliciousness is
claimed anywhere: base64 reconstruction is a normal operation, and DET-003 says
"reconstruction observed, here is the context".

## 2. Phase 7 blind spot

Phase 7 performed one controlled benign execution and returned
`OUTCOME B — blind spot confirmed`:

- **DET-001 v2** = MISS (the payload process carried no `-EncodedCommand`/`-enc`/`-e`/`-en`).
- **DET-002** = CONTEXT (the payload was recorded as lineage context, `Encoded switch = absent`).
- **CORR-001** = no correlation (it consumes DET-001 candidates, so it inherits the gap).
- The activity was nevertheless fully visible in 4688, Sysmon Event 1, 4104 and DC1 `ForwardedEvents`.

The Phase 7 payload (PID 1428, marker `SOC002-PHASE7-BLINDSPOT-TEST`) is the
primary validation target for Phase 8.

## 3. Detection objective

Add a second, independently auditable detection whose trigger is the Base64
**reconstruction call** rather than the CLI switch, so that switch-free
reconstruction becomes visible — without duplicating DET-001's coverage claim and
without turning "Base64" into a keyword rule.

## 4. DET-003 design

Full rationale in `evidence/DET003_DESIGN.md`. Key points:

- **Sources:** Sysmon Event 1 `CommandLine`, Security 4688 `CommandLine`, PowerShell 4104 `ScriptBlockText` — locally and at DC1 `ForwardedEvents`.
- **Trigger:** a `.NET` reconstruction **call** — `REC-01 … REC-05` (`[Convert]::FromBase64String`, `[System.Convert]::FromBase64String`, `FromBase64String(`, `FromBase64CharArray(`, `[Convert]::FromBase64CharArray`).
- **Explicit non-trigger:** the literal word `Base64`; and a call that appears **only inside a comment** (recorded as a visible `COMMENT-MENTION`).
- **Context (never a trigger alone):** `CTX-EXEC-ADJACENT`, `CTX-STRING-ROUNDTRIP`, `CTX-REMOTE-RETRIEVAL`, `CTX-PLUMBING`.
- **Severity:** `LOW` (RECONSTRUCTION-OBSERVED) or `MEDIUM` (RECONSTRUCTION-WITH-EXECUTION-ADJACENT).
- **Separation:** DET-001 v2 and DET-002 are not touched. The Phase 6 library is dot-sourced **read-only** for process-index/lineage/DET-002 context, and its hash is printed in the output.
- **Safety:** DET-003 reads text only. It never executes, invokes or decodes-and-runs anything.

## 5. Detection logic

One pipeline (`Invoke-Soc002P8Assessment`) is shared by the live detector and
the offline replay harness, so the replay measures the real logic. It:

1. scans each record's text for the reconstruction call (comment-aware);
2. classifies severity from the context flags;
3. resolves the process (Sysmon/4688 record, or by PID for a 4104 block);
4. derives the DET-002 lineage context when a WinRM-rooted chain exists;
5. emits a structured record + a CORR-002 correlation record.

Structured DET-003 output fields: detection ID, timestamp, host, user, PID,
parent process, command line, LogonId, ProcessGuid, ScriptBlockId, matched
indicator, source event, severity, class, context flags and investigation reason.

## 6. Replay of Phase 7 evidence

The preserved, unmodified `phase7/evidence/raw/` files were parsed offline
(EventData XML as text — nothing executed). The **real** DET-003 trigger and the
**real, unmodified** DET-001 v2 trigger were run over the same records.

| Replay (preserved Phase 7 view) | events | records examined | DET-003 candidates | Phase 7 payload hit |
|---|---|---|---|---|
| controlled window, WS001 local | 17 | 8 | 3 | **yes (REC-01)** |
| controlled window, DC1 ForwardedEvents | 17 | 8 | 3 | **yes (REC-01)** |
| session window, WS001 local | 342 | 112 | 6 | **yes (REC-01)** |
| session window, DC1 ForwardedEvents | 340 | 112 | 6 | **yes (REC-01)** |

`OBSERVED` — the exact previously-missed payload (PID 1428) was flagged by
DET-003 in **4 of 4** preserved views. The blind-spot contrast held in every
view: the payload was **DET-001 miss / DET-003 hit**, and the WinRS transport
(PID 2936, `-encodedcommand`) was **DET-001 hit / DET-003 miss**.

## 7. Benign comparison testing

`evidence/t05_benign_comparison.txt` runs DET-003 over a small set of literally
non-executed strings and compares it with a naive `match "Base64"` rule.

| case | description | keyword rule | DET-003 |
|---|---|---|---|
| B01 | plain PowerShell, no base64 | clear | clear |
| B02 | word "Base64" in commentary | **FIRE** | clear |
| B03 | explicit `FromBase64String` reconstruction | FIRE | FIRE (LOW) |
| B04 | the real Phase 7 blind-spot command line | FIRE | FIRE (LOW) |
| B05 | decode call only inside a comment | **FIRE** | clear (suppressed) |
| B06 | decode + `Invoke-Expression` adjacency | FIRE | FIRE (MEDIUM) |
| B07 | operator WinRM file-transfer plumbing | FIRE | FIRE (LOW, CTX-PLUMBING) |

`OBSERVED` — DET-003 is more useful than a keyword rule: it fires on real
reconstruction and stays quiet on the word alone and on comment-only mentions.
These are **benign test cases**, not a measured false-positive rate.

## 8. Live validation

One controlled, benign execution on `SOC002-WS001` over the existing authorised
WinRM administrator channel (`SOC002\Administrator`), at **23:35:06–08Z**
(`evidence/t07_live_validation.txt`):

- a plainly-started `powershell.exe` reconstructed the marker
  **`SOC002-PHASE8-DET003-TEST`** with `[Convert]::FromBase64String(...)`;
- the payload child command line carries **no** encoded-command switch;
- marker printed, exit code 0;
- no network connection, no persistence, no configuration change, no permanent
  file (staging temp removed, `TMP_REMOVED=True`);
- nothing decoded was executed — the content is plain text and is only printed.

`OBSERVED` — DET-003 identified the live payload in Security 4688, Sysmon Event 1
and PowerShell 4104 (details in §9/§10). The WinRS transport that delivered it
(`powershell.exe` PID 5468, `-encodedcommand`) remained a **DET-001** candidate
and a **DET-003 non-trigger** — the same complementary contrast seen in Phase 7.

Honest note: the operator's own staging script block for this run also contains
the payload text as a literal, so it appears as a DET-003 candidate labelled
`CTX-PLUMBING` (4104 RecId 77434). It is operator plumbing, not the activity
under test, and is reported rather than hidden.

## 9. Local telemetry

`OBSERVED` — controlled window `23:34:45Z .. 23:35:40Z`, **50 events** on
`SOC002-WS001` (`evidence/t08_local_telemetry_ws001.txt`): Security 4688 = 13,
Sysmon Event 1 = 17, PowerShell 4104 = 12, Sysmon Event 3 = 8. DET-003 produced
**4 candidates**, all LOW:

| Source | RecordId | PID | Key fields |
|---|---|---|---|
| Security 4688 | **16123** | 1268 | Creator 5468, `SOC002\Administrator`, `LogonId 0x695d72` — payload |
| Sysmon Event 1 | **4600** | 1268 | `ProcessGuid {edcef402-11ab-6ad0-5706-000000000700}`, parent `powershell.exe`(5468) — payload |
| PowerShell 4104 | **77450** | 1268 | `ScriptBlockId 50aa4a2f-00ff-4f0f-b0d4-2f5f2543ccae` — payload |
| PowerShell 4104 | 77434 | 1996 | `ScriptBlockId a8662866-d48c-4970-98ef-e10ec1eb1c40` — operator staging, `CTX-PLUMBING` |

The transport fully qualified chain was
`winrshost.exe`(4008) → `cmd.exe`(5652) → `powershell.exe`(5468) → `powershell.exe`(1268).
The payload initiated no network connection (no Sysmon Event 3 for PID 1268).

## 10. Central telemetry

`OBSERVED` — the same window at `SOC002-DC1` `ForwardedEvents` captured **57
events** (`evidence/t09_central_telemetry_dc1.txt`), all attributed to
`SOC002-WS001`. DET-003 produced **4 candidates** with **identical RecordIDs**
(4688 16123, Sysmon1 4600, 4104 77434, 4104 77450), confirming the WEF path.

`OBSERVED` — running the **live** detector on DC1 over a 60-minute window
(`evidence/t09c_det003_live_dc1.txt`) examined 303 PowerShell records and produced
13 candidates, all LOW: 3 for the Phase 8 payload, 3 for the Phase 7 payload
(still inside the hour — the live detector independently rediscovered the Phase 7
blind spot on the collector), 1 for the Phase 8 staging transport, and 6 for
operator collection/staging script blocks (`CTX-PLUMBING`).

## 11. DET-001 comparison

`evidence/t14_det001_vs_det003.txt` runs both real triggers over the same command
lines. **DET-001 v2 and DET-003 are disjoint on the observed cases; neither is a
superset of the other.**

| Case | DET-001 v2 | DET-003 |
|---|---|---|
| Phase 5 control `-EncodedCommand` | TRIGGER | miss |
| Phase 7 blind spot `-Command` + decode | **miss** | **TRIGGER (REC-01, LOW)** |
| Phase 8 live `-Command` + decode | **miss** | **TRIGGER (REC-01, LOW)** |
| benign plain / word-only / comment-only | miss | miss |
| decode + `Invoke-Expression` | miss | TRIGGER (MEDIUM) |

## 12. DET-002 comparison

DET-002 is **not** a text trigger: it is CONTEXT derived from the process chain
(delivery through `winrshost.exe`/`wsmprovhost.exe`). It answers "how was this
process created?", DET-003 answers "did its text contain a decode call?", and
DET-001 answers "did its command line carry an encoded switch?". No one of them
decides another, and none asserts maliciousness. In the live run DET-002
recorded the WinRM-rooted lineage for the payload and the transport alike — as
expected for every remote administration call in this lab.

## 13. Correlation

`SOC002-CORR-002` ties a DET-003 record to the matching Sysmon Event 1, the
matching Security 4688, the PowerShell 4104 block, and the DET-002 lineage,
using PID with a ±120 s tolerance and preferring `ProcessGuid` agreement
(`evidence/t10_correlation.txt`).

- `OBSERVED` — for the live payload and the Phase 7 payload, all four links
  resolved, including the full chain to `winrshost.exe`.
- `OBSERVED` — **gaps are printed, never forced**: a 4104-sourced record can
  report "no Sysmon Event 1 for this PID/window" or "no WinRM-rooted lineage
  resolved", and the reading is explicitly described as *weaker*, not stronger.
- `OBSERVED` — PID reuse is a real hazard (the session window reuses PID 1428);
  the correlation is time/guid-constrained rather than trusting the PID alone.

## 14. Investigation

A DET-003 record raises the question "who ran a base64 reconstruction, where did
it come from, and did the reconstructed data feed an execution or a network
retrieval?" — not "is this malicious?". For this case: the operator is the
authorised lab admin, the delivery path is the sanctioned WinRM channel, the
decoded content is a harmless marker, and nothing decoded was executed.
Classified **CONTROLLED TEST ACTIVITY / AUTHORISED BENIGN** (§18).

## 15. False-positive considerations

`evidence/t12_false_positive_considerations.txt`. The two reproduced, documented
sources are (a) the SOC team's own WinRM file transfer, which uses
`[Convert]::FromBase64String` and therefore appears as a DET-003 candidate
(labelled `CTX-PLUMBING`), and (b) legitimate scripts decoding configuration,
certificates or blobs. In the live 60-minute DC1 run, 7 of 13 candidates were
operator plumbing and 6 were the two controlled payloads. This is **observed
behaviour on a tiny sample**; it is explicitly **not** a false-positive rate.

## 16. Limitations

`evidence/t13_limitations.txt`. Load-bearing: the trigger is **text-only**
(fragment-assembled method names, custom decoders, `certutil -decode`, compiled
or non-PowerShell hosts are NOT covered); **decode-and-execute is inferred from
text proximity, not observed**; here-strings are not comment-stripped; PID reuse
is handled only within ±120 s; coverage depends on the Phase 4 enablers; operator
plumbing inflates volume; and **no rate, no generalisation and no production
validation** is claimed.

## 17. Evidence integrity

- **DET-001 v2 is byte-identical** before and after Phase 8 (`c9b73426…d16c`);
  all six detection source files match their pre-change hashes.
- **Phase 5/6/7 trees:** `phase5 88 / phase6 34 / phase7 51` files re-hashed —
  **changed 0, missing 0, added 0**.
- Replay inputs are the preserved `phase7/evidence/raw/` files (hashes in
  `evidence/replay_inputs.txt`).
- Lab temp dirs (`…\soc002-phase8`, `…\soc002-phase8-det003`) removed from both
  hosts; a read-only check confirms they do not exist (`evidence/t15_integrity.txt`).
- SHA256 manifest for the whole Phase 8 tree: `phase8/SHA256_MANIFEST.txt` (49 files).
- No credentials or secrets appear in any Phase 8 artefact.

## 18. SOC002-CASE-0003

`cases/SOC002-CASE-0003/` (`CASE.md` + `case.json`). Documents the detection
objective, the Phase 7 blind spot, the DET-003 design, the observed telemetry,
the detection result, the correlation result, the investigation, the
classification (**CONTROLLED TEST ACTIVITY / AUTHORISED BENIGN**), the
limitations and the recommended next step.

## 19. Conclusion

`SOC002-DET-003` is implemented **separately** from DET-001 v2 and **identifies**
the PowerShell Base64 reconstruction behaviour that DET-001 v2 missed, in the
preserved Phase 7 evidence (4 of 4 views) and in one controlled live run. It does
**not** fire on the word "Base64", it **suppresses** comment-only mentions, and
its severity model distinguishes a bare decode from a decode sitting next to an
execution/retrieval primitive. Correlation connects the signal to Sysmon Event 1,
Security 4688, PowerShell 4104 and the DET-002 lineage context without forcing a
verdict, and prints its gaps. DET-001 v2 is unchanged, Phase 5/6/7 evidence is
untouched, and every limitation is documented rather than hidden.

**This is a controlled lab validation, not production validation.** The
controlled activity is benign, and the finding of value is the detection
behaviour, not the activity.

## 20. Recommended next phase

1. **Decide CORR-001's scope.** Now that DET-003 supplies a switch-free signal,
   decide explicitly whether `CORR-001` should also correlate on DET-002 lineage
   alone (Phase 7 §18 item 2), or stay anchored to DET-001.
2. **Handle operator plumbing.** Consider a separately auditable enrichment for
   `CTX-PLUMBING` staging traffic instead of leaving it as raw DET-003 volume.
3. **Extend coverage carefully.** Test additional reconstruction styles
   (fragment-assembled names, compressed/hex blobs, `certutil -decode`, decode
   followed by execution) as new, independently auditable indicators — never by
   weakening DET-001 or broadening the `BASE-01` baseline.
4. **Re-run the controlled tests unchanged** after any future detection change,
   so the before/after comparison stays honest — including this Phase 8 payload
   and the Phase 7 payload as fixed regression targets.

Phase 8 stops here. No Phase 9 work was begun.
