# SOC-002 Phase 6 — Detection Hardening & Correlation Depth

Phase 6 takes the single detection proven in Phase 5 (`SOC002-DET-001`, Encoded
PowerShell) and makes it usable by an analyst: it separates the routine WinRM
administration that flooded it from the events that actually need a human, adds a
second detection for process lineage, and joins the two so the analyst gets the
"what" and the "how" in one view.

**Phase 6 generated no new activity.** Every measurement in this phase is either a
replay over the preserved Phase 5 evidence or a read-only query against the
collector. The lab's WEF subscription, Sysmon configuration, AD/DNS/Kerberos,
WinRM and Windows security settings were not modified.

## Why Phase 6 exists

Phase 5 proved the chain end to end — controlled activity → telemetry → detection
→ correlation → investigation → evidence → conclusion — and then reported the
problem with the detection it had just proven:

- 39 candidates in a 60-minute window on one workstation, for **one** real event.
- 38 of the 39 were the lab operator's own WinRM administration.
- The Phase 5 report recommended exactly this phase: *detection hardening &
  correlation depth*.

Detection hit volume is not the disease; **unexplained** hit volume is. Phase 6's
goal is therefore not "fewer alerts" but "every remaining alert arrives with a
reason, a payload and a lineage attached".

## What changed from Phase 5

| | Phase 5 | Phase 6 |
|---|---|---|
| Detection file | `phase5/detections/detect_encoded_powershell.ps1` (preserved, untouched) | `phase6/detections/detect_encoded_powershell_v2.ps1` |
| Trigger | Sysmon Ev1 `powershell/pwsh.exe` + encoded switch | **identical** — coverage does not silently change |
| Output | every candidate listed as "INVESTIGATION REQUIRED" | candidates **classified** into three tiers, with the reason for each |
| Baseline | none (the analyst separated the 38 by hand) | `BASE-01`, one narrow, evidence-derived condition |
| Payload | decoded for display | decoded **and screened** (`ESC-01..08`); any hit overrides the baseline |
| Lineage | assembled by hand from three logs | resolved automatically from surviving process-create events |
| Second detection | none | `SOC002-DET-002` — PowerShell delivered through a WinRM host (context only) |
| Correlation | manual timeline in a text file | `SOC002-CORR-001`, joins DET-001 and DET-002 per process |
| Case material | investigation notes | `cases/SOC002-CASE-0001/` (structured case + JSON) |

The one thing that did **not** change is the trigger. A hardening phase that
quietly narrows the trigger would improve its own numbers and lose coverage.

## Why the original detection was noisy

Measured, from `phase5/evidence/t6_detection_broad60_dc1.txt`:

- Immediate parent of 38 of 39 alerts = `cmd.exe` running the WinRS wrapper
  `cmd.exe /C powershell -encodedcommand <base64>`.
- Immediate parent of 1 of 39 = `powershell.exe` (the nested operator runner —
  the controlled test).
- 39 of 39 used the same account, the same host and the same Microsoft binary hash.

The lab is operated over WinRM, and the WinRS client delivers **every** remote
command as an encoded PowerShell one-liner. So each administrative call satisfies
the indicator by construction. The noise was structural: one administrator
produces alert-per-command volume.

The important corollary: the one event worth looking at did **not** have that
shape. Any tuning that treated "parent is cmd.exe" as benign would have hidden the
only real candidate in the set.

## What tuning was performed

One narrow baseline, one fail-safe screen, one strength gate. Full detail and the
list of *refused* tunings are in `evidence/TUNING_RATIONALE.txt`.

**`BASE-01` — the narrow WinRS transport baseline.** Matched only when the parent
process image leaf is exactly `cmd.exe` **and** that parent's command line matches
the WinRS wrapper:

```
^\s*"?[^"]*cmd\.exe"?\s+/c\s+("?[^\s"]*powershell(?:\.exe)?"?\s+)?-(e|en|enc|encodedcommand)(\s|$)
```

`cmd.exe /C <anything else>` is **not** baselined. This is the exact string the
38 benign alerts carry and the controlled event does not.

**`ESC-01..08` — the payload screen.** The decoded payload of every
baseline-matched event is scanned for high-risk constructs: reflection/AMSI,
download/execute stagers, a second decode layer, execution-policy/AV tampering or
hidden windows, persistence primitives, credential-access tooling, account or
directory modification, and nested encoded commands. Any hit **overrides** the
baseline and clears the event back to `INVESTIGATION`. The baseline is never blind
to a payload whose meaning it can see.

**Lineage gate on the baseline's strength.** The baseline only reaches
`BASELINE-TRANSPORT-CONFIRMED` (INFO) when the ancestry is actually resolved to a
WinRM host (`winrshost.exe` / `wsmprovhost.exe`). Otherwise it drops to
`BASELINE-TRANSPORT-PATTERN` (LOW), the gap is printed in the record, and the
event is still emitted and still fed to correlation. An unexplainable event is a
lead, not a suppression.

## What was intentionally NOT suppressed

- No general `powershell.exe` rule — measured output prints `0` for it in every run.
- No general `-EncodedCommand` rule — likewise `0`.
- The controlled event (Sysmon RecId 3535) stays `INVESTIGATION`: its parent is
  `powershell.exe`, so it never matches the baseline.
- The 2 events whose payload contains a second base64 decode (ESC-03, RecIds 2975
  and 3045) stay `INVESTIGATION`. They are lab Sysmon-config work, but
  base64-in-base64 is precisely the shape real stagers use.
- Nothing is suppressed by host, user, account, LogonId, binary hash, integrity
  level, or time of day. Each of those was considered and refused with a reason
  (see `evidence/TUNING_RATIONALE.txt`, section 4) — notably, all 39 alerts share
  the same user, the same host and the same hash, so tuning on any of them would
  have suppressed the controlled event too.
- Baseline events are still emitted (one line each, with the reason) unless the
  operator explicitly passes `-HideBaseline`.

## How correlation works

`SOC002-CORR-001` (`detections/correlate_det001_det002.ps1`) joins the two
detections per process, on the identity fields that actually survive WEF:
`Computer` + `ProcessGuid` where available, otherwise `Computer` + PID + time.

```
single encoded-PowerShell signal   (DET-001: what ran, decoded)
          +                             +
process lineage / delivery context (DET-002: how it was created)
          =                             =
one record with both readings, a combined reading, and the gaps stated
```

A joined record means "the analyst gets both views at once". It does **not** mean
compromise, and it does not mean benign: the correlation output says so on every
record —

> CORRELATION IS CONTEXT, NOT A VERDICT. Det-001 + Det-002 agreeing does not make
> this a compromise; it means the analyst gets the "what" and the "how" in one view.

When the lineage is missing, correlation *says so* and marks the missing hop as an
investigative gap rather than inventing a chain. A gap is treated as **more**
suspicious than a resolved path, never less.

## Measured results

Two measurements were taken, because they answer different questions.

**Replay over the preserved Phase 5 evidence** (the apples-to-apples comparison
with the Phase 5 baseline of 39/38):

| Metric | Phase 5 | Phase 6 (replay) |
|---|---|---|
| Candidate alerts | 39 | 39 |
| Retained investigation candidates | 39 (all) | **1** (RecId 3535) |
| Auto-classified baseline transport | 0 (manual) | 38 |
| — ancestry-confirmed (INFO) | n/a | 5 |
| — pattern only, lineage not in retained evidence (LOW) | n/a | 33 |
| Re-opened by the payload screen | n/a | 0 (payload text was truncated in the preserved output) |
| Suppressed by a general `powershell` rule | 0 | 0 |
| Suppressed by a general `-EncodedCommand` rule | 0 | 0 |
| DET-002 records | n/a | 6 (5 match the observed `LIN-01` shape) |
| CORR-001 records | n/a | 39 (6 joined, 33 gap) |

**Live run on the collector over the same window** (42 candidates, because three
extra Sysmon Event 1 records created at 01:05:05–01:05:50 — after Phase 5's query
ran — are now visible):

| Metric | Phase 5 | Phase 6 (live) |
|---|---|---|
| Candidate alerts | 39 | 42 |
| Retained investigation candidates | 39 (all) | **3** (the controlled event + 2 ESC-03 re-opens) |
| Auto-classified baseline transport | 0 (manual) | 39 (all ancestry-confirmed) |
| Re-opened by the payload screen | n/a | 2 |
| DET-002 lineage records | n/a | 42 (41 match `LIN-01`) |
| CORR-001 records | n/a | 42 joined, 0 gaps |

**Self-observation check (last 50 minutes):** 20 candidates, 19 baseline, 1
retained (the same controlled event) — i.e. Phase 6's own DC1 work added no new
WS001 encoded-PowerShell telemetry that the detection could not explain.

### The false-positive statement, stated precisely

- **Detection hits did not fall.** 39 encoded-PowerShell events are still detected;
  the trigger is unchanged. Nothing was made to disappear.
- **Triage volume fell** from 39 manual reviews to 1 (replay) / 3 (live).
- **What this is:** the Phase 6 baseline reproduces, automatically and with a
  recorded reason per event, the exact split the Phase 5 analyst made by hand
  (38 benign / 1 controlled). It is a **triage-efficiency** change.
- **What this is not:** a demonstrated reduction in false positives *in general*.
  The 38 were already known-benign, the lab holds no adversary telemetry, and no
  new activity was generated to test the other direction. `NOT VERIFIED`.
- The 2 ESC-03 re-opens are a deliberate precision/recall trade: two benign
  events are kept in the queue so the same shape is never invisible.

## Remaining limitations

1. **The trigger is unchanged, so the known blind spots remain.** Encoded payloads
   that never use the CLI switch (`-Command` with
   `[Convert]::FromBase64String(...)`) and non-`powershell`/`pwsh` hosts are still
   not seen. This is a deliberate scope limit, not an oversight.
2. **`BASE-01` is mimicable.** An adversary already able to execute remotely could
   deliver a payload as `cmd.exe /C powershell -encodedcommand <b64>` and pass the
   baseline. `ESC-01..08` is a keyword screen, not a proof. Documented in
   `evidence/TUNING_RATIONALE.txt` §5.1.
3. **The baseline is single-operator, single-host, one-hour.** It is
   evidence-based **for this lab** and must not be presented as a production
   baseline. No production telemetry or production SOC experience is claimed.
4. **There is a real coverage hole in the primary source.** The Sysmon Event 1
   stream at the collector has a 2012-second hole inside the Phase 5 window
   (00:07:38–00:41:10 local) while Security 4688 kept recording. Root cause is
   `NOT VERIFIED` (local log rollover vs collector drop); establishing it would
   require changing logging configuration, which Phase 6 must not do. Mitigated
   only by `-Include4688Fallback`, which has weaker lineage (no `ProcessGuid`).
5. **PowerShell 4104 is not dependable.** 4104 was absent for a minority of
   candidates (8 by Phase 5's own corroboration step; 6 by a strict executing-PID
   match), so the decoded "what it did" view is not guaranteed.
6. **Correlation depth is limited by surviving events.** In the replay, 33 of 39
   chains stopped at the immediate parent because Phase 5 preserved only excerpts.
   Live, all 39 resolved — which shows the replay's gaps are an evidence artefact,
   but it also shows how quickly lineage depth degrades when events are missing.
7. **PID-based joins are unsafe on their own.** Security 4688 carries no
   `ParentProcessGuid`, and the Phase 5 evidence contains a PID that is
   `winrshost.exe` early and `cmd.exe` later. Phase 6 refuses a PID candidate whose
   image name does not match the image the child recorded for its parent.
8. **No adversary telemetry exists.** Everything measured here is a re-decision
   over known-benign data. Detection of a real intrusion is `NOT VERIFIED`.

## Files

```
phase6/
  README.md                          this file
  detections/
    lib_soc002_v2.ps1                shared decision library (cross-platform: no Get-WinEvent)
    lib_soc002_windows.ps1           Windows/WEF adapter (Get-WinEvent readers)
    detect_encoded_powershell_v2.ps1 SOC002-DET-001 v2  (live)
    detect_powershell_lineage.ps1    SOC002-DET-002     (live, context only)
    correlate_det001_det002.ps1      SOC002-CORR-001    (live)
  analysis/
    lib_evidence_phase5.ps1          read-only parsers for the preserved Phase 5 evidence
    replay_phase5_evidence.ps1       offline replay of the real library over Phase 5 evidence
    baseline_false_positives.ps1     Tasks 1–2: why the noise happened, field by field
    compare_phase5_phase6.ps1        Task 6: joins Phase 5 alerts to Phase 6 decisions
    failure_modes.ps1                Task 7: offline failure-mode report
    probe_failure_modes_dc1.ps1      Task 7: READ-ONLY live probe (run on DC1)
    build_manifest.ps1               Task 10: SHA256 manifest + Phase 5 preservation check
  tools/
    dc1_ops.py                       read-only WinRM helper (push/run/ps/rm), creds from env
  cases/
    README.md                        case-management conventions
    SOC002-CASE-0001/CASE.md         the Phase 5 controlled detection as a case
    SOC002-CASE-0001/case.json       the same case, structured
  evidence/                          all Phase 6 outputs (see below)
```

Key evidence files: `t2_false_positive_baseline.txt` (why the noise happened),
`t6_phase6_det001_v2_{live_dc1,replay}.txt`, `t6_phase6_det002_lineage_*.txt`,
`t6_phase6_correlation_*.txt`, `t6_comparison_phase5_vs_phase6.txt`,
`t7_failure_modes.txt`, `t7_fm_live_probe_dc1.txt`, `TUNING_RATIONALE.txt`,
`SHA256_MANIFEST.txt`.

## Reproducing the measurements

```bash
# offline replay over the preserved Phase 5 evidence (no lab access needed)
pwsh -File ~/soc-lab/phase6/analysis/replay_phase5_evidence.ps1 -Section all
pwsh -File ~/soc-lab/phase6/analysis/failure_modes.ps1
pwsh -File ~/soc-lab/phase6/analysis/build_manifest.ps1

# live, read-only, against the collector (creds from WINRM_USER / WINRM_PASS)
python3 ~/soc-lab/phase6/tools/dc1_ops.py run 'C:\Windows\Temp\soc002-phase6\detect_encoded_powershell_v2.ps1'
```

The live detector on the collector and the offline replay call the **same**
functions in `lib_soc002_v2.ps1`; only the input adapter differs. That is what
makes the replay a measurement of the real logic rather than a second
implementation of it.

## Next recommended phase

**Phase 7 — Adversary simulation & true-positive validation (with baseline drift
monitoring).** Phase 6 measured a re-decision over known-benign data; the open
question is whether these detections fire correctly on activity that is *supposed*
to be suspicious, and whether the lab can tell deliberate-test activity from a
real intrusion. Phase 7 should (a) execute a documented, authorised adversary
simulation that stays inside the existing telemetry — including at least one
encoded payload that avoids the CLI switch, to test the known blind spot,
(b) verify `SOC002-DET-001 v2`, `SOC002-DET-002` and `SOC002-CORR-001` all fire
and classify it correctly, and (c) add baseline-drift monitoring so a change in
the observed WinRM shape is noticed rather than silently absorbed by `BASE-01`.

Phase 7 was **not** started. This phase stops here.
