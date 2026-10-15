# SOC-002 — Detection Coverage and Limitations

This is the explicit coverage map for the SOC-002 detections. Every row states
what is covered, which telemetry it needs, which detector covers it, how it was
validated, and where it fails. Nothing here is a rate or a percentage: the lab is
too small to measure detection or false-positive rates, and none is claimed.

## Coverage table

| Covered behaviour | Telemetry source | Detector | Validation | Limitations |
|---|---|---|---|---|
| PowerShell process created with an encoded-command switch (`-EncodedCommand` / `-enc` / `-en` / `-e`) | Sysmon Event ID 1 (`Image`, `CommandLine`) | `SOC002-DET-001` / `v2` | Phase 5 controlled execution (1 corroborated alert); Phase 6 replay + live re-assessment; Phase 9/10 semantic spot-check | Triage signal only; command-line-shape based; image match unanchored in the PowerShell implementation; silent if Sysmon 1 or the command line is missing |
| Same encoded-command event corroborated by script-block logging | PowerShell Event ID 4104 (`ScriptBlockText`, `ScriptBlockId`, executing PID) | `SOC002-DET-001` (corroboration step) | Phase 5 (RecId 72974, ExecPID 1500 == Sysmon PID 1500) | Not mandatory; 4104 absent for a minority (33/39 bound, 6 unbound in the Phase 6 probe); fragmentation and noise; may not carry the reconstructed text |
| Same encoded-command event seen centrally | WEF `ForwardedEvents` (Security 4688 fallback) | `SOC002-DET-001` (`-Include4688Fallback`) | Phase 5 central correlation (identical RecordIDs); Phase 6 failure-mode probe | Weaker lineage (no `ParentProcessGuid`); must not be treated as equal to Sysmon |
| Delivery of PowerShell through a WinRM host process | Sysmon Event 1 / Security 4688 ancestry (`winrshost.exe` / `wsmprovhost.exe`) | `SOC002-DET-002` | Phase 6 (39/39 live lineages resolved); Phase 7 baseline-drift check (22/22 wrappers) | **Context only**, high volume (essentially every administrative call); no verdict |
| One encoded execution joined to its delivery lineage | DET-001 v2 + DET-002 | `SOC002-CORR-001` | Phase 6 live + replay (`CORR-SOC002-WS001-1500-20261014T215948Z`) | Inherits DET-001's trigger blind spot by construction; prints explanation gaps, never forces them |
| In-process Base64 reconstruction via a `.NET` call (`REC-01..05`) | Sysmon Event 1 `CommandLine`, Security 4688 `CommandLine`, PowerShell 4104 `ScriptBlockText` | `SOC002-DET-003` | Phase 8 replay of the Phase 7 evidence (4/4 views) + one controlled live run | Text-only; decode-and-execute is *inferred* from proximity; here-strings not comment-stripped; operator plumbing inflates volume |
| DET-003 correlated to process creation and lineage | DET-003 + Sysmon 1 + Security 4688 + PowerShell 4104 + DET-002 lineage | `SOC002-CORR-002` | Phase 8 live run + replay | PID joins constrained to ±120 s; gaps printed, never hidden |
| Comment-only Base64 mention (non-trigger by design) | DET-003 text sources | `SOC002-DET-003` (suppression) | Phase 8 benign comparison suite (B05 = clear) | Here-strings are a documented exception |
| The literal word "Base64" (non-trigger by design) | DET-003 text sources | `SOC002-DET-003` (non-trigger) | Phase 8 benign comparison suite (B02 = clear) | — |

Validation statuses are single-run, single-host measurements. Where a behaviour
was validated only in a replay of preserved evidence, that is stated; where it was
validated live, that is stated.

## Known blind spots

These are **known, documented gaps**. The first was demonstrated by a real
controlled test (Phase 7), not assumed.

1. **`-Command` + `[Convert]::FromBase64String` (switch-free reconstruction).**
   PowerShell that rebuilds a payload in-process carries no encoded-command
   switch, so `SOC002-DET-001 v2` never creates a candidate for it. Phase 7
   (`SOC002-CASE-0002`) confirmed this with a controlled execution; Phase 8 built
   `SOC002-DET-003` to cover the tested form. Other reconstruction styles are
   *not verified* — the blind spot is not claimed to be limited to the one form
   tested.
2. **Non-PowerShell hosts.** Both detections are scoped to PowerShell. A
   reconstruction or encoded payload performed by another interpreter, a compiled
   binary, or a script host other than `powershell.exe` / `pwsh.exe` is not
   covered.
3. **Missing Sysmon.** DET-001's primary signal is Sysmon Event ID 1. If Sysmon is
   not installed or not forwarding, the primary signal disappears; only the
   weaker Security 4688 fallback (DET-001) remains, and DET-003 loses one of its
   three text sources. (DC1 itself has no Sysmon, so central Sysmon visibility is
   entirely dependent on WS001.)
4. **Missing PowerShell 4104.** If Script Block Logging is off or the log is not
   forwarded, the "what did it actually do" view is lost. DET-001 still fires on
   the Sysmon signal (corroboration is non-mandatory), and DET-003 loses a text
   source. Measured: 33 of 39 candidates had a binding 4104 block; 6 did not.
5. **Missing or empty command line.** If 4688 command-line auditing is off, or a
   field is empty, DET-001 cannot evaluate its trigger at all — and the failure is
   **silent** (no alert, no gap marker). Measured in the lab: 0 of 52 `powershell.exe`
   4688 records and 0 of 39 Sysmon candidates had an empty command line, i.e. only
   the "everything present" case was observed. Truncated command lines also cost
   real escalations: with only a preserved prefix, the payload screen escalated
   0 of 38 baselined events, versus 2 of 38 with the full text.
6. **Baseline mimicry.** `BASE-01` can be met by any process that looks like the
   WinRS wrapper (`cmd.exe /C powershell -encodedcommand <b64>`). An adversary who
   can already execute remotely could deliver a payload in that shape. The
   `ESC-01..08` keyword screen is the compensating control, and it is a keyword
   screen, not a proof.
7. **Bounded lab retention.** WS001's Security and Sysmon logs and DC1's
   `ForwardedEvents` are all bounded. Events can age out; a long window can
   silently miss events. Absence within a window is "not observed", not
   "disproved".
8. **No production-scale FP/FN measurement.** The lab has three controlled cases
   and a handful of benign test cases. It measures *observed* behaviour on a tiny
   sample — 39 alerts for one event, 13 DET-003 candidates in one hour — and
   explicitly **does not** establish a false-positive rate, a false-negative rate,
   or any performance figure. There is no adversary telemetry in the lab.

Additional measured infrastructure limitation: a **2012-second hole** in the
collector's Sysmon Event 1 stream (00:07:38 → 00:41:10 local) while Security 4688
kept recording. Root cause `NOT VERIFIED`; mitigated only by the weaker 4688
fallback.

## What Phase 7 actually demonstrated

Phase 7 was a **negative test held against real evidence**, and it succeeded in
its purpose by *failing* the detection:

- `SOC002-DET-001 v2` did **not** detect the controlled activity — the payload
  process never became a candidate.
- `SOC002-DET-002` recorded the payload only as lineage context (`Encoded switch
  = absent`).
- `SOC002-CORR-001` correlated nothing, because it consumes DET-001 candidates.

The activity was fully visible in Security 4688, Sysmon Event 1, PowerShell 4104
and DC1 `ForwardedEvents` throughout; nothing was changed to influence the result.
The lab reports this as a **confirmed, controlled blind spot**. It does not
pretend detection coverage was complete, and it does not paper over the gap with
tuning. The gap was then addressed the honest way — a **separate** detection
(`SOC002-DET-003`), with the existing detection left untouched.

## Non-claims

- No detection here is a compromise detector or a verdict of maliciousness.
- No false-positive rate, false-negative rate, coverage percentage, or MTTD/MTTR
  figure is claimed.
- No behavior against real adversary telemetry was observed; it is `NOT VERIFIED`.
- The Sigma and KQL artifacts are static translations; no backend execution,
  deployment, or production validation was performed.
