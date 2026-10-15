# SOC-002 — Project Summary

*Windows Detection Engineering & Investigation — controlled Windows/AD security
operations lab.*

## 1. Why the project exists

Detection engineering is easy to demonstrate badly: pick a suspicious string,
show that it matches a suspicious event, and declare success. SOC-002 exists to
demonstrate the parts that make a detection *trustworthy* — proving the telemetry
works, measuring the detection's own behaviour, admitting where it fails, and
handing the result to another analyst (or another platform) without overstating
what was proven.

The project is a self-directed, controlled lab. It was built to answer a concrete
question: *can one detection be carried from raw Windows/AD telemetry all the way
to a portable, defensible artifact, with every claim bounded by preserved
evidence?*

## 2. What problem it solves

The lab solves its own problem end to end. Starting from a single benign
encoded-PowerShell execution, it:

- proves that Sysmon, Windows Security and PowerShell telemetry reach a central
  collector;
- builds a detection and measures that it produces **39 alerts in 60 minutes on
  one host for one real event** (38 of them the operator's own WinRM
  administration);
- hardens the detection *without* narrowing its trigger, then documents the
  tunings it refused;
- tests a documented limitation with a controlled execution and records the
  negative result honestly;
- builds a separate detection for the confirmed gap;
- represents the detection in Sigma and translates it to KQL;
- preserves the evidence and verifies, by hash, that nothing was rewritten.

## 3. Architecture

```
Operator (Kali, 192.168.56.1) ── WinRM 5985 ──> SOC002-WS001 (Win10, 192.168.56.102)
                                                    │  Sysmon 1/3
                                                    │  Security 4624/4625/4688
                                                    │  PowerShell 4104
                                                    ▼  WEF pull subscription
                                             SOC002-DC1 (Server 2022, 192.168.56.10)
                                                    AD DS + DNS + WEC
                                                    ForwardedEvents
```

The operator host drives the lab over the authorised WinRM management channel.
That channel is central to the project: it is legitimate, and it is also the
source of almost all the detection noise (see §7).

## 4. Major phases

| Phase | Scope | Outcome |
|---|---|---|
| 4 | Telemetry plumbing: Sysmon config, 4688 command-line auditing, Script Block Logging, WEF subscription | All sources verified flowing to `ForwardedEvents` |
| 5 | First detection: controlled encoded-PowerShell execution → telemetry → detection → correlation → investigation → evidence | `SOC002-DET-001`; one alert corroborated; 39-alert noise measured |
| 6 | Hardening, correlation, failure modes | `SOC002-DET-001 v2`, `SOC002-DET-002`, `SOC002-CORR-001`, `CASE-0001` |
| 7 | Blind-spot validation | `CASE-0002`; both blind spots confirmed |
| 8 | Complementary detection for Base64 reconstruction | `SOC002-DET-003`, `SOC002-CORR-002`, `CASE-0003` |
| 9 | Sigma representation of DET-001 | `SOC002-DET-001-encoded-powershell.yml`; 61/61 structural checks |
| 10 | KQL translation of DET-001 | Two KQL forms (portable + regex); static validation PASS |

Phases 9 and 10 are **closure** phases: they represent and translate an existing,
already-validated detection. They add no new detection logic and ran no new lab
activity.

## 5. Major detection

**`SOC002-DET-001` — Encoded PowerShell Execution Observed (Investigation
Required).**

- Primary source: Sysmon Event ID 1 (`Process Create`).
- Conditions: `Image` matches `(powershell|pwsh)\.exe` **and** `CommandLine`
  matches the token-exact encoded-command switch
  `(?i)\s-(e|en|enc|encodedcommand)(\s|$)`.
- Enrichment: read-only Base64 decode of the payload for the analyst.
- Corroboration: PowerShell 4104 from the same executing PID.
- Severity: **MEDIUM** — a triage signal that says *look at this*, never
  *malicious*.

A second detection, **`SOC002-DET-003` — PowerShell Base64 Reconstruction /
Decode Behaviour**, keys on a Base64 reconstruction *call* (`REC-01..05`:
`[Convert]::FromBase64String`, `FromBase64String(`, `FromBase64CharArray(`, …)
rather than the CLI switch.

## 6. Investigation outcomes

Three controlled cases, all closed:

- `SOC002-CASE-0001` — the Phase 5 encoded-PowerShell test. Classification:
  **CONTROLLED TEST ACTIVITY / AUTHORISED BENIGN**. The decoded payload prints a
  marker and sleeps; no network, no persistence, no escalation, no lateral
  movement.
- `SOC002-CASE-0002` — the Phase 7 blind-spot test. Outcome: **blind spot
  confirmed** (DET-001 v2 miss). Classification: controlled/authorised benign.
- `SOC002-CASE-0003` — the Phase 8 validation of `SOC002-DET-003`. DET-003
  identified the previously-missed payload. Classification: controlled/authorised
  benign; *the finding of value is the detection behaviour, not the activity*.

## 7. Tuning outcomes

Phase 6 made the detection usable **without changing its trigger**:

- `BASE-01` — baseline only when the parent image leaf is exactly `cmd.exe`
  **and** that parent's command line is the WinRS wrapper
  `cmd.exe /C powershell -encodedcommand <b64>`. `cmd.exe /C <anything else>` is
  not baselined.
- `ESC-01..08` — the decoded payload is screened; any high-risk construct
  overrides the baseline and re-opens the event.
- Lineage gating — the baseline only reaches the confirmed tier when the ancestry
  resolves to a WinRM host; otherwise it drops to a weaker labelled tier and the
  gap is printed.

Explicitly **refused**: tuning on user, logon id, source host, parent image name
alone, binary hash, integrity level, or time-of-day. All 39 alerts shared the same
user, host and Microsoft binary hash — exactly the fields an attacker most likely
shares too.

Phase 6 claims a **triage-efficiency** improvement, not a general false-positive
reduction: the hit count is unchanged at 39.

## 8. Blind spots

- **Confirmed by test (Phase 7):** `-Command` with
  `[Convert]::FromBase64String(...)` and no encoded-command switch — invisible to
  `SOC002-DET-001 v2`, `SOC002-DET-002` (context only) and `SOC002-CORR-001`
  (inherits the trigger's gap).
- **Closed for the tested form (Phase 8):** `SOC002-DET-003` detects the
  reconstruction call in the preserved Phase 7 evidence (4 of 4 views) and in one
  controlled live run.
- **Known and not tested:** fragment-assembled method names, custom decoders,
  `certutil -decode`, compressed/hex blobs, decode-then-execute, and non-
  PowerShell hosts.
- **Infrastructure blind spot:** a **2012-second hole** in the collector's Sysmon
  Event 1 stream (00:07:38–00:41:10 local) while Security 4688 kept recording.
  Root cause is `NOT VERIFIED` (local rollover vs collector-side drop).

## 9. Sigma / KQL closure

- **Sigma:** `phase9/sigma/SOC002-DET-001-encoded-powershell.yml` represents the
  primary DET-001 condition only. It preserves the telemetry source, field names,
  process scope and MEDIUM interpretation; it deliberately drops the short
  switches `-e`/`-en`/`-enc` (portable Sigma `contains` cannot express a
  token-exact short switch without matching `-ErrorAction`/`-Enabled`/
  `-Encoding`) and documents that gap instead of writing a weak wildcard.
- **KQL:** two static forms. The portable form is a one-to-one rendering of the
  Sigma rule; the regex form reproduces the original detector's token-exact
  short-switch logic. Both assume a Microsoft Sentinel `Event` table carrying
  Sysmon Event 1 with a dynamic `EventData` column — an explicitly stated
  assumption, because the lab's own evidence came from `ForwardedEvents`, not
  Sentinel.

Neither form merges `SOC002-DET-003`, the `BASE-01` baseline, the Base64 decode
enrichment, or PowerShell 4104 into the trigger. That separation is enforced by
the offline validators (`validate_sigma.ps1`, `validate_kql.ps1`).

## 10. Final status

| Element | Status |
|---|---|
| Telemetry pipeline (Phase 4) | Verified (Sysmon 1/3, Security 4624/4625/4688, PowerShell 4104, WEF active) |
| `SOC002-DET-001` / v2 | Implemented, tuned, validated, documented |
| `SOC002-DET-002` | Implemented (context only) |
| `SOC002-DET-003` | Implemented, back-tested, live-validated once |
| Correlation `SOC002-CORR-001` / `-002` | Implemented; gaps printed, never forced |
| Cases `SOC002-CASE-0001/0002/0003` | Closed |
| Sigma representation | PASS (61/61 structural checks) |
| KQL translation | PASS (static/offline; no backend execution) |
| Phase 5–10 source integrity | Byte-identical pre/post (see `FINAL_INTEGRITY_REPORT.md`) |
| ATT&CK mapping | Conservative; OBSERVED / contextual separated |
| Production claim | **None** — controlled lab only |

SOC-002 is complete as a controlled detection-engineering and investigation lab.
It demonstrates skills; it does not claim employment experience.
