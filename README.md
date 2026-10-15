# SOC-002 — Windows Detection Engineering & Investigation

A self-directed, controlled Windows/AD security operations lab that takes one
detection from raw telemetry to a portable, vendor-neutral artifact. The project
builds an isolated two-VM Active Directory environment, centralises Windows
telemetry through Windows Event Forwarding (WEF), engineers and tunes detections
against controlled activity, investigates the resulting alerts, validates a real
blind spot, maps the behaviour to MITRE ATT&CK, and closes by representing the
detection in Sigma and translating it to KQL.

> This is a controlled laboratory project. It demonstrates detection-engineering
> and investigation skills; it is **not** production SOC experience, enterprise
> SOC experience, professional incident response, a real-world breach, live
> production detection, or a deployed Sentinel detection.

## 1. Objective

Prove, end to end and with preserved evidence, that a single detection can be
built, tuned, broken, fixed and handed off honestly:

- collect Windows/AD telemetry centrally and prove each source works;
- write a first detection and measure its real behaviour (including its noise);
- tune it without silently shrinking its coverage;
- test a known limitation with a controlled execution and accept the negative
  result;
- add a complementary detection for the confirmed gap;
- represent the detection portably (Sigma) and translate it (KQL);
- keep every claim bounded by what the evidence shows.

## 2. Project description

SOC-002 is a controlled Windows/AD security operations lab. Phase 4 established
the telemetry pipeline (Sysmon, Windows Security and PowerShell 4104 forwarded
from a domain-joined workstation to a WEF collector). Phase 5 executed one benign
encoded-PowerShell test and built the first detection, `SOC002-DET-001`. Phase 6
hardened it into `SOC002-DET-001 v2`, added a lineage detection and a correlation
layer, and documented the detection's failure modes. Phase 7 validated a real
blind spot with a single controlled execution. Phase 8 built `SOC002-DET-003` for
that gap. Phases 9 and 10 represented `SOC002-DET-001` in Sigma and translated it
to KQL. Every phase preserved its evidence and the evidence of the phases before
it; the integrity of the Phase 5–10 source artifacts is verified at hand-off.

## 3. Environment / architecture

Isolated VirtualBox lab on a single operator host. No internet-facing exposure,
no production network, no live adversary.

| Role | Host | Platform | Notes |
|---|---|---|---|
| Collector / domain controller | `SOC002-DC1` (192.168.56.10) | Windows Server 2022 | AD DS + DNS + WEF collector (`ForwardedEvents`); Sysmon absent by design |
| Endpoint | `SOC002-WS001` (192.168.56.102) | Windows 10 Pro | Domain-joined `soc002.local`; Sysmon, PowerShell Script Block Logging, Security auditing |
| Operator | Kali (192.168.56.1) | Linux | Drives the lab over WinRM/NTLM (authorised management channel) |

Telemetry path:

```
SOC002-WS001 ──(WEF pull subscription SOC002-WS001-Security)──> SOC002-DC1
   Sysmon 1/3, Security 4624/4625/4688, PowerShell 4104        ForwardedEvents
```

## 4. Telemetry sources

Proven present and flowing (Phase 4):

- `Sysmon Event ID 1` — process create (image, command line, `ProcessGuid`, parent, hashes).
- `Sysmon Event ID 3` — network connect (used to check for payload network activity).
- `Security Event ID 4688` — process creation with populated `CommandLine`.
- `Security Event ID 4624` / `4625` — successful / failed logon.
- `PowerShell Event ID 4104` — script block logging (payload corroboration).

Details and per-source limitations: `TELEMETRY_ARCHITECTURE.md`.

## 5. Detection engineering workflow

1. Start from a controlled, benign execution (Phase 5).
2. Write a transparent, reproducible detection over centralised `ForwardedEvents`.
3. Measure its real output, including the noise it produces (39 hits in 60
   minutes, 38 of them the operator's own WinRM administration).
4. Tune by *classification and context*, never by narrowing the trigger
   (`SOC002-DET-001 v2`: `BASE-01` baseline + `ESC-01..08` payload screen).
5. Add context detections (`SOC002-DET-002` lineage) and correlation
   (`SOC002-CORR-001`, later `SOC002-CORR-002`).
6. Document failure modes and refused tunings explicitly.

Details: `DETECTION_ENGINEERING.md`.

## 6. Investigation workflow

Every alert is treated as an analyst question — "what happened, how was it
delivered, does the evidence support a benign explanation?" — not as a verdict.
The investigation model is evidence-bounded:

- **OBSERVED** — read directly from an event or host output.
- **INFERRED** — drawn from multiple observations.
- **NOT VERIFIED** — not tested, or not auditable in this lab.

Three documented cases exist: `SOC002-CASE-0001` (Phase 5),
`SOC002-CASE-0002` (Phase 7), `SOC002-CASE-0003` (Phase 8). See
`INVESTIGATION_AND_CASES.md`.

## 7. Detection tuning

`SOC002-DET-001`'s trigger was deliberately **not** changed between Phase 5 and
Phase 6. Phase 6 added:

- `BASE-01`, a narrow WinRS transport baseline (parent `cmd.exe` **and** parent
  command line is the WinRS wrapper `cmd.exe /C powershell -encodedcommand <b64>`);
- `ESC-01..08`, a payload screen where any high-risk construct overrides the
  baseline;
- lineage gating of the baseline's strength, plus a 4688 fallback where Sysmon
  Event 1 is missing.

The full list of tunings that were considered and **refused** (user, logon id,
host, hash, integrity level, time-of-day) is preserved in
`phase6/evidence/TUNING_RATIONALE.txt`.

## 8. Blind-spot validation

Phase 7 ran **one** controlled, benign execution whose command line used
`-Command` with `[Convert]::FromBase64String(...)` and **no** encoded-command
switch. The unmodified Phase 6 stack did not detect it:

| Detection | Result |
|---|---|
| `SOC002-DET-001 v2` | **MISS** — the payload process never became a candidate |
| `SOC002-DET-002` | CONTEXT — recorded the payload as lineage, `Encoded switch = absent` |
| `SOC002-CORR-001` | no correlation (it consumes DET-001 candidates) |

The activity was nevertheless fully visible in Security 4688, Sysmon Event 1,
PowerShell 4104 and DC1 `ForwardedEvents`. This is reported as a confirmed,
controlled blind spot — not hidden and not explained away.

## 9. Sigma / KQL representation

- `phase9/sigma/SOC002-DET-001-encoded-powershell.yml` — Sigma representation of
  the existing trigger (`Sysmon Event ID 1`, `powershell.exe`/`pwsh.exe` +
  encoded-command switch). Structurally validated offline (61/61 checks).
- `phase10/kql/SOC002-DET-001-encoded-powershell.kql` — faithful KQL translation
  of the portable Sigma form.
- `phase10/kql/SOC002-DET-001-encoded-powershell-regex.kql` — KQL that reproduces
  the original detector's token-exact short-switch regex.

These are **Sentinel-oriented artifacts**: static, offline translations for a
Microsoft Sentinel / Defender-style `Event` table. They have **not** been
executed against any live backend and are **not** deployed to Microsoft Sentinel.

## 10. ATT&CK coverage

Evidence-bounded mapping only:

- **Observed technique-like behaviour:** `T1059.001` (PowerShell), `T1027`
  (obfuscated/encoded information).
- **Contextual mapping:** `T1021.006` (WinRM) — this is how the lab is *operated*
  (the sanctioned management channel), not adversary behaviour.
- **Deliberately not mapped:** persistence, privilege escalation, credential
  access, lateral movement, log tampering, `T1140`.

See `ATTACK_MAPPING.md` for the OBSERVED / INFERRED / contextual distinction.

## 11. Key findings

- A single encoded-command indicator produced **39 alerts in 60 minutes on one
  host**, 38 of them the operator's own WinRM administration — a **structural**
  false-positive source, not random noise.
- The one event worth investigating did **not** share the benign shape, so coarse
  tuning would have hidden it.
- The detection had a **real, confirmed blind spot**: switch-free in-process
  Base64 reconstruction (`[Convert]::FromBase64String`).
- A complementary, separately auditable detection (`SOC002-DET-003`) closes that
  specific gap without merging coverage claims; the two detections are **disjoint**
  on the observed cases.
- Telemetry itself has gaps: a **2012-second hole** in the Sysmon Event 1 stream
  at the collector, during which Security 4688 kept recording. The trigger for
  the hole is `NOT VERIFIED`.

## 12. Limitations

- Controlled lab, single analyst, two VMs; no adversary telemetry exists.
- Single-run validations; **no detection rate and no false-positive rate** is
  measured or claimed.
- `SOC002-DET-001` is a **triage** signal, not a compromise detector.
- The Base64-reconstruction detection is text-only; fragment-built decoders,
  `certutil -decode`, compiled binaries and non-PowerShell hosts are not covered.
- Sigma/KQL artifacts are static and offline; no backend execution occurred.
- Bounded lab retention makes long-window absence "not observed", not "disproved".

Full coverage matrix: `DETECTION_COVERAGE_AND_LIMITATIONS.md`.

## 13. Evidence structure

```
soc002-final/
  README.md
  PROJECT_SUMMARY.md                    executive/technical summary
  DETECTION_ENGINEERING.md              DET-001 / DET-001 v2 / DET-003 evolution
  INVESTIGATION_AND_CASES.md            CASE-0001/0002/0003
  TELEMETRY_ARCHITECTURE.md             WS001 / DC1 / WEF / Sysmon / 4104 / Security
  DETECTION_COVERAGE_AND_LIMITATIONS.md coverage table + blind spots
  ATTACK_MAPPING.md                     conservative ATT&CK mapping
  PORTFOLIO_NOTES.md                    how to present this publicly
  EVIDENCE_INDEX.md                     navigable index of the original evidence
  SHA256_MANIFEST.txt                   hashes of this documentation package
  FINAL_INTEGRITY_REPORT.md             pre/post integrity of Phase 5–10 sources
```

The original Phase 4–10 artifacts are preserved untouched under `phase4/` …
`phase10/`. This directory contains documentation, summaries and indexes only —
no original evidence was rewritten.

## 14. Honest skills demonstrated

- Building and verifying a WEF-based Windows/AD telemetry pipeline.
- Writing readable detection logic over centralised event data.
- Measuring, rather than asserting, detection behaviour and false positives.
- Tuning by context without silently reducing coverage; documenting refused
  tunings.
- Designing a negative test, accepting the negative result, and building a
  complementary detection for a confirmed gap.
- Multi-source correlation and evidence-bounded investigation with explicit
  OBSERVED / INFERRED / NOT VERIFIED labelling.
- Conservative ATT&CK mapping; portable detection representation (Sigma) and a
  Sentinel-oriented translation (KQL).
- Evidence preservation and SHA256-based integrity hand-off.

The project demonstrates skills; it does not claim employment experience.
