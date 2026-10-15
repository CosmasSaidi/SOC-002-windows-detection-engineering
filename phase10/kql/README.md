# SOC-002 — Phase 10: KQL translation of SOC002-DET-001

Phase 10 closes SOC-002 by translating the detection the lab already built and validated
into **KQL** for a Microsoft Sentinel / Microsoft Defender-style environment, and by
stating explicitly which source schema that KQL assumes.

This is a **translation / validation artefact**, not a new detection. No new detection
logic was developed, no detection was modified, no lab activity was run, and no Phase 5–9
artefact was touched.

## Contents

| File | Purpose |
|---|---|
| `SOC002-DET-001-encoded-powershell.kql` | Primary KQL query — faithful translation of the **portable Sigma** form (`CommandLine contains -EncodedCommand`). |
| `SOC002-DET-001-encoded-powershell-regex.kql` | KQL query that reproduces the **original detector's** token-exact short-switch regex `(?i)\s-(e\|en\|enc\|encodedcommand)(\s\|$)`. |
| `KQL_NOTES.md` | Source-table assumption, operator rationale, portable-vs-regex difference, and the limits of the claim. |
| `validate_kql.ps1` | Offline static validation (no internet, no Sentinel, no KQL parser required). |
| `PRE_KQL_HASHES.txt` | SHA256 baseline of the authoritative sources, recorded **before** creation. |
| `SHA256_MANIFEST.txt` | SHA256 of the Phase 10 artefacts, for tamper-evident hand-off. |
| `KQL_VALIDATION_REPORT.md` | Validation results, pre/post hash comparison, limitations, PASS/FAIL. |

## The detection in one line

```
Sysmon Event ID 1  AND  Image endswith powershell.exe|pwsh.exe
                   AND  CommandLine carries an encoded-command switch
```

That is the same condition Phase 5 validated against controlled lab activity and Phase 6
replayed unchanged. It is a **triage** signal — "an analyst should look at this" — not a
malicious-verdict and not a compromise detector.

## The assumed source schema

Primary target: the Microsoft Sentinel **`Event`** table carrying **Sysmon Event ID 1**
(Process Create) forwarded from the channel `Microsoft-Windows-Sysmon/Operational`, with
`EventData` as a dynamic (JSON) column. This is an **assumption**, stated because the lab's
evidence was collected from a Windows Event Forwarding collector's `ForwardedEvents` log,
not from Sentinel. The alternative ingestion shape (`ParameterXml`) is documented in
`KQL_NOTES.md` §1.

`DeviceProcessEvents` is **not** used. It represents **Defender for Endpoint telemetry, not
the lab's Sysmon Event 1**. An optional Defender XDR equivalent is shown, clearly
labelled as a different source model, in `KQL_NOTES.md` §9.

## Two forms, deliberately

| | Switch covered | Boundary-enforced | Relationship |
|---|---|---|---|
| `...encoded-powershell.kql` | `-EncodedCommand` | no | faithful to the portable Sigma representation |
| `...encoded-powershell-regex.kql` | `-e` \| `-en` \| `-enc` \| `-encodedcommand` | yes | closer to the original lab detector |

Portable Sigma string matching cannot express the short switches `-e` / `-en` / `-enc`
without also matching `-ErrorAction` / `-Enabled` / `-Encoding`, so Phase 9 documented
that gap instead of writing a weak wildcard. The regex KQL file closes the gap with a
token-exact regex. **Neither form silently broadens or narrows the other** — the
difference is documented in `KQL_NOTES.md` §5.

## What is intentionally not here

- **Base64 decoding / payload extraction** — enrichment in the original detector, not a
  detection condition.
- **PowerShell Event ID 4104** — corroboration in the original detector, and a
  non-mandatory one (the Sysmon alert stands even when 4104 is `NONE FOUND`).
- **The Phase 6 `BASE-01` WinRS baseline** — lab-contextual tuning, not a portable
  exclusion; it needs the parent command line and the decoded payload.
- **`SOC002-DET-003`** (`FromBase64String` reconstruction) — a different detection for a
  different blind spot; merging it would silently broaden DET-001.

## Validation

```powershell
pwsh -NoProfile -File phase10/kql/validate_kql.ps1
```

Performs deterministic offline checks: the query files exist and are non-empty; Event ID 1,
the Sysmon source, `powershell.exe`+`pwsh.exe` and the encoded-command logic are all
represented; the other detection's reconstruction logic and the environment-specific
baseline are absent from the query logic; 4104 is not required; no production/Sentinel
execution claim is made; the notes/README document the assumptions; the SHA256 manifest is
valid; and the pre-change hashes of the Phase 5–9 sources are re-verified.

The validator **does not execute KQL** — there is no local KQL parser or backend. It checks
structure and claims, not runtime behaviour.

## Honest scope

Static, offline KQL translation of an existing lab detection. **Not executed against any
live backend; not deployed to Microsoft Sentinel or any production SIEM; no production SOC
experience is implied.** See `KQL_NOTES.md` for the full list of assumptions, portability
caveats and blind spots.
