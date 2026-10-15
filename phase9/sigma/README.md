# SOC-002 — Phase 9: Sigma representation of SOC002-DET-001

Phase 9 closes SOC-002 by expressing the detection the lab already built and validated
in a portable, vendor-neutral format. It is a **representation** phase: no new detection
logic, no new lab activity, and no modification to any Phase 5–8 artifact.

## Contents

| File | Purpose |
|---|---|
| `SOC002-DET-001-encoded-powershell.yml` | Sigma rule for the existing DET-001 trigger (Sysmon Event ID 1, `powershell.exe`/`pwsh.exe` + encoded-command switch). |
| `SIGMA_NOTES.md` | What was preserved, what could not be represented portably, and the limits of the claim. |
| `validate_sigma.ps1` | Offline structural validation (no internet, no Sentinel, no Sigma backend required). |
| `PRE_SIGMA_HASHES.txt` | SHA256 baseline of the authoritative source files, recorded **before** creation. |
| `SHA256_MANIFEST.txt` | SHA256 of the Phase 9 artifacts, for tamper-evident hand-off. |
| `SIGMA_VALIDATION_REPORT.md` | Validation results, pre/post hash comparison, caveats, PASS/FAIL. |

## Why Sigma

Sigma is the portable representation of the detection logic — the same trigger can be
translated to whichever backend a team runs, instead of living only inside one
PowerShell script that queries `ForwardedEvents` on a specific collector.

The rule encodes the **primary** DET-001 condition only:

```
Sysmon Event ID 1  AND  Image endswith powershell.exe|pwsh.exe
                   AND  CommandLine contains -EncodedCommand
```

That is the same condition Phase 5 validated against controlled lab activity and Phase 6
replayed unchanged.

## What is intentionally not here

- **Base64 decoding / payload extraction** — enrichment in the original detector, not a
  detection condition.
- **PowerShell Event ID 4104** — corroboration in the original detector; a separate
  correlation step, not part of the trigger.
- **Phase 6 `BASE-01` WinRS baseline** — lab-contextual tuning, not a portable exclusion.
  It needs the parent command line and the decoded payload, which a single-event
  process-creation rule does not have. Encoding it globally would suppress exactly the
  transport a real operator's tooling uses.
- **SOC002-DET-003** (`[Convert]::FromBase64String` reconstruction) — a different
  detection for a different blind spot. Merging it would silently broaden DET-001.
- **Short-switch forms `-e` / `-en` / `-enc`** — they cannot be expressed safely with
  portable Sigma string matching, so the gap is documented instead of written as a weak
  wildcard.

## Validation

```powershell
pwsh -NoProfile -File phase9/sigma/validate_sigma.ps1
```

Performs deterministic local checks: required Sigma fields, UUID, logsource
(Sysmon / process create / Event ID 1), `powershell.exe`+`pwsh.exe`, the encoded-command
variant, absence of DET-003 trigger logic, absence of production/Sentinel claims, and
re-verification of the pre-change hashes of the Phase 5–8 sources.

## Honest scope

Lab-validated Sigma representation of an existing lab detection. Not deployed to
Microsoft Sentinel or any production SIEM; no production SOC experience is implied. See
`SIGMA_NOTES.md` for the full list of limits, portability caveats and blind spots.
