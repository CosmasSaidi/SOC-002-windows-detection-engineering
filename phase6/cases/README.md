# SOC-002 Phase 6 — Case Management

This directory holds SOC cases created from SOC-002 detections. A case is the
artefact that survives after an alert is triaged: it records what was seen, what
was concluded, on what authority, and what remains unknown.

## Structure

```
cases/
  README.md                  <- this file (how cases are laid out and used)
  SOC002-CASE-0001/
    CASE.md                  <- the human-readable case record
    case.json                <- the same case in structured form (fields + status)
```

## Conventions used by SOC-002 cases

- **One case per triaged alert (or alert cluster).** The case ID is stable and
  never reused: `SOC002-CASE-NNNN`.
- **Every factual line is labelled** `OBSERVED`, `INFERRED` or `NOT VERIFIED`.
  A case must never present an inference as an observation.
- **Detections are referenced, not restated.** The case points at the detection
  file that produced the alert (`phase5/detections/…`, `phase6/detections/…`)
  and at the evidence file the alert was read from.
- **Classification vocabulary** used here:
  - `CONTROLLED TEST ACTIVITY / AUTHORISED BENIGN` — deliberate, documented lab
    activity, authorised by the lab design.
  - `AUTHORISED ADMINISTRATION` — legitimate operator activity through the
    sanctioned management channel (WinRM in this lab).
  - `SUSPECTED MALICIOUS` — reserved; has never been used in SOC-002.
  - `INCONCLUSIVE — INSUFFICIENT EVIDENCE` — used when the telemetry needed to
    decide is missing (see the failure modes in `evidence/t7_failure_modes.txt`).
- **A detection firing is not a verdict.** `SOC002-DET-001` and `SOC002-DET-002`
  are deliberately written to say "look at this", never "this is malicious".
  A case is where a human, not a rule, decides.
- **No credentials or secrets** are ever written into a case. Logon IDs and SIDs
  are identifiers, not secrets, and are retained because they are the correlation
  keys of record.

## Cases in this phase

| Case ID | Host | Detection | Classification | Status |
|---|---|---|---|---|
| `SOC002-CASE-0001` | `SOC002-WS001.soc002.local` | `SOC002-DET-001` (Encoded PowerShell) | CONTROLLED TEST ACTIVITY / AUTHORISED BENIGN | CLOSED |

The 38 authorised WinRM alerts that Phase 6 auto-classifies as baseline transport
do **not** each get a case. They are recorded as a single baseline observation in
`SOC002-CASE-0001` (`bulk_baseline_observation`), because a case per routine
administrative call is exactly the triage load Phase 6 exists to remove. What
they do keep is the per-event reason they were baselined, in
`evidence/t6_phase6_det001_v2_live_dc1.txt`.
