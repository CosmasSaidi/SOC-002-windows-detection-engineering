# SOC-002 — Portfolio Notes

How to represent this project publicly. These notes exist because the honest
version of SOC-002 is more credible than an inflated one — and because the
inflated version would be false.

## Recommended positioning

> **Windows Detection Engineering & Investigation**

Optional one-line framing: *a controlled Windows/AD security operations lab.*

## Recommended description

> A controlled Windows/AD security operations lab demonstrating telemetry
> engineering, detection development, investigation, tuning, ATT&CK mapping,
> Sigma representation, and KQL translation.

Longer version, if a paragraph is needed:

> I built an isolated two-VM Active Directory lab and centralised Windows
> telemetry (Sysmon, Windows Security, PowerShell 4104) through Windows Event
> Forwarding. Starting from one benign encoded-PowerShell execution, I developed
> and measured a detection, hardened it without narrowing its trigger, validated a
> real blind spot with a controlled test, built a separate complementary detection
> for it, and represented the detection in Sigma and KQL. Every claim in the
> project is bounded by preserved evidence with SHA256 integrity checks.

## Accurate skill statements

These are safe to say, and are each backed by an artifact in this repository:

- Built and verified a WEF-based Windows/AD telemetry pipeline across two VMs.
- Developed detection logic in PowerShell over centralised `ForwardedEvents`.
- **Measured** the detection's behaviour instead of asserting it (39 alerts in 60
  minutes for one real event; 38 were the operator's own WinRM administration).
- Tuned a detection by classification and context rather than by shrinking its
  trigger, and documented the tunings that were refused.
- Designed and ran a negative test, accepted the negative result, and built a
  **separate** detection for the confirmed gap.
- Performed multi-source correlation and evidence-bounded investigation with
  explicit OBSERVED / INFERRED / NOT VERIFIED labelling.
- Mapped activity to ATT&CK conservatively and separated observed behaviour from
  operational context.
- Represented a detection in Sigma and translated it to KQL for a Microsoft
  Sentinel-style environment.
- Preserved evidence and verified integrity by SHA256 across phases.

## Words that are safe to use

- controlled Windows/AD security operations lab
- self-directed security operations project
- controlled detection-engineering environment
- documented investigation
- laboratory validation
- Sentinel-oriented KQL artifact
- Sigma representation
- blind-spot validation
- triage signal
- evidence-bounded / OBSERVED · INFERRED · NOT VERIFIED

## Explicit warnings — do not claim

Do **not** describe SOC-002 as any of the following. Each would be false:

1. **Production SOC experience** — no production environment was involved.
2. **Enterprise SOC experience / enterprise deployment** — the lab is two VMs on
   an isolated host.
3. **Live or deployed Sentinel detection** — the KQL is a static, offline
   translation; it was never executed against a backend, and nothing is deployed
   to Microsoft Sentinel or any SIEM.
4. **A real-world breach / real compromise / real incident** — all activity was
   controlled, authorised and benign, and each case is classified
   `CONTROLLED TEST ACTIVITY / AUTHORISED BENIGN`.
5. **Professional incident response experience** — the investigations are lab
   exercises, not professional IR work.
6. **Zero false positives** — the lab measured the *opposite*: 38 of 39 alerts in
   one hour were the operator's own administration, and the lab's own tooling also
   inflates `SOC002-DET-003` volume. No FP/FN rate is claimed at any scale.
7. **Complete attack coverage** — Phase 7 demonstrated a real, confirmed blind
   spot, and several more are documented as unverified. Coverage is explicitly
   incomplete.
8. **Malware analysis / red teaming / threat hunting** — not what was done.
9. **A detection that "proves compromise"** — `SOC002-DET-001` and
   `SOC002-DET-003` are triage/context signals, not verdicts.

## Points to emphasise in interviews

- **I tested the detection against its known weakness and reported the failure.**
  The Phase 7 result is a *negative* result that the project keeps and explains.
- **I refused the easy tuning.** User, host, hash, integrity level and time-of-day
  would all have silenced the noise — and would all have hidden real activity.
- **I kept the coverage claims separate.** `SOC002-DET-003` was not merged into
  `SOC002-DET-001`; the two detections are disjoint on every observed case.
- **I labelled my uncertainty.** Every case uses OBSERVED / INFERRED / NOT
  VERIFIED, and the unverified root cause of the Sysmon gap is stated as
  unverified.
- **I preserved the evidence.** Each phase re-hashed the previous phases; the
  Phase 5–10 sources are byte-identical at hand-off
  (`FINAL_INTEGRITY_REPORT.md`).

## Suggested repository blurb

> A controlled Windows/AD detection-engineering lab: WEF telemetry → detection →
> controlled activity → investigation → tuning → blind-spot validation → Sigma →
> KQL, with evidence preservation throughout. Lab-validated; not production.

## What is deliberately *not* included publicly

- No credentials, keys or tokens are stored anywhere in the artifact tree (WinRM
  credentials come from environment variables at run time).
- No malware, no offensive tooling, no captured real-world data.
- The controlled payloads are self-labelled harmless markers; they are documented
  as such so no reviewer mistakes them for malicious content.
