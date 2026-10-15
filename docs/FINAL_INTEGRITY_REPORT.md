# SOC-002 — Final Integrity Report

Scope: integrity of the authoritative Phase 5–10 source artifacts across the
creation of this documentation package, plus the SHA256 manifest of the package
itself.

**Result: PASS — every Phase 5–10 source artifact is byte-identical before and
after packaging. No original evidence was modified, rewritten or removed.**

## 1. Method

- **Algorithm:** SHA256.
- **Paths:** relative to the repository root (`./`).
- **Recursive tree digest:** `digest = sha256( sha256sum output of every file under
  the roots, the file list produced with `find <root> -type f -print0` and ordered
  with `LC_ALL=C sort -z`; each line formatted `<hash>  <relpath>` )`.
  This is the same method used by the Phase 9 and Phase 10 closure phases.
- **Pre-state captured before any documentation was written:** `2026-10-15T15:42:16Z`.
- **Post-state captured after all documentation was written:** verified below.

## 2. Recursive Phase 5–10 tree digest

| | Value |
|---|---|
| Roots | `phase5/`, `phase6/`, `phase7/`, `phase8/`, `phase9/`, `phase10/` |
| Files | **240** |
| Pre-state digest | `0488176406775a499d726244a3fb9f222759dd41f7bff9abb5d2fffe78fbc3ac` |
| Post-state digest | `0488176406775a499d726244a3fb9f222759dd41f7bff9abb5d2fffe78fbc3ac` |
| Result | **byte-identical** (the two `sha256sum` listings diff to empty) |

Per-root file counts and digests (each computed with its own `sha256sum | sha256sum`):

| Root | Files | Digest of that root |
|---|---|---|
| `phase5/` | 88 | `c1bc88cabc83e6e7d226930acf61de04cbc6b3beb3287d459076759a21e75b7b` |
| `phase6/` | 34 | `88b7821392d0582c584e1fe1850f38bda609d35449784937ef13b83705cdd5a8` |
| `phase7/` | 51 | `19d5f10a7959ed9b82cecefbee7aff783d53722dad79a2cb098c81930fda80b8` |
| `phase8/` | 52 | `7e0828e8206c7f897ab051f5de76d32cadcd1b7edad41534196b196d0cd40666` |
| `phase9/` | 7 | `46fa393ff958b2cc86778459daf01bb1bd8b643d4c235ade9c102067fc99a225` |
| `phase10/` | 8 | `d005b8a4306fdff5c7cb2000a31bd6dd18f26cac8a4c696f6bbb7ed8bebdb106` |

## 3. Curated source-artifact check

A curated set of **36** artifacts (all detection sources, phase reports, cases,
detection/numerical evidence files, and the Phase 4 telemetry configuration) was
hashed before and after packaging. Result: **36/36 byte-identical, 0 changed, 0
missing.**

Curated set includes (representative, not exhaustive):

- Detection sources: `phase5/detections/detect_encoded_powershell.ps1`,
  `phase6/detections/detect_encoded_powershell_v2.ps1`,
  `phase6/detections/lib_soc002_v2.ps1`,
  `phase6/detections/lib_soc002_windows.ps1`,
  `phase6/detections/detect_powershell_lineage.ps1`,
  `phase6/detections/correlate_det001_det002.ps1`,
  `phase8/detections/detect_base64_reconstruction.ps1`,
  `phase8/detections/lib_soc002_phase8.ps1`.
- Reports: `phase6/README.md`, `phase7/PHASE7_REPORT.md`, `phase8/PHASE8_REPORT.md`.
- Cases: `phase6/cases/SOC002-CASE-0001/{CASE.md,case.json}`,
  `phase7/cases/SOC002-CASE-0002/...`, `phase8/cases/SOC002-CASE-0003/...`.
- Mechanism/limitation evidence: `phase5/evidence/{ATTACK_MAPPING,DETECTION_LIMITATIONS,INVESTIGATION_NOTES,CORRELATION_TIMELINE,DECODED_TEST_COMMAND}.txt`,
  `phase6/evidence/{TUNING_RATIONALE.txt,t7_failure_modes.txt}`,
  `phase7/evidence/t11_limitations.txt`,
  `phase8/evidence/{DET003_DESIGN.md,t13_limitations.txt,t14_det001_vs_det003.txt}`.
- Representation: `phase9/sigma/SOC002-DET-001-encoded-powershell.yml`,
  `phase10/kql/SOC002-DET-001-encoded-powershell.kql`,
  `phase10/kql/SOC002-DET-001-encoded-powershell-regex.kql`.
- Telemetry config: `phase4/configs/wef_subscription.phase4.xml`,
  `phase4/configs/soc002_sysmon_phase4.xml`.

## 4. Independent cross-check against the recorded digests

The digests recorded by the earlier closure phases still reproduce exactly:

| Recorded by | Scope | Recorded value | Recomputed at packaging | Match |
|---|---|---|---|---|
| `phase9/sigma/PRE_SIGMA_HASHES.txt` | Phase 5–8 tree (225 files) | `26e3e636c24dde731d32e3a070956a9e326d4743f5f4e922441d8daf1eb9b702` | same value, 225 files | **yes** |
| `phase10/kql/PRE_KQL_HASHES.txt` | Phase 5–9 tree (232 files) | `d7e98c4a27a2dc0d0e410e7f88ad0794e1ec99d4760073db05a6c8455a788db5` | same value, 232 files | **yes** |

This confirms that the Phase 9 and Phase 10 records are internally consistent with
the artifacts on disk, and that the Phase 5–10 sources have not drifted since
those phases closed.

Note: `phase4/` is telemetry-architecture enabling evidence outside the Phase 5–10
change scope. It was **not** modified during packaging either (77 files;
digest `2a6c27ac62aa34dc0f719a98b71bddcb25b6b320ac1b78a40a4f4c7563d39708`), and
its two configuration files appear in the curated set above.

## 5. Package manifest and file count

- `SHA256_MANIFEST.txt` lists the SHA256 of every file in this package **except
  itself and this report** (following the Phase 9/10 precedent, so the report can
  record the manifest hash without creating a cycle).
- Manifest self-hash (`SHA256_MANIFEST.txt`):
  `69442938ff51a0e3a926593e0b97342d9407d1cca0a50e0b09b9afce383a1d12`
- Manifest entries: **9** (ATTACK_MAPPING.md,
  DETECTION_COVERAGE_AND_LIMITATIONS.md, DETECTION_ENGINEERING.md,
  EVIDENCE_INDEX.md, INVESTIGATION_AND_CASES.md, PORTFOLIO_NOTES.md,
  PROJECT_SUMMARY.md, README.md, TELEMETRY_ARCHITECTURE.md).
- Verify with: `cd soc002-final && sha256sum -c SHA256_MANIFEST.txt`
  (all 9 entries verify `OK` with no warnings).
- **Exact file count of the package: `soc002-final/` contains 11 files**
  (the 9 manifest entries above + `SHA256_MANIFEST.txt` +
  `FINAL_INTEGRITY_REPORT.md`).

## 6. What was and was not done

**Done:** created `soc002-final/` containing documentation, a summary, a coverage
matrix, an evidence index and this integrity report. Every fact in those documents
was taken from the existing artifacts. The evidence index was machine-checked: all
115 referenced paths exist.

**Not done:** no Phase 5–10 source file was edited, moved, renamed or deleted; no
detection logic was added or changed; no lab activity was run; no VM, WEF, Sysmon,
AD or DNS configuration was touched; no new detection or new phase was created; no
Git repository or commit was created; no software was installed. Temporary
validation files (pre/post hash listings) were written under `/tmp` only.

## 7. Statement

Every claim in this documentation package is bounded by the preserved artifacts it
cites. Any later edit to the files listed in `SHA256_MANIFEST.txt` (or to this
report) will invalidate the corresponding hash and is detectable with
`sha256sum -c`. The original evidence has not been rewritten.
