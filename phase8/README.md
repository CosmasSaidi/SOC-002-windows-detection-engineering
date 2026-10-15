# SOC-002 Phase 8 — DET-003: PowerShell Base64 Reconstruction / Decode Behaviour

Phase 8 builds a **complementary** detection — `SOC002-DET-003` — for the exact
blind spot Phase 7 confirmed: PowerShell that reconstructs data with
`[Convert]::FromBase64String(...)` and carries **no** encoded-command CLI switch.
`SOC002-DET-001 v2` is **not** modified or extended.

**Result: DET-003 identifies the behaviour.** It flagged the Phase 7 blind-spot
payload (PID 1428) in all four preserved Phase 7 views, a benign comparison suite
showed it does **not** fire on the word "Base64", and one controlled, harmless
live run on `SOC002-WS001` was detected in 4688, Sysmon Event 1 and 4104 locally
and in DC1 `ForwardedEvents`.

Read `PHASE8_REPORT.md` first. The case is `cases/SOC002-CASE-0003/`.

- DET-001 v2 is **byte-identical** before and after Phase 8 (`c9b73426…d16c`).
- Phase 5/6/7 trees re-hashed: **0 changed, 0 missing, 0 added**.
- No configuration, policy, WEF subscription or Sysmon setting was changed.
- No credentials are stored anywhere in this tree.

## Layout

```
phase8/
  PHASE8_REPORT.md                      the phase report (20 sections)
  SHA256_MANIFEST.txt                   integrity manifest for this tree
  detections/
    lib_soc002_phase8.ps1               DET-003 decision logic (cross-platform)
    detect_base64_reconstruction.ps1    DET-003 live detector (Windows/WEF)
  analysis/
    replay_phase8_phase7_evidence.ps1   offline replay over preserved Phase 7 XML
    benign_comparison_phase8.ps1        benign comparison suite (keyword rule vs DET-003)
    det_comparison_phase8.ps1           DET-001 vs DET-003 trigger matrix
    phase8_result_summary.ps1           derives the Phase 7 back-test result
    format_phase8_telemetry.ps1         raw XML -> analyst-facing telemetry view
    phase8_integrity_and_cleanup.sh     pre/post integrity + preservation check
    build_manifest.sh                   builds SHA256_MANIFEST.txt
    run_all_offline_phase8.sh           regenerates ALL offline evidence
  scripts/
    phase8_child_command.txt            the harmless payload body under test
    build_phase8_payload.py             builds the body + metadata
    execute_phase8_once.py              the single controlled live run
    run_det003_on_dc1.py                runs DET-003 live on the DC1 collector
  tools/
    collect_raw_events.py               read-only raw telemetry sampler
  evidence/                             all Phase 8 evidence
  cases/SOC002-CASE-0003/               the case (CASE.md + case.json)
```

## Reproducing the offline analysis

```bash
# regenerate every offline artefact (replays, benign suite, telemetry view, summary)
bash ~/soc-lab/phase8/analysis/run_all_offline_phase8.sh
# integrity + preservation check
bash ~/soc-lab/phase8/analysis/phase8_integrity_and_cleanup.sh
# rebuild the SHA256 manifest
bash ~/soc-lab/phase8/analysis/build_manifest.sh
```

The live steps (execution and collection) require the lab VMs and credentials in
`WINRM_USER` / `WINRM_PASS`; no credential is stored in this tree.

## Lab notes for anyone re-running this

- WS001's effective execution policy is **Restricted**; Phase 8 did not change it
  and did not use `-ExecutionPolicy Bypass`. The payload is handed to a plainly
  started `powershell.exe` via `-Command` (exactly the Phase 7 shape).
- The operator's own file staging uses `[Convert]::FromBase64String`, so it
  appears as a DET-003 candidate labelled `CTX-PLUMBING`. That is a documented,
  measured precision cost, not the activity under test.
- `DET-003` reads text only. It never executes or decodes-and-runs anything.
