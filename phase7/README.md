# SOC-002 Phase 7 — Blind-Spot Validation

Phase 7 tested one documented Phase 6 blind spot with a single controlled, benign
execution on `SOC002-WS001`, then ran the **unmodified** Phase 6 detection stack
over the result.

**Result: OUTCOME B — the blind spot is confirmed.** `SOC002-DET-001 v2` did not
detect the activity (its trigger requires an encoded-command CLI switch);
`SOC002-DET-002` recorded the payload process as lineage context only; and
`SOC002-CORR-001` could not correlate it because it consumes DET-001 candidates.

Read `PHASE7_REPORT.md` first. The case is `cases/SOC002-CASE-0002/`.

- Phase 5 and Phase 6 evidence were **not** modified (88 and 34 files re-hashed: 0 changes).
- No detection logic was modified. The Phase 6 detection files were staged
  byte-identical and their SHA256 values are re-printed inside the run output.
- No configuration, policy, WEF subscription or Sysmon setting was changed.

## Layout

```
phase7/
  PHASE7_REPORT.md                     the phase report (18 sections)
  SHA256_MANIFEST.txt                  integrity manifest for this tree
  scripts/
    phase7_child_command.txt           the exact payload command body (the thing under test)
    phase7_run_ws001.ps1               first-attempt runner (blocked by execution policy)
    execute_phase7_once.py             the single controlled execution driver
    collect_raw_events.py              read-only raw event sampler (WS001 / DC1)
    collect_phase7_telemetry.ps1       read-only collector body (run as content)
    collect_via_winrm.py               content-delivery helper for the collector
    run_phase7_detections_dc1.ps1      invokes the unmodified Phase 6 stack on DC1
    snapshot_tree_hashes.sh            preservation snapshotter
    phase7_cleanup_and_integrity.sh    post-run integrity + lab temp cleanup
  analysis/
    preflight_phase7.ps1               trigger check against the real Phase 6 library
    format_phase7_evidence.ps1         raw XML -> readable evidence
    phase7_process_lineage.ps1         lineage + per-process trigger evaluation
    compare_phase6_phase7.ps1          baseline comparison + drift check
    phase7_result_summary.ps1          derives the result from the evidence files
    build_manifest.sh                  builds SHA256_MANIFEST.txt
  evidence/                            all Phase 7 evidence (see report section 14)
  cases/SOC002-CASE-0002/              the case (CASE.md + case.json)
```

## Reproducing the offline analysis

```bash
pwsh -File ~/soc-lab/phase7/analysis/preflight_phase7.ps1
pwsh -File ~/soc-lab/phase7/analysis/phase7_process_lineage.ps1
pwsh -File ~/soc-lab/phase7/analysis/compare_phase6_phase7.ps1
pwsh -File ~/soc-lab/phase7/analysis/phase7_result_summary.ps1
```

The live steps (execution and collection) require the lab VMs and credentials in
`WINRM_USER` / `WINRM_PASS`; no credential is stored in this tree.

## Lab notes for anyone re-running this

- `SOC002-WS001`'s effective execution policy is **Restricted** (every scope
  Undefined), so a staged `.ps1` cannot be executed there. Phase 7 did not change
  that policy and did not use `-ExecutionPolicy Bypass`; the payload is handed to
  a plainly started `powershell.exe` via `-Command`.
- A WinRS transport command line is bounded (~8 KB), so large bodies must be
  staged rather than sent inline.
- Every WinRM call creates `cmd.exe /C powershell -EncodedCommand <b64>` on the
  target. That transport wrapper is baseline noise, not the activity under test.
- The operator's own staged-file transfers contain `[Convert]::FromBase64String`
  and therefore trip `ESC-03`, producing INVESTIGATION records that are the
  operator's own plumbing. This is a known Phase 6 precision cost.
