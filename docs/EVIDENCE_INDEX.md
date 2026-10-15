# SOC-002 — Evidence Index

A navigable index of the important SOC-002 evidence. All paths are relative to the
repository root (`./`) and point at the **original, preserved**
artifacts — nothing in this index was copied or rewritten. Every path below was
confirmed to exist at packaging time.

## Telemetry / architecture

| Path | What it shows |
|---|---|
| `phase4/configs/wef_subscription.phase4.xml` | Active WEF subscription: source, collector, query (Security 4624/4625/4688, PowerShell 4104, Sysmon 1/3), `ForwardedEvents` |
| `phase4/configs/soc002_sysmon_phase4.xml` | Active Sysmon config (schema 4.90; ProcessCreate + NetworkConnect only) |
| `phase4/backup/wef_subscription.pre-phase4.xml` | Subscription before the Phase 4 change |
| `phase4/evidence/final_snapshot_ws001.txt` | WS001 health: 4688 CommandLine policy, Sysmon status/config hash, retention |
| `phase4/evidence/final_snapshot_dc1.txt` | DC1 health: WEF active (`LastError 0`), Sysmon absent, `ForwardedEvents` coverage counts |
| `phase4/evidence/t3_preserve_check_dc1.txt` | Proof that 4624/4688/4104 + Sysmon + `RecordId` semantics are preserved centrally |
| `phase4/evidence/t3_dest_debug_dc1.txt` | Discovery that forwarded events have no rendered `Message` text (parse `EventData` XML) |
| `phase4/evidence/t4_dest4625_dc1.txt` | Controlled failed auth → fresh 4625 centralised with the same RecordID |
| `phase4/evidence/MANIFEST.txt` | Phase 4 evidence manifest |

## Detections

| Path | What it is |
|---|---|
| `phase5/detections/detect_encoded_powershell.ps1` | `SOC002-DET-001` (Phase 5 original) |
| `phase6/detections/detect_encoded_powershell_v2.ps1` | `SOC002-DET-001 v2` (trigger unchanged; classification added) |
| `phase6/detections/lib_soc002_v2.ps1` | Shared decision library (cross-platform) |
| `phase6/detections/lib_soc002_windows.ps1` | Windows/WEF adapter (`Get-WinEvent` readers) |
| `phase6/detections/detect_powershell_lineage.ps1` | `SOC002-DET-002` (WinRM lineage, context only) |
| `phase6/detections/correlate_det001_det002.ps1` | `SOC002-CORR-001` correlation |
| `phase8/detections/detect_base64_reconstruction.ps1` | `SOC002-DET-003` live detector |
| `phase8/detections/lib_soc002_phase8.ps1` | `SOC002-DET-003` decision logic (incl. `SOC002-CORR-002`) |
| `phase5/evidence/DETECTION_LIMITATIONS.txt` | DET-001 false positives / negatives / visibility gaps |
| `phase8/evidence/DET003_DESIGN.md` | DET-003 design and rationale |

## Investigations

| Path | What it shows |
|---|---|
| `phase5/evidence/INVESTIGATION_NOTES.txt` | CASE-0001: the 12 analyst questions and answers |
| `phase5/evidence/CORRELATION_TIMELINE.txt` | CASE-0001: multi-source timeline (WS001 + DC1) |
| `phase5/evidence/DECODED_TEST_COMMAND.txt` | CASE-0001: verbatim decoded benign script + base64 + hash |
| `phase5/evidence/t2_execute_ws001.txt` | CASE-0001: exact command construction, timestamps, output, exit code |
| `phase5/evidence/t3z_ancestry_ws001.txt` | CASE-0001: full Sysmon Event 1 process ancestry |
| `phase5/evidence/t7_integrity_ws001.txt` | CASE-0001: persistence/elevation integrity checks + audit-policy gaps |
| `phase5/evidence/t7_tasks2_ws001.txt` | CASE-0001: TaskScheduler 106 = 0 in window |
| `phase5/evidence/t8_cleanup_dc1.txt` | Transient on-target detection copy removed (hash matched) |
| `phase5/evidence/t9_post_ws001.txt` | Post-activity health + retention |
| `phase7/evidence/t10_investigation_notes.txt` | CASE-0002 investigation notes |
| `phase7/evidence/t12_exclusivity_checks.txt` | CASE-0002 containment / exclusivity checks |
| `phase8/evidence/t11_investigation_notes.txt` | CASE-0003 investigation notes |
| `phase8/evidence/t10_correlation.txt` | CASE-0003 correlation evidence |

## Cases

| Path | What it is |
|---|---|
| `phase6/cases/README.md` | Case-management conventions |
| `phase6/cases/SOC002-CASE-0001/CASE.md` | CASE-0001 (Phase 5 encoded PowerShell), human-readable |
| `phase6/cases/SOC002-CASE-0001/case.json` | CASE-0001 structured |
| `phase7/cases/SOC002-CASE-0002/CASE.md` | CASE-0002 (Phase 7 blind-spot validation) |
| `phase7/cases/SOC002-CASE-0002/case.json` | CASE-0002 structured |
| `phase8/cases/SOC002-CASE-0003/CASE.md` | CASE-0003 (Phase 8 DET-003 validation) |
| `phase8/cases/SOC002-CASE-0003/case.json` | CASE-0003 structured |

## Tuning

| Path | What it shows |
|---|---|
| `phase6/evidence/TUNING_RATIONALE.txt` | Why DET-001 was noisy; exactly what was changed; the tunings **refused**; residual risk |
| `phase6/evidence/t2_false_positive_baseline.txt` | Field-by-field account of the 38 benign WinRS alerts |
| `phase6/evidence/t6_comparison_phase5_vs_phase6.txt` | Phase 5 alerts joined to Phase 6 decisions (hit count unchanged at 39) |
| `phase6/evidence/t6_comparison_phase5_vs_phase6_live_join.txt` | Same join, live-run output |
| `phase6/evidence/t6_phase6_det001_v2_live_dc1.txt` | DET-001 v2 live classifications on the collector |
| `phase6/evidence/t6_phase6_det001_v2_replay.txt` | DET-001 v2 replay over preserved Phase 5 evidence |
| `phase6/evidence/t6_phase6_det002_lineage_live_dc1.txt` | DET-002 lineage output |
| `phase6/evidence/t6_phase6_correlation_live_dc1.txt` | CORR-001 output |
| `phase6/evidence/t7_failure_modes.txt` | Failure modes FM-1..FM-4 (offline report + live probe appendix) |
| `phase6/evidence/t7_fm_live_probe_dc1.txt` | Read-only live failure-mode probe (incl. the 2012 s Sysmon gap) |
| `phase6/analysis/replay_phase5_evidence.ps1` | Offline replay harness over preserved Phase 5 evidence |
| `phase6/analysis/failure_modes.ps1` | Offline failure-mode report generator |

## Blind-spot validation

| Path | What it shows |
|---|---|
| `phase7/PHASE7_REPORT.md` | Full Phase 7 report — `OUTCOME B — blind spot confirmed` |
| `phase7/evidence/t1_preflight_blindspot_check.txt` | Static check: payload command line does not match the DET-001 trigger |
| `phase7/evidence/t3_controlled_execution_ws001.txt` | The single controlled execution + its output |
| `phase7/evidence/t4_local_telemetry_ws001_controlled.txt` | Local telemetry for the controlled window |
| `phase7/evidence/t5_central_telemetry_dc1_controlled.txt` | Central `ForwardedEvents` for the same 14 events |
| `phase7/evidence/t6_det001_controlled.txt` | DET-001 v2 result: miss (transport baselined) |
| `phase7/evidence/t6_det002_controlled.txt` | DET-002 result: context only |
| `phase7/evidence/t6_corr001_controlled.txt` | CORR-001 result: no correlation |
| `phase7/evidence/t6_detection_stack_controlled.txt` | Whole-stack run output |
| `phase7/evidence/t7_baseline_comparison.txt` | Baseline-drift check (22/22 wrappers matched `BASE-01`) |
| `phase7/evidence/t8_process_lineage.txt` | Payload lineage (depth 3, PID 1428) |
| `phase7/evidence/t9_detection_result.txt` / `.json` | Derived detection result |
| `phase7/evidence/t9_integrity_and_cleanup.txt` | Post-run integrity + temp cleanup |
| `phase7/evidence/t11_limitations.txt` | Phase 7 limitations |
| `phase7/evidence/raw/t4_raw_local_ws001_controlled.txt` | Preserved raw local XML (Phase 8 replay input) |
| `phase7/evidence/raw/t5_raw_central_dc1_controlled.txt` | Preserved raw central XML (Phase 8 replay input) |

## Phase 8 detection validation

| Path | What it shows |
|---|---|
| `phase8/PHASE8_REPORT.md` | Full Phase 8 report — DET-003 identifies the Phase 7 blind spot |
| `phase8/evidence/replay_inputs.txt` | Replay inputs + hashes (preserved Phase 7 files) |
| `phase8/evidence/replay_1_ws001_controlled.txt` | Replay: WS001 controlled view |
| `phase8/evidence/replay_4_dc1_forwarded_session.txt` | Replay: DC1 session view |
| `phase8/evidence/t05_benign_comparison.txt` | DET-003 vs a naive keyword rule on benign cases |
| `phase8/evidence/t07_live_validation.txt` | Single controlled live validation |
| `phase8/evidence/t08_local_telemetry_ws001.txt`, `t08b_det003_local_live.txt` | Live local telemetry + DET-003 result |
| `phase8/evidence/t09_central_telemetry_dc1.txt`, `t09b_det003_central_live.txt` | Live central telemetry + DET-003 result |
| `phase8/evidence/t12_false_positive_considerations.txt` | Observed benign behaviour (incl. `CTX-PLUMBING`) |
| `phase8/evidence/t13_limitations.txt` | DET-003 limitations |
| `phase8/evidence/t14_det001_vs_det003.txt` | DET-001 vs DET-003 trigger matrix (disjoint) |
| `phase8/evidence/t15_integrity.txt` | DET-001 v2 byte-identical; Phase 5/6/7 unchanged |

## Sigma

| Path | What it is |
|---|---|
| `phase9/sigma/SOC002-DET-001-encoded-powershell.yml` | Sigma rule (`9e77668f-116f-459b-80bf-4b6c4ba02ae7`; status experimental; level medium) |
| `phase9/sigma/SIGMA_NOTES.md` | What was preserved, what cannot be represented, limits |
| `phase9/sigma/SIGMA_VALIDATION_REPORT.md` | Validation results (61/61 structural checks) + pre/post integrity |
| `phase9/sigma/validate_sigma.ps1` | Offline structural validator |
| `phase9/sigma/README.md` | Overview and honest scope |

## KQL

| Path | What it is |
|---|---|
| `phase10/kql/SOC002-DET-001-encoded-powershell.kql` | Portable Sigma-faithful KQL translation |
| `phase10/kql/SOC002-DET-001-encoded-powershell-regex.kql` | KQL reproducing the original token-exact short-switch regex |
| `phase10/kql/KQL_NOTES.md` | Source-table assumption, operator rationale, portable-vs-regex difference, limits |
| `phase10/kql/KQL_VALIDATION_REPORT.md` | Validation results + pre/post integrity + no-backend-execution statement |
| `phase10/kql/validate_kql.ps1` | Offline static validator |
| `phase10/kql/README.md` | Overview and honest scope |

## Integrity

| Path | What it covers |
|---|---|
| `phase6/evidence/SHA256_MANIFEST.txt` | Phase 6 tree manifest (incl. Phase 5 preservation check) |
| `phase7/SHA256_MANIFEST.txt` | Phase 7 tree manifest (incl. Phase 5/6 preservation) |
| `phase8/SHA256_MANIFEST.txt` | Phase 8 tree manifest (incl. Phase 5/6/7 preservation) |
| `phase9/sigma/PRE_SIGMA_HASHES.txt` | Phase 9 pre-change baseline + recursive Phase 5–8 digest (225 files) |
| `phase9/sigma/SHA256_MANIFEST.txt` | Phase 9 artifact manifest |
| `phase10/kql/PRE_KQL_HASHES.txt` | Phase 10 pre-change baseline + recursive Phase 5–9 digest (232 files) |
| `phase10/kql/SHA256_MANIFEST.txt` | Phase 10 artifact manifest |
| `phase5/evidence/MANIFEST.txt` | Phase 5 file manifest with SHA256 |
| `phase4/evidence/MANIFEST.txt` | Phase 4 file manifest |
| `FINAL_INTEGRITY_REPORT.md` (this package) | Pre/post integrity of the Phase 5–10 sources at hand-off |
| `SHA256_MANIFEST.txt` (this package) | Hashes of the SOC-002 final documentation package |

## Reporting / narrative

| Path | What it is |
|---|---|
| `phase6/README.md` | Phase 6 report (detection hardening & correlation depth) |
| `phase7/PHASE7_REPORT.md` | Phase 7 report (blind-spot validation) |
| `phase8/PHASE8_REPORT.md` | Phase 8 report (DET-003) |
| `phase5/evidence/ATTACK_MAPPING.txt` | Evidence-bounded ATT&CK mapping |
| `PHASE5_PROMPT.txt` … `PHASE10_KQL_PROMPT.txt` | Phase specifications (scope/safety framing) |
