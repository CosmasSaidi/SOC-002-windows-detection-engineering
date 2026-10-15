#!/usr/bin/env bash
# SOC-002 Phase 8 - regenerate ALL offline Phase 8 evidence (read-only).
# Replays preserved Phase 7 telemetry, runs the benign comparison suite, and
# re-runs DET-003 over the Phase 8 live captures. Writes only under phase8/evidence.
set -u
cd "$HOME/soc-lab"
R=phase8/analysis/replay_phase8_phase7_evidence.ps1

replay () { # raw out json label
  pwsh -NoProfile -File "$R" -Raw "$1" -Out "$2" -JsonOut "$3" -Label "$4" >/dev/null
  echo "  replayed $1 -> $2"
}

echo "== Phase 7 replay (preserved evidence) =="
replay phase7/evidence/raw/t4_raw_local_ws001_controlled.txt   phase8/evidence/replay_1_ws001_controlled.txt        phase8/evidence/replay_1_ws001_controlled.json        "phase7 WS001 local controlled window"
replay phase7/evidence/raw/t5_raw_central_dc1_controlled.txt   phase8/evidence/replay_2_dc1_forwarded_controlled.txt phase8/evidence/replay_2_dc1_forwarded_controlled.json "phase7 DC1 ForwardedEvents controlled window"
replay phase7/evidence/raw/t4b_raw_local_ws001_session.txt     phase8/evidence/replay_3_ws001_session.txt            phase8/evidence/replay_3_ws001_session.json            "phase7 WS001 local session window"
replay phase7/evidence/raw/t5b_raw_central_dc1_session.txt     phase8/evidence/replay_4_dc1_forwarded_session.txt     phase8/evidence/replay_4_dc1_forwarded_session.json     "phase7 DC1 ForwardedEvents session window"

echo "== Phase 8 live-capture replay =="
replay phase8/evidence/raw/p8_raw_local_ws001.txt   phase8/evidence/t08b_det003_local_live.txt    phase8/evidence/t08b_det003_local_live.json    "PHASE 8 live WS001 local capture"
replay phase8/evidence/raw/p8_raw_central_dc1.txt   phase8/evidence/t09b_det003_central_live.txt  phase8/evidence/t09b_det003_central_live.json  "PHASE 8 live DC1 ForwardedEvents capture"

echo "== Benign comparison suite =="
pwsh -NoProfile -File phase8/analysis/benign_comparison_phase8.ps1 >/dev/null
echo "  wrote phase8/evidence/t05_benign_comparison.txt"

echo "== Result summary =="
pwsh -NoProfile -File phase8/analysis/phase8_result_summary.ps1 >/dev/null
echo "  wrote phase8/evidence/t06_phase7_detection_result.txt"

echo "== Telemetry rendering =="
pwsh -NoProfile -File phase8/analysis/format_phase8_telemetry.ps1 -Raw phase8/evidence/raw/p8_raw_local_ws001.txt -Out phase8/evidence/t08_local_telemetry_ws001.txt >/dev/null
pwsh -NoProfile -File phase8/analysis/format_phase8_telemetry.ps1 -Raw phase8/evidence/raw/p8_raw_central_dc1.txt -Out phase8/evidence/t09_central_telemetry_dc1.txt >/dev/null
echo "  wrote t08/t09 telemetry renderings"
echo "DONE"
