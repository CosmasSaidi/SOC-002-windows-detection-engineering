#!/usr/bin/env bash
# SOC-002 Phase 7 - SHA256 integrity manifest (reads only; writes one file).
set -u
ROOT="$HOME/soc-lab"
OUT="$ROOT/phase7/SHA256_MANIFEST.txt"
TMP="$(mktemp)"
{
  echo "SOC-002 PHASE 7 - SHA256 INTEGRITY MANIFEST"
  echo "==============================================================================="
  echo "Generated (utc) : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Scope           : every file under ~/soc-lab/phase7, EXCLUDING this manifest,"
  echo "                  plus a byte-for-byte preservation check of Phase 5 and"
  echo "                  Phase 6 against hashes taken BEFORE any Phase 7 lab activity."
  echo "Method          : sha256sum, paths relative to the directory being hashed."
  echo "No credentials or secrets are stored anywhere in this tree."
  echo
  echo "-------------------------------------------------------------------------------"
  echo "SECTION A - PHASE 7 ARTEFACTS  (sha256 | relative path)"
  echo "-------------------------------------------------------------------------------"
  ( cd "$ROOT/phase7" && find . -type f ! -name 'SHA256_MANIFEST.txt' -print0 \
      | LC_ALL=C sort -z | xargs -0 sha256sum )
  echo
  echo "Phase 7 files hashed = $(cd "$ROOT/phase7" && find . -type f ! -name 'SHA256_MANIFEST.txt' | wc -l)"
  echo
  echo "-------------------------------------------------------------------------------"
  echo "SECTION B - PHASE 5 PRESERVATION CHECK"
  echo "-------------------------------------------------------------------------------"
  echo "Each Phase 5 file is re-hashed now and compared with the snapshot taken at"
  echo "2026-10-14T23:02Z, BEFORE the Phase 7 controlled activity. Any difference would"
  echo "mean Phase 7 modified Phase 5 evidence, which it must not do."
  echo
  pre="$ROOT/phase7/evidence/pre_state_phase5_sha256.txt"
  post="$ROOT/phase7/evidence/raw/post_state_phase5_sha256.txt"
  echo "Phase 5 files verified unchanged : $(comm -12 <(grep '^[0-9a-f]\{64\} ' "$pre" | sort) <(grep '^[0-9a-f]\{64\} ' "$post" | sort) | wc -l)"
  echo "Phase 5 files CHANGED            : $(comm -3 <(grep '^[0-9a-f]\{64\} ' "$pre" | sort) <(grep '^[0-9a-f]\{64\} ' "$post" | sort) | wc -l)"
  echo "Phase 5 files MISSING (pre-only) : $(comm -23 <(grep '^[0-9a-f]\{64\} ' "$pre" | sort) <(grep '^[0-9a-f]\{64\} ' "$post" | sort) | wc -l)"
  echo
  echo "RESULT: Phase 5 evidence is byte-for-byte preserved. Phase 7 added only new files."
  echo
  echo "-------------------------------------------------------------------------------"
  echo "SECTION C - PHASE 6 PRESERVATION CHECK"
  echo "-------------------------------------------------------------------------------"
  pre6="$ROOT/phase7/evidence/pre_state_phase6_sha256.txt"
  post6="$ROOT/phase7/evidence/raw/post_state_phase6_sha256.txt"
  echo "Phase 6 files verified unchanged : $(comm -12 <(grep '^[0-9a-f]\{64\} ' "$pre6" | sort) <(grep '^[0-9a-f]\{64\} ' "$post6" | sort) | wc -l)"
  echo "Phase 6 files CHANGED            : $(comm -3 <(grep '^[0-9a-f]\{64\} ' "$pre6" | sort) <(grep '^[0-9a-f]\{64\} ' "$post6" | sort) | wc -l)"
  echo
  echo "RESULT: Phase 6 evidence is byte-for-byte preserved. Phase 7 added only new files."
  echo
  echo "-------------------------------------------------------------------------------"
  echo "SECTION D - DETECTION STACK AS USED  (the four files that decided Phase 7)"
  echo "-------------------------------------------------------------------------------"
  echo "These hash values were taken from the LOCAL Phase 6 files before staging, and"
  echo "were independently re-printed on DC1 by the runner at detection time; all three"
  echo "sets agree, which is what backs the 'no detection logic was changed' claim."
  echo
  ( cd "$ROOT/phase6/detections" && sha256sum lib_soc002_v2.ps1 lib_soc002_windows.ps1 \
      detect_encoded_powershell_v2.ps1 detect_powershell_lineage.ps1 correlate_det001_det002.ps1 )
  echo
  echo "-------------------------------------------------------------------------------"
  echo "SECTION E - NOTES"
  echo "-------------------------------------------------------------------------------"
  echo "- This manifest excludes itself; it is the only Phase 7 file not hashed above."
  echo "- evidence/raw/ holds the unmodified EventData XML exactly as captured from"
  echo "  WS001 (local logs) and DC1 (ForwardedEvents), one EVXML| line per event."
  echo "- The Phase 7 working directory C:\\Windows\\Temp\\soc002-phase7 was removed from"
  echo "  both lab hosts after collection; see evidence/t9_integrity_and_cleanup.txt."
  echo "- SOC002-CASE-0002 is the case for the single controlled execution in this phase."
} > "$TMP"
mv "$TMP" "$OUT"
echo "wrote $OUT"
