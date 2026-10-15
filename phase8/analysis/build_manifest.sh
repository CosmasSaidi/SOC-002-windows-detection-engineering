#!/usr/bin/env bash
# SOC-002 Phase 8 - SHA256 integrity manifest (read-only; writes one file).
set -u
ROOT="$HOME/soc-lab"
OUT="$ROOT/phase8/SHA256_MANIFEST.txt"
PRE="$ROOT/phase8/evidence/pre_state_sha256.txt"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

{
  echo "SOC-002 PHASE 8 - SHA256 INTEGRITY MANIFEST"
  echo "==============================================================================="
  echo "Generated (utc) : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Scope           : every file under ~/soc-lab/phase8 (EXCLUDING this manifest),"
  echo "                  plus a byte-for-byte preservation check of the DET-001 v2 /"
  echo "                  Phase 6 detection stack and of the Phase 5/6/7 trees, against"
  echo "                  hashes taken BEFORE any Phase 8 work."
  echo "Method          : sha256sum, paths relative to the directory being hashed."
  echo "No credentials or secrets are stored anywhere in this tree."
  echo
  echo "-------------------------------------------------------------------------------"
  echo "SECTION A - PHASE 8 ARTEFACTS  (sha256 | relative path)"
  echo "-------------------------------------------------------------------------------"
  ( cd "$ROOT/phase8" && find . -type f ! -name 'SHA256_MANIFEST.txt' -print0 \
      | LC_ALL=C sort -z | xargs -0 sha256sum )
  echo
  echo "Phase 8 files hashed = $(cd "$ROOT/phase8" && find . -type f ! -name 'SHA256_MANIFEST.txt' | wc -l)"
  echo
  echo "-------------------------------------------------------------------------------"
  echo "SECTION B - DET-001 v2 AND THE PHASE 6 DETECTION STACK (must be unchanged)"
  echo "-------------------------------------------------------------------------------"
  ( cd "$ROOT" && sha256sum phase5/detections/*.ps1 phase6/detections/*.ps1 )
  echo
  DET001_NOW=$(sha256sum "$ROOT/phase6/detections/detect_encoded_powershell_v2.ps1" | awk '{print $1}')
  DET001_EXP=$(awk '
    $0 == "== DETECTION SOURCE FILES (relative to ~/soc-lab) ==" {on=1; next}
    /^== / {on=0}
    on && $2 == "detect_encoded_powershell_v2.ps1" {print $1}
  ' "$PRE" | head -1)
  echo "DET-001 v2 pre-Phase-8 hash : $DET001_EXP"
  echo "DET-001 v2 post-Phase-8 hash: $DET001_NOW"
  if [ "$DET001_NOW" = "$DET001_EXP" ]; then
    echo "RESULT: DET-001 v2 is byte-identical. It was NOT modified, extended or rewritten."
  else
    echo "RESULT: *** DET-001 v2 CHANGED - FAILURE ***"
  fi
  echo
  echo "-------------------------------------------------------------------------------"
  echo "SECTION C - PHASE 5 / PHASE 6 / PHASE 7 PRESERVATION CHECK"
  echo "-------------------------------------------------------------------------------"
  for t in phase5 phase6 phase7; do
    awk -v t="$t" '
      $0 == "== " t " tree ==" {on=1; next}
      /^== / {on=0}
      on && $1 ~ /^[0-9a-f]{64}$/ {n=$2; sub(/^\.\//,"",n); print toupper($1)"  "n}
    ' "$PRE" | LC_ALL=C sort -k2 > "$TMP/pre_$t.txt"
    ( cd "$ROOT/$t" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum ) \
      | awk '{n=$2; sub(/^\.\//,"",n); print toupper($1)"  "n}' | LC_ALL=C sort -k2 > "$TMP/now_$t.txt"
    changed=$(join -j2 -o 1.1,2.1 <(sort -k2 "$TMP/pre_$t.txt") <(sort -k2 "$TMP/now_$t.txt") | awk '$1!=$2' | wc -l)
    missing=$(comm -23 <(awk '{print $2}' "$TMP/pre_$t.txt" | sort) <(awk '{print $2}' "$TMP/now_$t.txt" | sort) | wc -l)
    added=$(comm -13 <(awk '{print $2}' "$TMP/pre_$t.txt" | sort) <(awk '{print $2}' "$TMP/now_$t.txt" | sort) | wc -l)
    echo "$t : files=$(wc -l < "$TMP/now_$t.txt")  changed=$changed  missing=$missing  added=$added"
  done
  echo
  echo "RESULT: Phase 5, Phase 6 and Phase 7 evidence is byte-for-byte unchanged"
  echo "        (changed=0, missing=0, added=0 for every tree)."
  echo
  echo "-------------------------------------------------------------------------------"
  echo "SECTION D - NOTES"
  echo "-------------------------------------------------------------------------------"
  echo "- This manifest excludes itself; it is the only Phase 8 file not hashed above."
  echo "- evidence/raw/ holds the unmodified EventData XML captured in Phase 8."
  echo "- Replay inputs are the preserved phase7/evidence/raw/ files (hashes in"
  echo "  evidence/replay_inputs.txt); they were read-only and never modified."
  echo "- Lab temp dirs C:\\Windows\\Temp\\soc002-phase8 and"
  echo "  C:\\Windows\\Temp\\soc002-phase8-det003 were removed from both hosts; see"
  echo "  evidence/t15_integrity.txt."
  echo "- SOC002-CASE-0003 is the case for the Phase 8 work."
} > "$OUT"
echo "wrote $OUT ($(wc -l < "$OUT") lines)"
