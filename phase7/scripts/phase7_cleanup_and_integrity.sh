#!/usr/bin/env bash
# SOC-002 Phase 7 - post-run integrity check and lab temp cleanup.
set -u
OUT=evidence/t9_integrity_and_cleanup.txt
{
  echo "### PHASE 7 POST-RUN INTEGRITY + CLEANUP ###"
  echo "run utc : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  echo "--- staged files still present on the lab hosts (before removal) ---"
} > "$OUT"
SOC002_DC1=192.168.56.102 python3 ../phase6/tools/dc1_ops.py ps \
  "Get-ChildItem 'C:\Windows\Temp\soc002-phase7' -Recurse -File | ForEach-Object { '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 \$_.FullName).Hash, \$_.FullName }" \
  2>&1 | grep -v -e Cryptography -e 'arc4 =' >> "$OUT"
{
  echo
  echo "--- removing Phase 7 temp working directories from both hosts ---"
} >> "$OUT"
SOC002_DC1=192.168.56.102 python3 ../phase6/tools/dc1_ops.py rm 'C:\Windows\Temp\soc002-phase7' 2>&1 | grep -v -e Cryptography -e 'arc4 =' >> "$OUT"
python3 ../phase6/tools/dc1_ops.py rm 'C:\Windows\Temp\soc002-phase7' 2>&1 | grep -v -e Cryptography -e 'arc4 =' >> "$OUT"
{
  echo
  echo "--- Phase 5 / Phase 6 preservation re-check (post) ---"
} >> "$OUT"
scripts/snapshot_tree_hashes.sh ~/soc-lab/phase5 evidence/raw/post_state_phase5_sha256.txt "POST-STATE PHASE 5" >/dev/null
scripts/snapshot_tree_hashes.sh ~/soc-lab/phase6 evidence/raw/post_state_phase6_sha256.txt "POST-STATE PHASE 6" >/dev/null
for ph in phase5 phase6; do
  pre=evidence/pre_state_${ph}_sha256.txt
  [ "$ph" = phase5 ] && pre=evidence/pre_state_phase5_sha256.txt
  post=evidence/raw/post_state_${ph}_sha256.txt
  # strip the 5 header lines before comparing
  if diff <(grep '^[0-9a-f]\{64\} ' "$pre" | sort) <(grep '^[0-9a-f]\{64\} ' "$post" | sort) >/dev/null; then
    echo "  $ph : UNCHANGED ($(grep -c '^[0-9a-f]\{64\} ' "$post") files re-hashed, 0 differences)" >> "$OUT"
  else
    echo "  $ph : DIFFERENCES FOUND - see below" >> "$OUT"
    diff <(grep '^[0-9a-f]\{64\} ' "$pre" | sort) <(grep '^[0-9a-f]\{64\} ' "$post" | sort) >> "$OUT"
  fi
done
cat "$OUT"
