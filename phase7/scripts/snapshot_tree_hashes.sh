#!/usr/bin/env bash
# SOC-002 Phase 7 - SHA256 snapshot of a preserved tree (read-only).
# usage: snapshot_tree_hashes.sh <dir> <outfile> <label>
set -u
dir="$1"; out="$2"; label="$3"
{
  echo "# $label"
  echo "# tree: $dir"
  echo "# snapshot utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# files: $(find "$dir" -type f | wc -l)"
  echo "# format: <sha256>  <relative path>"
  echo "--------------------------------------------------------------------------------"
  ( cd "$dir" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum )
} > "$out"
echo "$label -> $out ($(grep -c '^[0-9a-f]\{64\} ' "$out") hashed)"
