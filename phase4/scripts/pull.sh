#!/usr/bin/env bash
# pull.sh <host> <remote-path> <local-path>
host="$1"; rpath="$2"; lpath="$3"
b64=$(python3 scripts/wr.py "$host" "\$b=[Convert]::ToBase64String([IO.File]::ReadAllBytes('$rpath')); Write-Output \$b" --inline 2>/dev/null | tr -d '\r' | grep -E '^[A-Za-z0-9+/=]{16,}$' | head -1)
if [ -z "$b64" ]; then echo "FAILED to pull $rpath" >&2; exit 1; fi
mkdir -p "$(dirname "$lpath")"
printf '%s' "$b64" | base64 -d > "$lpath"
echo "pulled $rpath -> $lpath ($(wc -c < "$lpath") bytes)"
