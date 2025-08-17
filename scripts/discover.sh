#!/usr/bin/env bash
set -euo pipefail
targets_file="${1:-hosts.txt}"
mkdir -p findings
while read -r root; do
  [ -z "$root" ] && continue
  outdir="findings/$root"; mkdir -p "$outdir"
  echo "[*] discovery => $outdir/subs.txt"
  # quick passive subs
  subfinder -silent -d "$root" | dnsx -silent -a -resp-only | sort -u > "$outdir/subs.txt" || true
  # probe live
  cat "$outdir/subs.txt" | httpx -silent -threads 200 -status-code -title -json > "$outdir/httpx.json" || true
  jq -r 'select(.failed|not) | .url' "$outdir/httpx.json" 2>/dev/null | sort -u > "$outdir/live.txt" || true
done < "$targets_file"
