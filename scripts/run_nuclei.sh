#!/usr/bin/env bash
set -euo pipefail
ENDPOINT_FILE="$1"
OUTDIR="$2"
TEMPLATES_DIR="nuclei-templates/cors-redirect-s3"

mkdir -p "$OUTDIR"
if ! command -v nuclei >/dev/null 2>&1; then
  echo "[!] nuclei not installed - skipping"
  exit 0
fi

jq -r 'keys[]' "$ENDPOINT_FILE" > "$OUTDIR/nuclei_hosts.txt" || true
nuclei -l "$OUTDIR/nuclei_hosts.txt" -t "$TEMPLATES_DIR" -o "$OUTDIR/nuclei_raw.txt" -rate-limit 200 -c 6 || true
[ -f "$OUTDIR/nuclei_raw.txt" ] && awk 'NF' "$OUTDIR/nuclei_raw.txt" > "$OUTDIR/nuclei.txt" || true
echo "[+] nuclei done"
