#!/usr/bin/env bash
set -euo pipefail
infile="$1"
outfile="$2"
ATTACKER='https://attacker.example'
PARAMS=(redirect next return url callback continue redirect_uri dest)
echo "[]" > "$outfile"

while read -r host; do
  [ -z "$host" ] && continue
  base="https://$host"
  for p in "${PARAMS[@]}"; do
    url="${base}/?${p}=${ATTACKER}"
    # HEAD then look at Location
    resp=$(curl -s -I -L --max-redirs 0 --write-out "HTTP_CODE:%{http_code}" "$url" 2>/dev/null || true)
    loc=$(echo "$resp" | awk '/^Location:/ {print substr($0,11)}' | tr -d '\r' || true)
    if [ -n "$loc" ]; then
      jq ". + [{host:\"$host\",param:\"$p\",location:\"$loc\"}]" "$outfile" > "$outfile.tmp" && mv "$outfile.tmp" "$outfile"
    fi
  done
done < "$infile"
echo "[+] redirects -> $outfile"
