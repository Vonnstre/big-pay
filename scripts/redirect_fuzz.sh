#!/usr/bin/env bash
set -euo pipefail
target="$1"
tdir="findings/$target"
params_file="$tdir/params.json"
endpoints="$tdir/endpoints.json"
out="$tdir/redirects.json"
[ -s "$endpoints" ] || { echo "no endpoints"; exit 0; }
EVIL="https://evil.example.com/callback"
jq -r '.[]' "$endpoints" | while read -r base; do
  for p in $(jq -r '.[]' "$params_file"); do
    url="${base}?${p}=$(python3 -c "import urllib.parse;print(urllib.parse.quote('$EVIL',safe=''))")"
    resp=$(curl -sSI -m 12 -L --max-redirs 0 "$url" || true)
    code=$(echo "$resp" | awk 'NR==1{print $2}')
    loc=$(echo "$resp" | awk 'tolower($0) ~ /^location:/{sub(/^[^:]*:[ ]*/,"");print;exit}')
    if [[ "$code" =~ 30[127] ]] && [[ "$loc" == *"evil.example.com"* ]]; then
      echo "{\"url\":\"$base\",\"param\":\"$p\",\"location\":\"$loc\",\"code\":\"$code\"}"
    fi
  done
done | jq -s '.' > "$out"
