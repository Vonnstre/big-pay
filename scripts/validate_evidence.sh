#!/usr/bin/env bash
set -euo pipefail
if [ -z "${1-}" ]; then echo "Usage: $0 <evidence.zip>"; exit 2; fi
ZIP="$1"
TMP=$(mktemp -d)
unzip -q "$ZIP" -d "$TMP"
[ -f "$TMP/meta.json" ] || (echo "meta.json missing"; exit 3)
# fail if long tokens present
if grep -R --line-number -E "[A-Za-z0-9_\\-]{40,}" "$TMP" >/dev/null 2>&1; then
  echo "[!] potential token-like strings found - manual redact needed"; exit 4
fi
echo "[+] evidence validated"
rm -rf "$TMP"
