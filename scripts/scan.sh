#!/usr/bin/env bash
set -euo pipefail

echo "[*] scan.sh starting..."

# Validate confirmation
if [ "${SCAN_CONFIRM-}" != "True" ]; then
  echo "ERROR: SCAN_CONFIRM is not 'True'. Aborting."
  exit 1
fi

# Paths check
for f in hosts.txt smart_hunt.py vendor_fingerprints.py; do
  if [ ! -f "$f" ]; then
    echo "ERROR: Required file '$f' missing."
    exit 1
  fi
done

# Set defaults
GLOBAL_CONCURRENCY="${GLOBAL_CONCURRENCY:-6}"
PER_TARGET_CONCURRENCY="${PER_TARGET_CONCURRENCY:-6}"
HTTPX_THREADS="${HTTPX_THREADS:-40}"
HTTPX_TIMEOUT="${HTTPX_TIMEOUT:-8}"
NUCLEI_SEVERITY="${NUCLEI_SEVERITY:-low,medium,high,critical}"
NUCLEI_RATE_LIMIT="${NUCLEI_RATE_LIMIT:-80}"
NUCLEI_THREADS="${NUCLEI_THREADS:-40}"
AMASS_TIMEOUT_MIN="${AMASS_TIMEOUT_MIN:-6}"

# Prepare outputs
mkdir -p out findings state logs
: > out/summary.txt

# Load targets
mapfile -t ROOTS < <(grep -vE '^\s*(#|$)' hosts.txt | sed 's/\r$//' | sort -u)
if [ ${#ROOTS[@]} -eq 0 ]; then
  echo "ERROR: hosts.txt is empty."
  exit 1
fi

# scan_one function
scan_one() {
  root="$1"
  safe="$(echo "$root" | sed 's#[/:]#_#g')"
  work="out/$safe"
  findir="findings/$safe"
  mkdir -p "$work" "$findir"

  echo "[+] START $root"

  amass enum -passive -d "$root" -timeout "${AMASS_TIMEOUT_MIN}m" -silent -o "$work/subs.passive.txt" || true

  for p in staging dev qa test uat preview canary int internal beta alpha sandbox; do
    echo "https://$p.$root"
  done | sort -u > "$work/seed.txt"

  cat "$work/subs.passive.txt" "$work/seed.txt" | sort -u | sed '/^$/d' > "$work/subs.txt" || true

  if command -v httpx >/dev/null 2>&1; then
    echo "[*] httpx probing: $root"
    httpx -l "$work/subs.txt" -silent -follow-host-redirects -status-code -tech-detect -title -json \
      -threads "$HTTPX_THREADS" -timeout "$HTTPX_TIMEOUT" -retries 1 > "$work/httpx.json" || true
  else
    echo "[*] httpx not installed; skipping probing"
    : > "$work/httpx.json"
  fi

  python3 smart_hunt.py --target "$root" --httpx-json "$work/httpx.json" --outdir "$findir" --per-target "$PER_TARGET_CONCURRENCY"

  if command -v nuclei >/dev/null 2>&1; then
    echo "[*] Running nuclei on: $root"
    jq -r 'select(.url!=null) | .url' "$work/httpx.json" 2>/dev/null | sed 's#/*$##' > "$work/alive.txt" || echo "https://$root" > "$work/alive.txt"
    nuclei -l "$work/alive.txt" -severity "$NUCLEI_SEVERITY" -rl "$NUCLEI_RATE_LIMIT" -c "$NUCLEI_THREADS" -retries 1 -bulk-size 50 -json -stats -no-meta -o "$work/nuclei.json" || true
    python3 smart_hunt.py --domain "$root" --nuclei-json "$work/nuclei.json" --outdir "$findir" --fold-nuclei
  else
    echo "[*] nuclei not installed; skipping nuclei scanning"
  fi

  if [ -f "$findir/summary.txt" ]; then
    cat "$findir/summary.txt" >> out/summary.txt
  fi

  echo "[+] DONE $root"
}

export -f scan_one

printf "%s\n" "${ROOTS[@]}" | xargs -n1 -P "$GLOBAL_CONCURRENCY" -I{} bash -c 'scan_one "$@"' _ {}

echo; echo "===== RUN SUMMARY ====="; cat out/summary.txt || true
