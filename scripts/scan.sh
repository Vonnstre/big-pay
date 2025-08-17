#!/usr/bin/env bash
set -euo pipefail

# Config — aggressive but survivable
GLOBAL_CONCURRENCY="${GLOBAL_CONCURRENCY:-40}"
PER_TARGET_CONCURRENCY="${PER_TARGET_CONCURRENCY:-6}"
NUCLEI_SEVERITY="${NUCLEI_SEVERITY:-low,medium,high,critical}"
NUCLEI_RATE_LIMIT="${NUCLEI_RATE_LIMIT:-180}"   # requests/sec
NUCLEI_THREADS="${NUCLEI_THREADS:-80}"
TIMEOUT="${TIMEOUT:-12}"                        # amass timeout minutes per domain

mkdir -p out findings state
: > out/summary.txt

echo "[+] Using $(nproc) cores; per-target concurrency ${PER_TARGET_CONCURRENCY}; global ${GLOBAL_CONCURRENCY}"

parallel --version >/dev/null 2>&1 || { echo "[*] installing parallel"; sudo apt-get update -y && sudo apt-get install -y parallel >/dev/null; }

# Build a worklist from hosts.txt (dedupe, strip blanks)
mapfile -t ROOTS < <(grep -vE '^\s*(#|$)' hosts.txt | sed 's/\r$//' | sort -u)

scan_one() {
  root="$1"
  safe_root="$(echo "$root" | tr '/:' '_')"
  work="out/$safe_root"
  finddir="findings/$safe_root"
  mkdir -p "$work" "$finddir"

  echo "[+] START $root"

  # 1) Discovery (passive + a tiny brute on common envs)
  #    We keep it bounded to avoid explosions.
  amass enum -passive -d "$root" -timeout ${TIMEOUT}m -silent -o "$work/subs.passive.txt" || true

  # Seed obvious staging/canary subs
  for p in staging dev qa test uat preview canary int internal beta alpha sandbox; do
    echo "$p.$root"
  done | tee "$work/seed.txt" >/dev/null

  sort -u "$work/subs.passive.txt" "$work/seed.txt" | sed '/^$/d' > "$work/subs.txt"

  # 2) Probe with httpx (collect JSON for smart checks)
  httpx -l "$work/subs.txt" -silent -follow-host-redirects -status-code -tech-detect -title -json \
        -probe -threads 150 -timeout 8 -retries 1 > "$work/httpx.json" || true
  jq -r 'select(.url!=null) | .url' "$work/httpx.json" | sed 's#/*$##' > "$work/alive.txt" || true

  echo "[+] $(wc -l < "$work/alive.txt") live URLs for $root"

  # 3) Smart checks (CORS creds, auth-redirects, takeover, panels)
  python3 smart_hunt.py \
      --domain "$root" \
      --httpx-json "$work/httpx.json" \
      --alive "$work/alive.txt" \
      --outdir "$finddir" \
      --per-target "$PER_TARGET_CONCURRENCY"

  # 4) Nuclei (selected classes; templates auto-updated in workflow)
  nuclei -l "$work/alive.txt" \
      -severity "$NUCLEI_SEVERITY" \
      -rl "$NUCLEI_RATE_LIMIT" -c "$NUCLEI_THREADS" -retries 1 -bulk-size 50 \
      -json -stats -no-meta -o "$work/nuclei.json" || true

  # 5) Fold nuclei hits into the same evidence pack (lightweight parse)
  python3 smart_hunt.py \
      --domain "$root" \
      --nuclei-json "$work/nuclei.json" \
      --outdir "$finddir" \
      --fold-nuclei

  # 6) Per-target summary
  if [ -f "$finddir/summary.txt" ]; then
    cat "$finddir/summary.txt" >> out/summary.txt
  fi

  echo "[+] DONE $root"
}

export -f scan_one
export TIMEOUT NUCLEI_THREADS NUCLEI_RATE_LIMIT NUCLEI_SEVERITY PER_TARGET_CONCURRENCY

# Run with limited parallelism across roots
printf "%s\n" "${ROOTS[@]}" | parallel -j "$GLOBAL_CONCURRENCY" --no-notice scan_one {}

echo
echo "======== RUN SUMMARY ========"
cat out/summary.txt || true
