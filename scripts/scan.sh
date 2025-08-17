#!/usr/bin/env bash
set -euo pipefail
# scan.sh — aggressive funnel (requires SCAN_CONFIRM="True" when run from workflow)

# Configurable (tune via env)
GLOBAL_CONCURRENCY="${GLOBAL_CONCURRENCY:-6}"
PER_TARGET_CONCURRENCY="${PER_TARGET_CONCURRENCY:-6}"
HTTPX_THREADS="${HTTPX_THREADS:-40}"
HTTPX_TIMEOUT="${HTTPX_TIMEOUT:-8}"
NUCLEI_SEVERITY="${NUCLEI_SEVERITY:-low,medium,high,critical}"
NUCLEI_RATE_LIMIT="${NUCLEI_RATE_LIMIT:-80}"
NUCLEI_THREADS="${NUCLEI_THREADS:-40}"
AMASS_TIMEOUT_MIN="${AMASS_TIMEOUT_MIN:-6}"

# Safety: must explicitly confirm in manual workflow with the exact string "True"
SCAN_CONFIRM="${SCAN_CONFIRM:-False}"

# Basic paths
mkdir -p out findings state logs
: > out/summary.txt

echo "[*] Starting funnel. GLOBAL_CONCURRENCY=${GLOBAL_CONCURRENCY}"

# Require exact confirmation
if [[ "${SCAN_CONFIRM}" != "True" ]]; then
  echo "[!] SCAN_CONFIRM not set to the exact string 'True'."
  echo "    When running the GitHub workflow manually, type True into the 'confirm' input."
  echo "    Locally you can export SCAN_CONFIRM=True before running."
  exit 1
fi

# Basic required tools check (fail early)
required=(jq xargs amass)
for t in "${required[@]}"; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "[!] Required tool missing: $t. Install before running."
    exit 1
  fi
done

# load hosts (one per line)
mapfile -t ROOTS < <(grep -vE '^\s*(#|$)' hosts.txt | sed 's/\r$//' | sort -u)
if [[ ${#ROOTS[@]} -eq 0 ]]; then
  echo "[!] hosts.txt is empty - provide targets and retry."
  exit 1
fi

# helper to ensure directories and safe names
ensure_dir() { mkdir -p "$1"; }

# per-target scan function
scan_one() {
  target="$1"
  safe="$(echo "$target" | sed 's#[/:]#_#g')"
  work="out/$safe"
  finddir="findings/$safe"
  ensure_dir "$work" "$finddir"

  echo "[+] START $target"

  # 1) passive discovery (bounded)
  amass enum -passive -d "$target" -timeout "${AMASS_TIMEOUT_MIN}m" -silent -o "$work/subs.passive.txt" || true

  # seed common staging hosts
  for p in staging dev qa test uat preview canary int internal beta alpha sandbox; do
    echo "https://$p.$target"
  done | sort -u > "$work/seed.txt"

  # merge subs
  cat "$work/subs.passive.txt" "$work/seed.txt" 2>/dev/null | sort -u | sed '/^$/d' > "$work/subs.txt" || true

  # 2) probe with httpx (if installed)
  if command -v httpx >/dev/null 2>&1; then
    echo "[*] httpx probing ${target}"
    httpx -l "$work/subs.txt" -silent -follow-host-redirects -status-code -tech-detect -title -json \
      -threads "$HTTPX_THREADS" -timeout "$HTTPX_TIMEOUT" -retries 1 > "$work/httpx.json" || true
  else
    : > "$work/httpx.json"
  fi

  # 3) smart checks (CORS, redirects, takeover, admin)
  python3 smart_hunt.py --target "$target" --httpx-json "$work/httpx.json" --outdir "$finddir" --per-target "$PER_TARGET_CONCURRENCY"

  # 4) nuclei (if available)
  if command -v nuclei >/dev/null 2>&1; then
    echo "[*] running nuclei for ${target}"
    jq -r 'select(.url!=null) | .url' "$work/httpx.json" 2>/dev/null | sed 's#/*$##' > "$work/alive.txt" || echo "https://$target" > "$work/alive.txt"
    nuclei -l "$work/alive.txt" -severity "$NUCLEI_SEVERITY" -rl "$NUCLEI_RATE_LIMIT" -c "$NUCLEI_THREADS" -retries 1 -bulk-size 50 -json -stats -no-meta -o "$work/nuclei.json" || true
    python3 smart_hunt.py --domain "$target" --nuclei-json "$work/nuclei.json" --outdir "$finddir" --fold-nuclei
  fi

  # append per-target summary
  if [[ -f "$finddir/summary.txt" ]]; then
    cat "$finddir/summary.txt" >> out/summary.txt
  fi

  echo "[+] DONE $target"
}

export -f scan_one

# run with limited parallelism (xargs)
printf "%s\n" "${ROOTS[@]}" | xargs -n1 -P "$GLOBAL_CONCURRENCY" -I{} bash -c 'scan_one "$@"' _ {}

echo; echo "======== RUN SUMMARY ========"; cat out/summary.txt || true
