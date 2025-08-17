#!/usr/bin/env bash
set -euo pipefail

# Aggressive, wide-scope recon funnel.
# Requires SCAN_CONFIRM="True" (set by workflow input).

# Tunables (override via env)
GLOBAL_CONCURRENCY="${GLOBAL_CONCURRENCY:-8}"
PER_TARGET_CONCURRENCY="${PER_TARGET_CONCURRENCY:-8}"
HTTPX_THREADS="${HTTPX_THREADS:-200}"
HTTPX_TIMEOUT="${HTTPX_TIMEOUT:-10}"
NUCLEI_THREADS="${NUCLEI_THREADS:-120}"
NUCLEI_RATE_LIMIT="${NUCLEI_RATE_LIMIT:-140}"
NUCLEI_SEVERITY="${NUCLEI_SEVERITY:-low,medium,high,critical}"
AMASS_TIMEOUT_MIN="${AMASS_TIMEOUT_MIN:-8}"

SCAN_CONFIRM="${SCAN_CONFIRM:-False}"

root() { realpath "$(dirname "$0")/.."; }
REPO_ROOT="$(root)"

cd "$REPO_ROOT"

# Safety gate
if [[ "$SCAN_CONFIRM" != "True" ]]; then
  echo "[!] SCAN_CONFIRM must be exactly 'True'. Aborting."
  exit 1
fi

# Tool sanity (soft for optional tools)
need() { command -v "$1" >/dev/null 2>&1 || { echo "[!] Missing required tool: $1"; exit 1; }; }
need jq
need python3
# subfinder/amass/httpx/nuclei are optional but recommended
for opt in subfinder amass httpx nuclei; do
  command -v "$opt" >/dev/null 2>&1 || echo "[i] Optional tool not found: $opt (continuing)"
done

mkdir -p out findings logs
: > out/summary.txt

# Load roots
mapfile -t ROOTS < <(grep -vE '^\s*(#|$)' hosts.txt | sed 's/\r$//' | sort -u)
if [[ ${#ROOTS[@]} -eq 0 ]]; then
  echo "[!] hosts.txt is empty."
  exit 1
fi

ensure_dir() { mkdir -p "$@"; }

scan_one() {
  target="$1"
  safe="$(echo "$target" | sed 's#[^A-Za-z0-9._-]#_#g')"
  work="out/$safe"
  fdir="findings/$safe"
  ensure_dir "$work" "$fdir"

  echo "[+] START $target"

  # ---------- 1) Subdomain discovery (volume) ----------
  : > "$work/all_subs.raw"
  if command -v subfinder >/dev/null 2>&1; then
    subfinder -d "$target" -all -silent >> "$work/all_subs.raw" || true
  fi
  if command -v amass >/dev/null 2>&1; then
    amass enum -passive -d "$target" -timeout "${AMASS_TIMEOUT_MIN}m" -silent >> "$work/all_subs.raw" || true
  fi
  # seed likely environments
  printf "%s\n" \
    "admin.$target" "internal.$target" "staging.$target" "preview.$target" \
    "dev.$target" "qa.$target" "test.$target" "uat.$target" "beta.$target" \
    "sandbox.$target" "canary.$target" >> "$work/all_subs.raw"

  sort -u "$work/all_subs.raw" | sed '/^$/d' > "$work/subs.txt"
  echo "[*] ${target}: subs=$(wc -l < "$work/subs.txt")"

  # Bail early if nothing
  if [[ ! -s "$work/subs.txt" ]]; then
    echo "[-] No subs for $target"
    return 0
  }

  # ---------- 2) Probe & filter with httpx ----------
  echo "[]" > "$work/httpx.jsonl"
  if command -v httpx >/dev/null 2>&1; then
    # httpx writes JSON lines with -json
    httpx -l "$work/subs.txt" -silent -threads "$HTTPX_THREADS" -timeout "$HTTPX_TIMEOUT" \
      -follow-redirects -no-color -status-code -title -tech-detect -ip -websocket -json \
      > "$work/httpx.jsonl" || true
  else
    # fallback: synthesize URLs so later steps still run
    awk '{print "https://" $0 "/"}' "$work/subs.txt" | jq -R '{url: .}' > "$work/httpx.jsonl"
  fi

  # Keep unique URLs, prefer 200-399, drop obvious noise
  jq -r '
    select(.url!=null)
    | select((.status_code|tonumber? // 0) > 0)
    | .url' "$work/httpx.jsonl" \
    | awk '!seen[$0]++' > "$work/alive.urls"

  echo "[*] ${target}: alive=$(wc -l < "$work/alive.urls")"

  # ---------- 3) Smart filter (your Python) ----------
  python3 scripts/smart_hunt.py \
    --target "$target" \
    --httpx-json "$work/httpx.jsonl" \
    --outdir "$fdir" \
    --per-target "$PER_TARGET_CONCURRENCY" || true

  # ---------- 4) Nuclei (optional, folded into findings) ----------
  if command -v nuclei >/dev/null 2>&1 && [[ -s "$work/alive.urls" ]]; then
    nuclei -l "$work/alive.urls" \
      -severity "$NUCLEI_SEVERITY" \
      -rl "$NUCLEI_RATE_LIMIT" -c "$NUCLEI_THREADS" \
      -retries 1 -no-meta -json -silent \
      -o "$work/nuclei.jsonl" || true

    python3 scripts/smart_hunt.py \
      --target "$target" \
      --nuclei-json "$work/nuclei.jsonl" \
      --outdir "$fdir" \
      --fold-nuclei || true
  fi

  # Append target summary
  [[ -f "$fdir/summary.txt" ]] && cat "$fdir/summary.txt" >> out/summary.txt

  echo "[+] DONE $target"
}

export -f scan_one
export PER_TARGET_CONCURRENCY

printf "%s\n" "${ROOTS[@]}" | xargs -n1 -P "$GLOBAL_CONCURRENCY" -I{} bash -c 'scan_one "$@"' _ {}

echo
echo "===== RUN SUMMARY ====="
[[ -f out/summary.txt ]] && cat out/summary.txt || echo "No findings."
