#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# guard (must type True manually on dispatch)
SCAN_CONFIRM="${SCAN_CONFIRM:-False}"
if [[ "$SCAN_CONFIRM" != "True" ]]; then
  echo "[!] Aborting: you must type the exact string 'True' when dispatching the workflow."
  exit 1
fi

# config (override via env on dispatch)
GLOBAL_CONCURRENCY="${GLOBAL_CONCURRENCY:-8}"
PER_TARGET_CONCURRENCY="${PER_TARGET_CONCURRENCY:-10}"
AMASS_TIMEOUT_MIN="${AMASS_TIMEOUT_MIN:-8}"
SUBFINDER_SOURCES="${SUBFINDER_SOURCES:-all}"
DNSX_WORKERS="${DNSX_WORKERS:-200}"
HTTPX_THREADS="${HTTPX_THREADS:-120}"
HTTPX_TIMEOUT="${HTTPX_TIMEOUT:-8}"
NUCLEI_SEVERITY="${NUCLEI_SEVERITY:-low,medium,high,critical}"
NUCLEI_THREADS="${NUCLEI_THREADS:-100}"
NUCLEI_RATE_LIMIT="${NUCLEI_RATE_LIMIT:-180}"
MAX_URLS_PER_HOST="${MAX_URLS_PER_HOST:-2000}"
PATH_CHECK_TOP_HOSTS="${PATH_CHECK_TOP_HOSTS:-150}"

mkdir -p out findings state logs
: > out/summary.txt

# tool check (fail early if essential tools missing)
need=(jq subfinder dnsx httpx)
for t in "${need[@]}"; do
  command -v "$t" >/dev/null 2>&1 || { echo "[!] missing tool: $t"; exit 1; }
done

# optional warnings
for t in nuclei amass ffuf; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "::warning:: optional tool missing: $t"
  fi
done

# load roots
if [[ ! -f "hosts.txt" ]]; then
  echo "[!] hosts.txt missing in repo root"
  exit 1
fi

mapfile -t ROOTS < <(grep -vE '^\s*(#|$)' hosts.txt | sed 's/\r$//' | tr ' ' '\n' | sed '/^$/d' | sort -u)
((${#ROOTS[@]})) || { echo "[!] hosts.txt empty"; exit 1; }
echo "[*] Roots: ${#ROOTS[@]} | global conc: ${GLOBAL_CONCURRENCY} | per-target conc: ${PER_TARGET_CONCURRENCY}"

ensure_dir(){ mkdir -p "$1"; }

scan_one() {
  local root="$1"
  local safe
  safe="$(echo "$root" | sed 's#[/:]#_#g')"
  local work="out/$safe"
  local finddir="findings/$safe"
  ensure_dir "$work"; ensure_dir "$finddir"

  echo "[+] START $root"

  # 1) subdomain discovery (subfinder + amass passive if available)
  subfinder -silent -d "$root" -all -sources "$SUBFINDER_SOURCES" -o "$work/subs.subfinder.txt" 2> "logs/subfinder.$safe.log" || true
  if command -v amass >/dev/null 2>&1; then
    timeout "${AMASS_TIMEOUT_MIN}m" amass enum -passive -d "$root" -silent -o "$work/subs.amass.txt" 2> "logs/amass.$safe.log" || true
  fi

  # seed common env names
  cat > "$work/seed.txt" <<EOF
staging.$root
dev.$root
qa.$root
test.$root
uat.$root
preview.$root
canary.$root
int.$root
internal.$root
beta.$root
alpha.$root
sandbox.$root
EOF

  cat "$work"/subs.*.txt "$work/seed.txt" 2>/dev/null | sed '/^$/d' | sort -u > "$work/subs.all.txt"

  echo "[*] $(wc -l < "$work/subs.all.txt" || echo 0) subs (pre-resolve) for $root"

  # 2) resolve with dnsx -> keep names with A/AAAA/CNAME
  dnsx -silent -l "$work/subs.all.txt" -a -aaaa -cname -resp -retries 1 -w "${DNSX_WORKERS}" -json > "$work/dnsx.json" 2> "logs/dnsx.$safe.log" || true
  jq -r 'select(.a!=null or .aaaa!=null or .cname!=null) | .host' "$work/dnsx.json" | sort -u > "$work/resolved.txt" || true
  echo "[*] $(wc -l < "$work/resolved.txt" || echo 0) resolved hosts for $root"

  # 3) probe (httpx) -> rich JSON per-host
  httpx -l "$work/resolved.txt" -silent -follow-host-redirects -status-code -tech-detect -title -content-type -ip -cname -cdn -websocket -tls-grab -threads "${HTTPX_THREADS}" -timeout "${HTTPX_TIMEOUT}" -retries 1 -json > "$work/httpx.json" 2> "logs/httpx.$safe.log" || true

  # cap per-host URLs (true per-host cap)
  if [[ -f "$work/httpx.json" ]]; then
    jq -r '[.host, (.url|tostring)] | @tsv' "$work/httpx.json" \
      | awk -v N="$MAX_URLS_PER_HOST" '{
          host=$1; url=$2;
          count[host]++;
          if (count[host] <= N) print url;
        }' | sed 's#/*$##' | sort -u > "$work/alive.sample.txt" || true
  fi

  echo "[*] $(wc -l < "$work/alive.sample.txt" || echo 0) live URLs (sampled per-host) for $root"

  # 4) smart greedy low/med harvester
  python3 smart_hunt.py --target "$root" --httpx-json "$work/httpx.json" --alive "$work/alive.sample.txt" --outdir "$finddir" --per-target "${PER_TARGET_CONCURRENCY}" --path-check-top-hosts "${PATH_CHECK_TOP_HOSTS}" 2> "logs/smart.$safe.log" || true

  # 5) nuclei on sampled URLs (if available)
  if command -v nuclei >/dev/null 2>&1 && [[ -s "$work/alive.sample.txt" ]]; then
    nuclei -l "$work/alive.sample.txt" -severity "${NUCLEI_SEVERITY}" -rl "${NUCLEI_RATE_LIMIT}" -c "${NUCLEI_THREADS}" -retries 1 -bulk-size 60 -json -stats -no-meta -o "$work/nuclei.json" 2> "logs/nuclei.$safe.log" || true
    python3 smart_hunt.py --target "$root" --nuclei-json "$work/nuclei.json" --outdir "$finddir" --fold-nuclei 2>> "logs/smart.$safe.log" || true
  fi

  # 6) fold per-target summary
  [[ -f "$finddir/summary.txt" ]] && cat "$finddir/summary.txt" >> out/summary.txt || true
  echo "[+] DONE $root"
}

export -f scan_one

# trap for cleanup
trap 'echo "[!] terminating…"; pkill -P $$ || true' INT TERM

# fan-out
printf "%s\n" "${ROOTS[@]}" | xargs -n1 -P "$GLOBAL_CONCURRENCY" -I{} bash -c 'scan_one "$@"' _ {}

echo "======== RUN SUMMARY ========"
cat out/summary.txt || true
