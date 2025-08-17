#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

############ guard ############
SCAN_CONFIRM="${SCAN_CONFIRM:-False}"
if [[ "$SCAN_CONFIRM" != "True" ]]; then
  echo "[!] Aborting: you must type the exact string 'True' when dispatching the workflow."
  exit 1
fi

############ config ############
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

############ tool check ############
need=(jq subfinder dnsx httpx nuclei amass)
for t in "${need[@]}"; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "[!] missing tool: $t"
    exit 1
  fi
done

############ load targets ############
if [[ ! -f "hosts.txt" ]]; then
  echo "[!] hosts.txt missing in repo root"
  exit 1
fi

mapfile -t ROOTS < <(grep -vE '^\s*(#|$)' hosts.txt | sed 's/\r$//' | tr ' ' '\n' | sed '/^$/d' | sort -u)
((${#ROOTS[@]})) || { echo "[!] hosts.txt empty"; exit 1; }

echo "[*] Roots: ${#ROOTS[@]} | global conc: ${GLOBAL_CONCURRENCY} | per-target conc: ${PER_TARGET_CONCURRENCY}"

############ helpers ############
ensure_dir(){ mkdir -p "$1"; }

scan_one() {
  local root="$1"
  local safe; safe="$(echo "$root" | sed 's#[/:]#_#g')"
  local work="out/$safe"
  local finddir="findings/$safe"
  ensure_dir "$work"; ensure_dir "$finddir"

  echo "[+] START $root"

  ######## 1) SUBDOMAIN DISCOVERY (wide) ########
  # Subfinder (fast passive + sources) + Amass (passive only, timeout bound)
  subfinder -silent -d "$root" -all -sources "$SUBFINDER_SOURCES" \
    -o "$work/subs.subfinder.txt" 2>"logs/subfinder.$safe.log" || true

  timeout "${AMASS_TIMEOUT_MIN}m" amass enum -passive -d "$root" -silent \
    -o "$work/subs.amass.txt" 2>"logs/amass.$safe.log" || true

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

  cat "$work"/subs.*.txt "$work/seed.txt" 2>/dev/null \
    | sed '/^$/d' | sort -u > "$work/subs.all.txt"

  echo "[*] $(wc -l < "$work/subs.all.txt") subs (pre-resolve) for $root"

  ######## 2) RESOLVE (dnsx) -> only alive names ########
  dnsx -silent -l "$work/subs.all.txt" -a -aaaa -cname -resp -retries 1 -w "$DNSX_WORKERS" -json \
    > "$work/dnsx.json" 2>"logs/dnsx.$safe.log" || true

  jq -r 'select(.a!=null or .aaaa!=null or .cname!=null) | .host' "$work/dnsx.json" \
    | sort -u > "$work/resolved.txt"

  echo "[*] $(wc -l < "$work/resolved.txt") resolved hosts for $root"

  ######## 3) PROBE (httpx) — rich JSON ########
  httpx -l "$work/resolved.txt" -silent \
    -follow-host-redirects -status-code -tech-detect -title -content-type \
    -ip -cname -cdn -websocket -tls-grab \
    -threads "$HTTPX_THREADS" -timeout "$HTTPX_TIMEOUT" -retries 1 -json \
    > "$work/httpx.json" 2>"logs/httpx.$safe.log" || true

  # true per-host URL capping from httpx JSON
  jq -r '[.host, (.url|tostring)] | @tsv' "$work/httpx.json" | awk -v N="$MAX_URLS_PER_HOST" '
    {
      host=$1; url=$2;
      count[host]++; if (count[host] <= N) print url;
    }' \
    | sed 's#/*$##' \
    | sort -u > "$work/alive.sample.txt" || true

  echo "[*] $(wc -l < "$work/alive.sample.txt") live URLs (sampled per-host) for $root"

  ######## 4) SMART & GREEDY LOW/MED HUNT ########
  python3 smart_hunt.py \
    --target "$root" \
    --httpx-json "$work/httpx.json" \
    --alive "$work/alive.sample.txt" \
    --outdir "$finddir" \
    --per-target "$PER_TARGET_CONCURRENCY" \
    --path-check-top-hosts "$PATH_CHECK_TOP_HOSTS" 2>"logs/smart.$safe.log" || true

  ######## 5) NUCLEI (on sampled URLs) + fold ########
  nuclei -l "$work/alive.sample.txt" \
    -severity "$NUCLEI_SEVERITY" \
    -rl "$NUCLEI_RATE_LIMIT" -c "$NUCLEI_THREADS" -retries 1 -bulk-size 60 \
    -json -stats -no-meta -o "$work/nuclei.json" 2>"logs/nuclei.$safe.log" || true

  python3 smart_hunt.py \
    --target "$root" \
    --nuclei-json "$work/nuclei.json" \
    --outdir "$finddir" \
    --fold-nuclei 2>>"logs/smart.$safe.log" || true

  ######## 6) per-target summary ########
  [[ -f "$finddir/summary.txt" ]] && cat "$finddir/summary.txt" >> out/summary.txt || true
  echo "[+] DONE $root"
}

export -f scan_one

############ run fan-out ############
# Best-effort child cleanup on SIGINT/SIGTERM
trap 'echo "[!] terminating…"; pkill -P $$ || true' INT TERM

printf "%s\n" "${ROOTS[@]}" | xargs -n1 -P "$GLOBAL_CONCURRENCY" -I{} bash -c 'scan_one "$@"' _ {}

echo
echo "======== RUN SUMMARY ========"
cat out/summary.txt || true
