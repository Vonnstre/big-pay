#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT_DIR"

RUN_TARGETS=${RUN_TARGETS:-}
CONCURRENCY=4

mkdir -p findings

# Simple function to run a single target pipeline
run_target() {
  target="$1"
  outdir="findings/$(echo "$target" | tr '/' '_')"
  mkdir -p "$outdir"

  echo "[+] Processing: $target"
  python3 scripts/discover.py "$target" --out "$outdir/subs.txt"
  python3 scripts/extract_endpoints.py "$outdir/subs.txt" --out "$outdir/endpoints.json"

  # Parallel checks inside target
  python3 scripts/cors_check.py "$outdir/endpoints.json" --out "$outdir/cors.json"
  bash scripts/redirect_fuzz.sh "$outdir/endpoints.json" "$outdir/redirects.json"
  python3 scripts/takeover_check.py "$outdir/subs.txt" --out "$outdir/takeovers.json"

  # validate and pack
  python3 scripts/validate_finding.py "$outdir" --scoring config/scoring.json --whitelist config/program_whitelist/default.json --out "$outdir/validated.json"
  python3 scripts/package_evidence.py "$outdir" --out "$outdir/evidence.zip"
}

# Build target list
if [ -n "$RUN_TARGETS" ]; then
  IFS=',' read -r -a TARGETS <<< "$RUN_TARGETS"
else
  mapfile -t TARGETS < <(grep -v '^#' hosts.txt | sed '/^\s*$/d')
fi

# simple concurrency
pids=()
for t in "${TARGETS[@]}"; do
  run_target "$t" &
  pids+=("$!")
  if [ "${#pids[@]}" -ge "$CONCURRENCY" ]; then
    wait -n
    # prune finished
    new=()
    for pid in "${pids[@]}"; do
      if kill -0 "$pid" 2>/dev/null; then
        new+=("$pid")
      fi
    done
    pids=("${new[@]}")
  fi
done

wait

echo "[+] All targets processed. Artifacts written under findings/"
