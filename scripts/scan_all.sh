#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

RUN_TARGETS=${RUN_TARGETS:-}
GLOBAL_CONCURRENCY=6   # conservative global parallelism for Actions
PER_TARGET_MAX=6

mkdir -p findings state artifacts || true

# helper to run a single target pipeline
run_target() {
  target="$1"
  outdir="findings/$(echo "$target" | tr '/' '_' )"
  mkdir -p "$outdir"

  echo "[+] START $target"
  python3 scripts/discover.py "$target" --out "$outdir/subs.txt"
  python3 scripts/extract_endpoints.py "$outdir/subs.txt" --out "$outdir/endpoints.json"

  # aggressive param fuzzer runs fast but limited by per-target pain
  python3 scripts/runner_manager.py >/dev/null || true
  python3 scripts/param_fuzzer.py "$outdir/endpoints.json" --out "$outdir/params.json" || true

  # concurrent checks (cors, redirect fuzz, takeover, nuclei)
  python3 scripts/cors_check.py "$outdir/endpoints.json" --out "$outdir/cors.json" || true
  bash scripts/redirect_fuzz.sh "$outdir/subs.txt" "$outdir/redirects.json" || true
  python3 scripts/takeover_check.py "$outdir/subs.txt" --out "$outdir/takeovers.json" || true

  # optional nuclei (if installed on runner)
  bash scripts/run_nuclei.sh "$outdir/endpoints.json" "$outdir" || true

  # validation, scoring, package evidence
  python3 scripts/validate_finding.py "$outdir" --scoring config/scoring.json --whitelist config/program_whitelist/default.json --out "$outdir/validated.json" || true
  python3 scripts/package_evidence.py "$outdir" --out "$outdir/evidence.zip" || true

  # run evidence validation to ensure no PII leaks
  bash scripts/validate_evidence.sh "$outdir/evidence.zip" || echo "[!] evidence validation warning for $target"

  # auto-draft for high confidence
  python3 scripts/auto_draft.py "$outdir/validated.json" || true

  echo "[+] DONE $target"
}

# build target list
if [ -n "$RUN_TARGETS" ]; then
  IFS=',' read -r -a TARGETS <<< "$RUN_TARGETS"
else
  mapfile -t TARGETS < <(grep -v '^#' hosts.txt | sed '/^\s*$/d')
fi

# run with limited concurrency
pids=()
for t in "${TARGETS[@]}"; do
  run_target "$t" &
  pids+=("$!")
  # throttle global concurrency
  while [ "${#pids[@]}" -ge "$GLOBAL_CONCURRENCY" ]; do
    wait -n
    # prune completed
    new=()
    for pid in "${pids[@]}"; do
      if kill -0 "$pid" 2>/dev/null; then new+=("$pid"); fi
    done
    pids=("${new[@]}")
  done
done

wait
echo "[+] All done. Check findings/"
