#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

source testing/acceptance/common.sh

report_dir="artifacts/p6-acceptance/ac04"
strict_tools=0
iterations="${P6_AC04_ITERATIONS:-120}"
warmup="${P6_AC04_WARMUP:-12}"
threshold_p95_us="${P6_AC04_THRESHOLD_P95_US:-5000}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --report-dir)
      report_dir="$2"
      shift 2
      ;;
    --strict-tools)
      strict_tools=1
      shift
      ;;
    --long-run)
      shift
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

mkdir -p "$report_dir"
status_tsv="$report_dir/status.tsv"
summary_md="$report_dir/summary.md"
outcome_tsv="$report_dir/outcome.tsv"
printf 'check\tstatus\tdetail\n' >"$status_tsv"

ac_run_case "$status_tsv" sse_dispatch_budget_contract \
  cargo test -p soth-mitm sse_first_chunk_delta_budget -q || true
ac_run_case "$status_tsv" sse_first_chunk_benchmark \
  cargo bench -p soth-mitm --bench sse_first_chunk -- \
    --iterations "$iterations" \
    --warmup "$warmup" \
    --threshold-p95-us "$threshold_p95_us" \
    --result-file "$report_dir/sse_first_chunk.tsv" || true

config_md=$'- strict_tools: '"${strict_tools}"$'\n- iterations: '"${iterations}"$'\n- warmup: '"${warmup}"$'\n- threshold_p95_us: '"${threshold_p95_us}"

ac_finalize \
  "$status_tsv" \
  "$summary_md" \
  "$outcome_tsv" \
  "AC-04 SSE First-Chunk Latency" \
  "$config_md"
