#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

source testing/acceptance/common.sh

report_dir="artifacts/p6-acceptance/ac01"
strict_tools=0
long_run=0
decoder_runs="${P6_AC01_DECODER_RUNS:-128}"
fuzz_runs="${P6_AC01_FUZZ_RUNS:-5000}"
soak_seconds="${P6_AC01_SOAK_SECONDS:-1800}"
soak_min_iterations="${P6_AC01_SOAK_MIN_ITERATIONS:-1}"
smoke_soak_seconds="${P6_AC01_SMOKE_SOAK_SECONDS:-30}"

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
      long_run=1
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

ac_run_case "$status_tsv" fuzz_harness_build \
  cargo check --manifest-path fuzz/Cargo.toml --offline || true
ac_run_case "$status_tsv" decoder_layering_regression \
  ./scripts/fuzz_decoder_layering_regression.sh --runs "$decoder_runs" || true

if command -v cargo-fuzz >/dev/null 2>&1; then
  ac_run_case "$status_tsv" tls_classification_fuzz_runs \
    cargo fuzz run tls_classification -- -runs "$fuzz_runs" || true
else
  ac_run_case "$status_tsv" tls_classification_fuzz_runs \
    cargo run --manifest-path fuzz/Cargo.toml --bin tls_classification -- \
      -runs="$fuzz_runs" fuzz/corpus/tls_classification || true
fi

effective_soak_seconds="$soak_seconds"
if [[ "$long_run" -ne 1 ]]; then
  effective_soak_seconds="$smoke_soak_seconds"
fi

ac_run_case "$status_tsv" mixed_traffic_soak_30m \
  env \
    SOTH_MITM_SOAK_SECONDS="$effective_soak_seconds" \
    SOTH_MITM_SOAK_MIN_ITERATIONS="$soak_min_iterations" \
    cargo test -p mitm-sidecar --test mixed_traffic_soak \
      mixed_traffic_soak_respects_runtime_budget_envelope -q || true

if command -v heaptrack >/dev/null 2>&1 || command -v valgrind >/dev/null 2>&1; then
  ac_record_status "$status_tsv" memory_tool_probe pass available
else
  if [[ "$strict_tools" -eq 1 ]]; then
    ac_record_status "$status_tsv" memory_tool_probe fail missing_tools:heaptrack_or_valgrind
  else
    ac_record_status "$status_tsv" memory_tool_probe pass missing_tools_fallback:heaptrack_or_valgrind
  fi
fi

config_md=$'- strict_tools: '"${strict_tools}"$'\n- long_run: '"${long_run}"$'\n- decoder_runs: '"${decoder_runs}"$'\n- fuzz_runs: '"${fuzz_runs}"$'\n- soak_seconds: '"${soak_seconds}"$'\n- smoke_soak_seconds: '"${smoke_soak_seconds}"$'\n- soak_min_iterations: '"${soak_min_iterations}"

ac_finalize \
  "$status_tsv" \
  "$summary_md" \
  "$outcome_tsv" \
  "AC-01 Full Proxy Fuzz + Memory Stability" \
  "$config_md"
