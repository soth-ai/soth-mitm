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
soak_exchange_timeout_seconds="${P6_AC01_SOAK_EXCHANGE_TIMEOUT_SECONDS:-60}"
soak_h2_retries="${P6_AC01_SOAK_H2_RETRIES:-4}"
soak_h2_upstream_accept_timeout_seconds="${P6_AC01_SOAK_H2_UPSTREAM_ACCEPT_TIMEOUT_SECONDS:-10}"

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
  if command -v rustup >/dev/null 2>&1 && rustup toolchain list | awk '{print $1}' | rg '^nightly' >/dev/null 2>&1; then
    ac_run_case "$status_tsv" tls_classification_fuzz_runs \
      cargo +nightly fuzz run tls_classification -- "-runs=${fuzz_runs}" || true
    ac_run_case "$status_tsv" websocket_framing_fuzz_runs \
      cargo +nightly fuzz run websocket_framing -- "-runs=${fuzz_runs}" || true
  else
    ac_record_status "$status_tsv" tls_classification_fuzz_runs fail missing_tools:nightly_toolchain
    ac_record_status "$status_tsv" websocket_framing_fuzz_runs fail missing_tools:nightly_toolchain
  fi
else
  ac_record_status "$status_tsv" tls_classification_fuzz_runs fail missing_tools:cargo-fuzz
  ac_record_status "$status_tsv" websocket_framing_fuzz_runs fail missing_tools:cargo-fuzz
fi

effective_soak_seconds="$soak_seconds"
if [[ "$long_run" -ne 1 ]]; then
  effective_soak_seconds="$smoke_soak_seconds"
fi

ac_run_case "$status_tsv" mixed_traffic_soak_30m \
  env \
    SOTH_MITM_SOAK_SECONDS="$effective_soak_seconds" \
    SOTH_MITM_SOAK_MIN_ITERATIONS="$soak_min_iterations" \
    SOTH_MITM_SOAK_EXCHANGE_TIMEOUT_SECONDS="$soak_exchange_timeout_seconds" \
    SOTH_MITM_SOAK_H2_RETRIES="$soak_h2_retries" \
    SOTH_MITM_SOAK_H2_UPSTREAM_ACCEPT_TIMEOUT_SECONDS="$soak_h2_upstream_accept_timeout_seconds" \
    cargo test -p mitm-sidecar --test mixed_traffic_soak \
      mixed_traffic_soak_respects_runtime_budget_envelope -q || true

if command -v heaptrack >/dev/null 2>&1 || command -v valgrind >/dev/null 2>&1; then
  ac_record_status "$status_tsv" memory_tool_probe pass available
else
  ac_record_status "$status_tsv" memory_tool_probe fail missing_tools:heaptrack_or_valgrind
fi

config_md=$'- strict_tools: '"${strict_tools}"$'\n- long_run: '"${long_run}"$'\n- decoder_runs: '"${decoder_runs}"$'\n- fuzz_runs: '"${fuzz_runs}"$'\n- soak_seconds: '"${soak_seconds}"$'\n- smoke_soak_seconds: '"${smoke_soak_seconds}"$'\n- soak_min_iterations: '"${soak_min_iterations}"$'\n- soak_exchange_timeout_seconds: '"${soak_exchange_timeout_seconds}"$'\n- soak_h2_retries: '"${soak_h2_retries}"$'\n- soak_h2_upstream_accept_timeout_seconds: '"${soak_h2_upstream_accept_timeout_seconds}"

ac_finalize \
  "$status_tsv" \
  "$summary_md" \
  "$outcome_tsv" \
  "AC-01 Full Proxy Fuzz + Memory Stability" \
  "$config_md"
