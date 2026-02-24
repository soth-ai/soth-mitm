#!/usr/bin/env bash
set -euo pipefail

report_dir="artifacts/p4-performance"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --report-dir)
      report_dir="$2"
      shift 2
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

run_case() {
  local lane="$1"
  shift
  if "$@"; then
    echo -e "${lane}\tpass" >>"$status_tsv"
  else
    echo -e "${lane}\tfail" >>"$status_tsv"
    return 1
  fi
}

: >"$status_tsv"
run_case connection_churn_core cargo test -p mitm-core --test server_concurrency -q
run_case connection_churn_sidecar cargo test -p mitm-sidecar --test phase_a concurrent_short_lived_tunnels_500 -q
run_case long_lived_streams_websocket cargo test -p mitm-sidecar --test websocket_mitm websocket_server_initiated_turns_emit_expected_boundaries -q
run_case long_lived_streams_sse cargo test -p mitm-sidecar --test sse_mitm parses_sse_events_incrementally_and_flushes_tail_on_stream_close -q
run_case header_stress_oversized_h2 cargo test -p mitm-sidecar --test http2_mitm http2_oversized_headers_emit_mitm_http_error_close -q
run_case header_stress_parallel_h2 cargo test -p mitm-sidecar --test http2_mitm http2_parallel_stream_stress_keeps_completed_close_and_byte_accounting -q
run_case memory_ceiling_runtime_governor cargo test -p mitm-sidecar --test runtime_governor -q
run_case memory_ceiling_decoder_budget cargo test -p mitm-sidecar --test chaos_charter infinite_sse_stream_hits_decoder_budget_and_closes_deterministically -q

failed="$(awk '$2 != "pass" {print $1}' "$status_tsv" || true)"
{
  echo "# Phase 4 Performance Gates"
  echo
  echo "Generated: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo
  if [[ -z "$failed" ]]; then
    echo "Status: PASS"
  else
    echo "Status: FAIL"
    echo
    echo "Failed lanes:"
    echo "$failed"
  fi
  echo
  echo "## Lane Status"
  echo
  echo '```tsv'
  cat "$status_tsv"
  echo '```'
} >"$summary_md"

if [[ -n "$failed" ]]; then
  exit 1
fi
