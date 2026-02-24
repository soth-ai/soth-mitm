#!/usr/bin/env bash
set -euo pipefail

report_dir="artifacts/p5-reliability-contract"

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
run_log="$report_dir/run.log"

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

{
  run_case flow_fsm_transition_validator \
    cargo test -p mitm-core invalid_transition_terminalizes_without_panic_and_allows_close -q
  run_case single_stream_closed_guardrail \
    cargo test -p mitm-core suppresses_duplicate_stream_closed_for_same_flow -q
  run_case runtime_budget_metrics \
    cargo test -p mitm-sidecar --test runtime_governor \
      runtime_governor_enforces_concurrent_flow_limit_and_records_metrics -q
  run_case idle_watchdog_metrics \
    cargo test -p mitm-sidecar --test runtime_governor \
      idle_watchdog_timeout_closes_stuck_tunnel_and_records_metrics -q
  run_case h2_stage_budget_metrics \
    cargo test -p mitm-sidecar --test mixed_traffic_soak \
      tls_h2_exchange_harness_path_succeeds -q
} >"$run_log" 2>&1 || true

failed="$(awk '$2 != "pass" {print $1}' "$status_tsv" || true)"
{
  echo "# Phase 5 Reliability Contract Gate"
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
  echo
  echo "## Log"
  echo
  echo "See: $run_log"
} >"$summary_md"

if [[ -n "$failed" ]]; then
  exit 1
fi
