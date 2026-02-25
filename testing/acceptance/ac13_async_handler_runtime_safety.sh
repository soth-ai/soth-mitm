#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

source testing/acceptance/common.sh

report_dir="artifacts/p6-acceptance/ac13"
strict_tools=0
long_run=0

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

ac_run_case "$status_tsv" request_timeout_cancellation_gate \
  cargo test -p soth-mitm request_timeout_cancels_future_and_records_metric -q
ac_run_case "$status_tsv" request_panic_recovery_gate \
  cargo test -p soth-mitm request_panic_recover_true_defaults_allow_and_records_metric -q
ac_run_case "$status_tsv" request_panic_fail_closed_gate \
  cargo test -p soth-mitm request_panic_recover_false_bubbles_panic -q
ac_run_case "$status_tsv" response_non_blocking_dispatch_gate \
  cargo test -p soth-mitm response_fire_and_forget_does_not_block_forward_path -q
ac_run_case "$status_tsv" response_timeout_cancellation_gate \
  cargo test -p soth-mitm response_timeout_records_metric_without_blocking -q
ac_run_case "$status_tsv" stream_close_lifecycle_gate \
  cargo test -p soth-mitm stream_end_invokes_connection_close_once -q
ac_run_case "$status_tsv" tls_process_info_plumb_gate \
  cargo test -p soth-mitm should_intercept_tls_receives_process_info_from_connect_path -q

if [[ "$long_run" -eq 1 ]]; then
  ac_run_case "$status_tsv" long_runtime_soak_deadlock_guard \
    scripts/p5_runtime_soak.sh --duration-seconds 300 --min-iterations 2
else
  ac_record_status "$status_tsv" long_runtime_soak_deadlock_guard skip disabled_without_long_run
fi

config_md=$'- strict_tools: '"${strict_tools}"$'\n- long_run: '"${long_run}"$'\n- scope: async callback timeout, cancellation, panic recovery, non-blocking dispatch, lifecycle close, deadlock sentinel'

ac_finalize \
  "$status_tsv" \
  "$summary_md" \
  "$outcome_tsv" \
  "AC-13 Async Handler Runtime Safety Gate" \
  "$config_md"
