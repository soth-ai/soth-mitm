#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

source testing/acceptance/common.sh

report_dir="artifacts/p6-acceptance/ac13"
strict_tools=0
long_run=0
smoke_soak_seconds="${P6_AC13_SMOKE_SOAK_SECONDS:-15}"
long_soak_seconds="${P6_AC13_LONG_SOAK_SECONDS:-300}"
long_soak_min_iterations="${P6_AC13_LONG_SOAK_MIN_ITERATIONS:-2}"

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

ac_run_case_with_socket_permission_fallback() {
  local status_tsv="$1"
  local check="$2"
  local strict_tools="$3"
  shift 3

  local log_file
  local exit_code=0
  log_file="$(mktemp)"
  "$@" >"$log_file" 2>&1 || exit_code=$?
  if [[ "$exit_code" -eq 0 ]]; then
    ac_record_status "$status_tsv" "$check" pass ok
    rm -f "$log_file"
    return 0
  fi

  if grep -E -q "Operation not permitted|PermissionDenied|kind: PermissionDenied|os error 1" "$log_file"; then
    if [[ "$strict_tools" -eq 1 ]]; then
      ac_record_status "$status_tsv" "$check" fail "permission_denied:${exit_code}"
    else
      ac_record_status "$status_tsv" "$check" skip "permission_denied:${exit_code}"
    fi
    cat "$log_file" >&2
    rm -f "$log_file"
    return 0
  fi

  ac_record_status "$status_tsv" "$check" fail "command_failed:${exit_code}"
  cat "$log_file" >&2
  rm -f "$log_file"
  return 1
}

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
  ac_run_case_with_socket_permission_fallback "$status_tsv" runtime_soak_deadlock_guard "$strict_tools" \
    /bin/zsh -lc "scripts/p5_runtime_soak.sh --report-dir $(printf '%q' "$report_dir/runtime_soak") --duration-seconds $(printf '%q' "$long_soak_seconds") --min-iterations $(printf '%q' "$long_soak_min_iterations") || { cat $(printf '%q' "$report_dir/runtime_soak/run.log"); exit 1; }" \
    || true
else
  ac_run_case_with_socket_permission_fallback "$status_tsv" runtime_soak_deadlock_guard "$strict_tools" \
    /bin/zsh -lc "scripts/p5_runtime_soak.sh --report-dir $(printf '%q' "$report_dir/runtime_soak") --duration-seconds $(printf '%q' "$smoke_soak_seconds") --min-iterations 1 || { cat $(printf '%q' "$report_dir/runtime_soak/run.log"); exit 1; }" \
    || true
fi

config_md=$'- strict_tools: '"${strict_tools}"$'\n- long_run: '"${long_run}"$'\n- smoke_soak_seconds: '"${smoke_soak_seconds}"$'\n- long_soak_seconds: '"${long_soak_seconds}"$'\n- long_soak_min_iterations: '"${long_soak_min_iterations}"$'\n- scope: async callback timeout, cancellation, panic recovery, non-blocking dispatch, lifecycle close, deadlock sentinel'

ac_finalize \
  "$status_tsv" \
  "$summary_md" \
  "$outcome_tsv" \
  "AC-13 Async Handler Runtime Safety Gate" \
  "$config_md"
