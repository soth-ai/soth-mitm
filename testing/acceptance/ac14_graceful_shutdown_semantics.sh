#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

source testing/acceptance/common.sh

report_dir="artifacts/p6-acceptance/ac14"
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

ac_run_case "$status_tsv" shutdown_noop_when_handle_missing \
  cargo test -p soth-mitm shutdown_noop_when_handle_already_consumed -q
ac_run_case "$status_tsv" shutdown_drains_active_flows \
  cargo test -p soth-mitm shutdown_drains_active_flows_before_joining_runtime -q
ac_run_case "$status_tsv" shutdown_timeout_when_flows_stuck \
  cargo test -p soth-mitm shutdown_returns_timeout_when_active_flows_do_not_drain -q
ac_run_case "$status_tsv" stream_close_once_lifecycle_contract \
  cargo test -p soth-mitm stream_end_invokes_connection_close_once -q

config_md=$'- strict_tools: '"${strict_tools}"$'\n- long_run: '"${long_run}"$'\n- scope: shutdown abort semantics, timeout fallback, and close-once lifecycle'

ac_finalize \
  "$status_tsv" \
  "$summary_md" \
  "$outcome_tsv" \
  "AC-14 Graceful Shutdown Drain and Timeout Semantics" \
  "$config_md"
