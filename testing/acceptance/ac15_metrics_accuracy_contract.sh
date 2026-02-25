#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

source testing/acceptance/common.sh

report_dir="artifacts/p6-acceptance/ac15"
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

ac_run_case "$status_tsv" proxy_metrics_counter_contract \
  cargo test -p soth-mitm proxy_metrics_counter_contract -q
ac_run_case "$status_tsv" request_timeout_metric_contract \
  cargo test -p soth-mitm request_timeout_cancels_future_and_records_metric -q
ac_run_case "$status_tsv" request_panic_metric_contract \
  cargo test -p soth-mitm request_panic_recover_true_defaults_allow_and_records_metric -q
ac_run_case "$status_tsv" response_timeout_metric_contract \
  cargo test -p soth-mitm response_timeout_records_metric_without_blocking -q
ac_run_case "$status_tsv" process_lookup_timeout_contract \
  cargo test -p soth-mitm process_lookup_timeout_sets_none -q
ac_run_case "$status_tsv" process_lookup_cache_contract \
  cargo test -p soth-mitm process_info_resolved_once_per_connection -q

config_md=$'- strict_tools: '"${strict_tools}"$'\n- long_run: '"${long_run}"$'\n- scope: metrics counter correctness for panic, timeout, and process-attribution paths'

ac_finalize \
  "$status_tsv" \
  "$summary_md" \
  "$outcome_tsv" \
  "AC-15 Metrics Accuracy Contract" \
  "$config_md"
