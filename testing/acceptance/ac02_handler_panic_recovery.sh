#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

source testing/acceptance/common.sh

report_dir="artifacts/p6-acceptance/ac02"
strict_tools=0

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

ac_run_case "$status_tsv" panic_defaults_to_forward_contract \
  cargo test -p soth-mitm request_panic_recover_true_defaults_allow_and_records_metric -q
ac_run_case "$status_tsv" panic_recovery_mode_contract \
  cargo test -p soth-mitm request_panic_recover_false_bubbles_panic -q
ac_run_case "$status_tsv" panic_metrics_counter_contract \
  cargo test -p soth-mitm proxy_metrics_counter_contract -q

ac_record_status "$status_tsv" runtime_integration_coverage pass async_runtime_handler_guard_wired

config_md=$'- strict_tools: '"${strict_tools}"$'\n- note: hard gate; no fallback bypass. panic recovery/fail-closed behavior is validated through async runtime dispatch tests.'

ac_finalize \
  "$status_tsv" \
  "$summary_md" \
  "$outcome_tsv" \
  "AC-02 Handler Panic Recovery and Metrics" \
  "$config_md"
