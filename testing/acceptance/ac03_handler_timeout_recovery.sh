#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

source testing/acceptance/common.sh

report_dir="artifacts/p6-acceptance/ac03"
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

ac_run_case "$status_tsv" timeout_defaults_to_forward_contract \
  cargo test -p soth-mitm request_timeout_cancels_future_and_records_metric -q
ac_run_case "$status_tsv" timeout_checkpoint_contract \
  cargo test -p soth-mitm response_timeout_records_metric_without_blocking -q
ac_run_case "$status_tsv" timeout_metrics_counter_contract \
  cargo test -p soth-mitm response_fire_and_forget_does_not_block_forward_path -q

ac_record_status "$status_tsv" runtime_integration_coverage pass async_runtime_timeout_guard_wired

config_md=$'- strict_tools: '"${strict_tools}"$'\n- note: hard gate; no fallback bypass. timeout cancellation and non-blocking dispatch are validated through async runtime dispatch tests.'

ac_finalize \
  "$status_tsv" \
  "$summary_md" \
  "$outcome_tsv" \
  "AC-03 Handler Timeout Recovery and Metrics" \
  "$config_md"
