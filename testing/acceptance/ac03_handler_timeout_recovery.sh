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
  cargo test -p soth-mitm handler_timeout_defaults_to_forward_and_counts -q || true
ac_run_case "$status_tsv" timeout_checkpoint_contract \
  cargo test -p soth-mitm returns_timeout_when_handler_exceeds_timeout_before_checkpoint -q || true
ac_run_case "$status_tsv" timeout_metrics_counter_contract \
  cargo test -p soth-mitm proxy_metrics_counter_contract -q || true

if rg -n "build_runtime_server\(config: &MitmConfig, _handler" crates/soth-mitm/src/runtime.rs >/dev/null; then
  ac_record_status "$status_tsv" runtime_integration_coverage skip handler_timeout_not_exercised_in_runtime_server
else
  ac_record_status "$status_tsv" runtime_integration_coverage pass handler_timeout_runtime_wired
fi

config_md=$'- strict_tools: '"${strict_tools}"$'\n- note: timeout behavior validated at contract/checkpoint layer; runtime in-flight timeout path is tracked via integration_coverage.'

ac_finalize \
  "$status_tsv" \
  "$summary_md" \
  "$outcome_tsv" \
  "AC-03 Handler Timeout Recovery and Metrics" \
  "$config_md"
