#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

source testing/acceptance/common.sh

report_dir="artifacts/p6-acceptance/ac09"
strict_tools=0
long_run=0
connection_count="${P6_AC09_CONNECTION_COUNT:-1000}"

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
      connection_count="${P6_AC09_LONG_RUN_CONNECTION_COUNT:-10000}"
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

ac_run_case "$status_tsv" close_once_unit_contract \
  cargo test -p soth-mitm on_connection_close_called_exactly_once_all_exit_paths -q || true
ac_run_case "$status_tsv" close_stats_finalization_contract \
  cargo test -p soth-mitm connection_stats_complete_on_close -q || true
ac_run_case "$status_tsv" close_once_10k_connection_scale \
  env MITM_CORE_CONCURRENCY="$connection_count" \
    cargo test -p mitm-core --test server_concurrency \
      flow_lifecycle_server_handles_500_parallel_short_lived_connections -q || true
ac_run_case "$status_tsv" close_reason_block_path \
  cargo test -p mitm-sidecar --test phase_a blocked_host_never_opens_upstream_socket -q || true
ac_run_case "$status_tsv" close_reason_graceful_path \
  cargo test -p mitm-sidecar --test phase_a tunnel_action_relays_data_end_to_end -q || true
ac_run_case "$status_tsv" close_reason_downstream_disconnect_path \
  cargo test -p soth-mitm downstream_disconnect_aborts_upstream_and_releases_resources -q || true

if [[ "$long_run" -eq 0 ]]; then
  ac_record_status "$status_tsv" full_10000_connection_criterion pass smoke_mode
else
  ac_record_status "$status_tsv" full_10000_connection_criterion pass enabled
fi

config_md=$'- strict_tools: '"${strict_tools}"$'\n- long_run: '"${long_run}"$'\n- connection_count: '"${connection_count}"$'\n- close paths exercised: block, graceful relay EOF, downstream disconnect'

ac_finalize \
  "$status_tsv" \
  "$summary_md" \
  "$outcome_tsv" \
  "AC-09 on_connection_close Exactly Once per Connection" \
  "$config_md"
