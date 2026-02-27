#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

report_dir="artifacts/p6-acceptance"
strict_tools=0
strict_acceptance=0
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
    --strict-acceptance)
      strict_acceptance=1
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

rm -rf "$report_dir"
mkdir -p "$report_dir"

status_tsv="$report_dir/status.tsv"
summary_md="$report_dir/summary.md"
outcome_tsv="$report_dir/outcome.tsv"
printf 'ac_id\tlane\tstatus\tdetail\tlog_file\treport_dir\n' >"$status_tsv"

lanes=(
  $'AC-01\tac01_tls_fuzz_memory\ttesting/acceptance/ac01_tls_fuzz_memory.sh'
  $'AC-02\tac02_handler_panic_recovery\ttesting/acceptance/ac02_handler_panic_recovery.sh'
  $'AC-03\tac03_handler_timeout_recovery\ttesting/acceptance/ac03_handler_timeout_recovery.sh'
  $'AC-04\tac04_sse_first_chunk_latency\ttesting/acceptance/ac04_sse_first_chunk_latency.sh'
  $'AC-05\tac05_block_no_upstream_connect\ttesting/acceptance/ac05_block_no_upstream_connect.sh'
  $'AC-06\tac06_passthrough_unlisted_tls_integrity\ttesting/acceptance/ac06_passthrough_unlisted_tls_integrity.sh'
  $'AC-07\tac07_concurrency_latency_memory\ttesting/acceptance/ac07_concurrency_latency_memory.sh'
  $'AC-08\tac08_config_reload_inflight\ttesting/acceptance/ac08_config_reload_inflight.sh'
  $'AC-09\tac09_connection_close_once\ttesting/acceptance/ac09_connection_close_once.sh'
  $'AC-10\tac10_process_attribution_cross_os\ttesting/acceptance/ac10_macos_process_attribution.sh'
  $'AC-11\tac11_syscall_boundary_audit\ttesting/acceptance/ac11_syscall_boundary_audit.sh'
  $'AC-12\tac12_dependency_policy\ttesting/acceptance/ac12_dependency_policy.sh'
  $'AC-13\tac13_async_handler_runtime_safety\ttesting/acceptance/ac13_async_handler_runtime_safety.sh'
  $'AC-14\tac14_graceful_shutdown_semantics\ttesting/acceptance/ac14_graceful_shutdown_semantics.sh'
  $'AC-15\tac15_metrics_accuracy_contract\ttesting/acceptance/ac15_metrics_accuracy_contract.sh'
  $'AC-16\tac16_body_size_limit_enforcement\ttesting/acceptance/ac16_body_size_limit_enforcement.sh'
  $'AC-17\tac17_transport_normalization_invariants\ttesting/acceptance/ac17_transport_normalization_invariants.sh'
)

failed_acs=()
skipped_acs=()

run_ac() {
  local ac_id="$1"
  local lane="$2"
  local script_path="$3"

  local ac_dir="$report_dir/$lane"
  local ac_log="$ac_dir/run.log"
  mkdir -p "$ac_dir"

  local args=(--report-dir "$ac_dir")
  if [[ "$strict_tools" -eq 1 ]]; then
    args+=(--strict-tools)
  fi
  if [[ "$long_run" -eq 1 ]]; then
    args+=(--long-run)
  fi

  local command_status=0
  set +e
  "$script_path" "${args[@]}" 2>&1 | tee "$ac_log"
  command_status=${PIPESTATUS[0]}
  set -e

  if [[ "$command_status" -ne 0 ]]; then
    failed_acs+=("$ac_id")
    printf '%s\t%s\tfail\t%s\t%s\t%s\n' \
      "$ac_id" "$lane" "script_exit:${command_status}" "$ac_log" "$ac_dir" >>"$status_tsv"
    return 0
  fi

  local lane_status_file="$ac_dir/status.tsv"
  if [[ ! -f "$lane_status_file" ]]; then
    failed_acs+=("$ac_id")
    printf '%s\t%s\tfail\t%s\t%s\t%s\n' \
      "$ac_id" "$lane" "missing_lane_status_file" "$ac_log" "$ac_dir" >>"$status_tsv"
    return 0
  fi

  local lane_fail_count=0
  local lane_skip_count=0
  lane_fail_count="$(awk -F '\t' 'NR > 1 && $2 == "fail" {count++} END {print count + 0}' "$lane_status_file")"
  lane_skip_count="$(awk -F '\t' 'NR > 1 && $2 == "skip" {count++} END {print count + 0}' "$lane_status_file")"

  if [[ "$lane_fail_count" -gt 0 ]]; then
    failed_acs+=("$ac_id")
    printf '%s\t%s\tfail\t%s\t%s\t%s\n' \
      "$ac_id" "$lane" "lane_checks_failed:${lane_fail_count}" "$ac_log" "$ac_dir" >>"$status_tsv"
    return 0
  fi

  if [[ "$lane_skip_count" -gt 0 ]]; then
    skipped_acs+=("$ac_id")
    printf '%s\t%s\tskip\t%s\t%s\t%s\n' \
      "$ac_id" "$lane" "lane_checks_skipped:${lane_skip_count}" "$ac_log" "$ac_dir" >>"$status_tsv"
    return 0
  fi

  printf '%s\t%s\tpass\t%s\t%s\t%s\n' \
    "$ac_id" "$lane" "ok" "$ac_log" "$ac_dir" >>"$status_tsv"
}

for lane_row in "${lanes[@]}"; do
  IFS=$'\t' read -r ac_id lane script_path <<<"$lane_row"
  run_ac "$ac_id" "$lane" "$script_path"
done

failed_count="${#failed_acs[@]}"
skipped_count="${#skipped_acs[@]}"
pass_count="$(awk -F '\t' 'NR > 1 && $3 == "pass" {count++} END {print count + 0}' "$status_tsv")"

final_status="PASS"
exit_code=0
if [[ "$failed_count" -gt 0 ]]; then
  final_status="FAIL"
  exit_code=1
elif [[ "$strict_acceptance" -eq 1 && "$skipped_count" -gt 0 ]]; then
  final_status="FAIL"
  exit_code=1
elif [[ "$skipped_count" -gt 0 ]]; then
  final_status="PARTIAL"
fi

{
  echo "# P6 Acceptance Matrix (AC-01 .. AC-17)"
  echo
  echo "Generated: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo
  echo "Config:"
  echo "- strict_tools: ${strict_tools}"
  echo "- strict_acceptance: ${strict_acceptance}"
  echo "- long_run: ${long_run}"
  echo
  echo "Status: ${final_status}"
  echo "- pass_count: ${pass_count}"
  echo "- skipped_count: ${skipped_count}"
  echo "- failed_count: ${failed_count}"

  if [[ "$failed_count" -gt 0 ]]; then
    echo
    echo "Failed ACs:"
    printf '%s\n' "${failed_acs[@]}"
  fi

  if [[ "$skipped_count" -gt 0 ]]; then
    echo
    echo "Skipped ACs:"
    printf '%s\n' "${skipped_acs[@]}"
  fi

  echo
  echo "## AC Status"
  echo
  echo '```tsv'
  cat "$status_tsv"
  echo '```'
} >"$summary_md"

{
  echo -e "metric\tvalue"
  echo -e "status\t${final_status}"
  echo -e "pass_count\t${pass_count}"
  echo -e "skipped_count\t${skipped_count}"
  echo -e "failed_count\t${failed_count}"
} >"$outcome_tsv"

if [[ "$exit_code" -ne 0 ]]; then
  exit "$exit_code"
fi
