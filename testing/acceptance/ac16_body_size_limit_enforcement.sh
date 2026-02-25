#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

source testing/acceptance/common.sh

report_dir="artifacts/p6-acceptance/ac16"
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

ac_run_case "$status_tsv" body_limit_config_validation_contract \
  cargo test -p soth-mitm reject_zero_body_size_limit -q
ac_run_case "$status_tsv" body_limit_runtime_mapping_contract \
  cargo test -p soth-mitm body_size_limit_maps_to_core_runtime_budget -q
ac_run_case "$status_tsv" decoder_budget_clamp_contract \
  cargo test -p soth-mitm decoder_budget_is_clamped_by_body_size_limit -q
ac_run_case_with_socket_permission_fallback "$status_tsv" oversized_sse_decoder_budget_contract "$strict_tools" \
  cargo test -p mitm-sidecar --test chaos_charter \
    infinite_sse_stream_hits_decoder_budget_and_closes_deterministically -q
ac_run_case_with_socket_permission_fallback "$status_tsv" oversized_h2_header_rejection_contract "$strict_tools" \
  cargo test -p mitm-sidecar --test http2_mitm \
    http2_oversized_headers_emit_mitm_http_error_close -q

config_md=$'- strict_tools: '"${strict_tools}"$'\n- long_run: '"${long_run}"$'\n- scope: config/body budget validation and deterministic oversized payload/header rejection paths'

ac_finalize \
  "$status_tsv" \
  "$summary_md" \
  "$outcome_tsv" \
  "AC-16 Body Size Limit and Budget Enforcement" \
  "$config_md"
