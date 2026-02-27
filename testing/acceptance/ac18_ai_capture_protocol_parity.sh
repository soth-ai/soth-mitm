#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

source testing/acceptance/common.sh

report_dir="artifacts/p6-acceptance/ac18"
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

ac_run_case_with_socket_permission_fallback "$status_tsv" h1_http10_absolute_form_contract "$strict_tools" \
  cargo test -p mitm-sidecar --test http1_mitm \
    forward_http10_absolute_form_request_relays_without_connect -q || true
ac_run_case_with_socket_permission_fallback "$status_tsv" h1_ai_capture_hook_host "$strict_tools" \
  cargo test -p mitm-sidecar --test http1_mitm \
    intercept_http11_request_hooks_receive_ai_host_header_for_capture -q || true
ac_run_case_with_socket_permission_fallback "$status_tsv" h2_ai_capture_hook_host "$strict_tools" \
  cargo test -p mitm-sidecar --test http2_mitm \
    intercept_http2_ai_host_request_hooks_receive_host_header_for_capture -q || true
ac_run_case_with_socket_permission_fallback "$status_tsv" h2_ai_tunnel_passthrough_guardrail "$strict_tools" \
  cargo test -p mitm-sidecar --test http2_mitm \
    ignored_ai_host_h2_tunnel_passthrough_relays_without_mitm_hooks -q || true

config_md=$'- strict_tools: '"${strict_tools}"$'\n- long_run: '"${long_run}"$'\n- scope: HTTP/1.0 baseline plus AI host capture parity and ignored-host HTTP/2 tunnel passthrough invariants'

ac_finalize \
  "$status_tsv" \
  "$summary_md" \
  "$outcome_tsv" \
  "AC-18 AI Capture Protocol Parity" \
  "$config_md"
