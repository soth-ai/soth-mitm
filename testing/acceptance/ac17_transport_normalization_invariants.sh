#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

source testing/acceptance/common.sh

report_dir="artifacts/p6-acceptance/ac17"
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

ac_run_case "$status_tsv" hop_by_hop_header_strip_matrix \
  cargo test -p soth-mitm header_preservation_and_strip_matrix -q
ac_run_case_with_socket_permission_fallback "$status_tsv" sse_stream_chunk_normalization "$strict_tools" \
  cargo test -p mitm-sidecar --test sse_mitm \
    parses_sse_events_incrementally_and_flushes_tail_on_stream_close -q
ac_run_case_with_socket_permission_fallback "$status_tsv" grpc_unary_frame_normalization "$strict_tools" \
  cargo test -p mitm-sidecar --test grpc_http2_mitm \
    grpc_unary_http2_emits_header_and_trailer_events_in_stable_sequence -q
ac_run_case_with_socket_permission_fallback "$status_tsv" grpc_stream_frame_normalization "$strict_tools" \
  cargo test -p mitm-sidecar --test grpc_http2_mitm \
    grpc_streaming_http2_path_pattern_detection_emits_stable_sequence -q
ac_run_case_with_socket_permission_fallback "$status_tsv" websocket_frame_normalization "$strict_tools" \
  cargo test -p mitm-sidecar --test websocket_mitm \
    websocket_upgrade_relays_text_and_binary_frames_without_corruption -q
ac_run_case_with_socket_permission_fallback "$status_tsv" websocket_turn_boundary_normalization "$strict_tools" \
  cargo test -p mitm-sidecar --test websocket_mitm \
    websocket_server_initiated_turns_emit_expected_boundaries -q

config_md=$'- strict_tools: '"${strict_tools}"$'\n- long_run: '"${long_run}"$'\n- scope: transport normalization contracts for header rewrite, SSE, gRPC framing, and WebSocket framing/turn boundaries'

ac_finalize \
  "$status_tsv" \
  "$summary_md" \
  "$outcome_tsv" \
  "AC-17 Transport Normalization Invariants" \
  "$config_md"
