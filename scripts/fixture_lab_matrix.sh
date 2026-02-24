#!/usr/bin/env bash
set -euo pipefail

report_dir="artifacts/fixture-lab"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --report-dir)
      report_dir="$2"
      shift 2
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

run_case() {
  local lane="$1"
  shift
  if "$@"; then
    echo -e "${lane}\tpass" >>"$status_tsv"
  else
    echo -e "${lane}\tfail" >>"$status_tsv"
    return 1
  fi
}

: >"$status_tsv"
run_case connect_policy_and_lifecycle cargo test -p mitm-sidecar --test phase_a -q
run_case http1_fixture cargo test -p mitm-sidecar --test http1_mitm intercept_get_over_tls_forwards_and_emits_http_events -q
run_case http2_fixture cargo test -p mitm-sidecar --test http2_mitm intercept_http2_over_tls_relays_and_marks_protocol -q
run_case websocket_fixture cargo test -p mitm-sidecar --test websocket_mitm websocket_upgrade_relays_text_and_binary_frames_without_corruption -q
run_case sse_fixture cargo test -p mitm-sidecar --test sse_mitm parses_sse_events_incrementally_and_flushes_tail_on_stream_close -q
run_case grpc_fixture_parser cargo test -p mitm-http --lib -q
run_case http3_passthrough_fixture cargo test -p mitm-sidecar --test http3_passthrough_mitm http3_hint_forces_tunnel_passthrough_and_emits_telemetry -q
run_case tls_fixture_matrix ./scripts/tls_failure_fixtures.sh --report-dir "$report_dir/tls-fixtures"

failed="$(awk '$2 != "pass" {print $1}' "$status_tsv" || true)"
{
  echo "# Fixture Lab Matrix"
  echo
  echo "Generated: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo
  if [[ -z "$failed" ]]; then
    echo "Status: PASS"
  else
    echo "Status: FAIL"
    echo
    echo "Failed lanes:"
    echo "$failed"
  fi
  echo
  echo "## Lane Status"
  echo
  echo '```tsv'
  cat "$status_tsv"
  echo '```'
} >"$summary_md"

if [[ -n "$failed" ]]; then
  exit 1
fi
