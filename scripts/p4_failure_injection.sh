#!/usr/bin/env bash
set -euo pipefail

report_dir="artifacts/p4-failure-injection"
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
run_case tls_reset_timeout_invalid_chain_taxonomy cargo test -p mitm-sidecar --test mitmproxy_tls_adapter replayed_mitmproxy_failed_callbacks_match_native_taxonomy -q
run_case tls_unknown_ca_native_path cargo test -p mitm-sidecar --test http1_mitm intercept_upstream_tls_failure_emits_taxonomy_reason -q
run_case tls_fragmented_handshake_failure cargo test -p mitm-sidecar --test chaos_charter tls_fragmented_client_hello_emits_failed_handshake_close -q
run_case upstream_eof_mid_stream cargo test -p mitm-sidecar --test chaos_charter jitter_and_loss_in_tunnel_path_emit_relay_error_close -q

failed="$(awk '$2 != "pass" {print $1}' "$status_tsv" || true)"
{
  echo "# Phase 4 Failure Injection"
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
