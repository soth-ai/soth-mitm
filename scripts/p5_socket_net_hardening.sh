#!/usr/bin/env bash
set -euo pipefail

report_dir="artifacts/p5-socket-net-hardening"

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

record_status() {
  local lane="$1"
  local status="$2"
  local detail="$3"
  printf '%s\t%s\t%s\n' "$lane" "$status" "$detail" >>"$status_tsv"
}

run_case() {
  local lane="$1"
  shift
  if "$@"; then
    record_status "$lane" "pass" "ok"
  else
    record_status "$lane" "fail" "command_failed"
    return 1
  fi
}

: >"$status_tsv"

run_case sidecar_socket_hardening_ipv6 \
  cargo test -p mitm-sidecar --test socket_hardening -q
run_case route_matrix_socket_path \
  cargo test -p mitm-sidecar --test route_mode_matrix upstream_socks5_mode_honors_ignore_host_and_relays_tunnel -q
run_case runtime_pressure_instrumentation \
  cargo test -p mitm-sidecar --test runtime_governor \
    runtime_governor_enforces_concurrent_flow_limit_and_records_metrics -q

failed="$(awk '$2 == "fail" {print $1}' "$status_tsv" || true)"
{
  echo "# Phase 5 Cross-Platform Socket/Net Hardening"
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
