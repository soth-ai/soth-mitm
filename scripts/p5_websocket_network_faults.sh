#!/usr/bin/env bash
set -euo pipefail

report_dir="artifacts/p5-websocket-network-faults"
netfault_clients="${SOTH_MITM_WS_NETFAULT_CLIENTS:-72}"
chaos_clients="${SOTH_MITM_WS_CHAOS_CLIENTS:-120}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --report-dir)
      report_dir="$2"
      shift 2
      ;;
    --netfault-clients)
      netfault_clients="$2"
      shift 2
      ;;
    --chaos-clients)
      chaos_clients="$2"
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
    printf '%s\tpass\n' "$lane" >>"$status_tsv"
  else
    printf '%s\tfail\n' "$lane" >>"$status_tsv"
    return 1
  fi
}

: >"$status_tsv"
run_case websocket_netfault_profiles \
  env SOTH_MITM_WS_NETFAULT_CLIENTS="$netfault_clients" \
  cargo test -p mitm-sidecar --test websocket_reliability_soak \
    websocket_network_fault_lane_settles_without_stuck_flows -q || true
run_case websocket_chaos_reference \
  env SOTH_MITM_WS_CHAOS_CLIENTS="$chaos_clients" \
  cargo test -p mitm-sidecar --test websocket_reliability_soak \
    websocket_chaos_soak_mixed_lanes_settle_without_stuck_flows -q || true

failed="$(awk '$2 != "pass" {print $1}' "$status_tsv" || true)"
{
  echo "# Phase 5 WebSocket Network Fault Lane"
  echo
  echo "Generated: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo
  echo "Config:"
  echo "- netfault_clients: $netfault_clients"
  echo "- chaos_clients: $chaos_clients"
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
