#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

source testing/acceptance/common.sh

report_dir="artifacts/p6-acceptance/ac06"
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

ac_run_case "$status_tsv" destination_scope_passthrough_contract \
  cargo test -p soth-mitm destination_scope_intercept_vs_passthrough -q || true
ac_run_case "$status_tsv" tunnel_byte_identity \
  cargo test -p mitm-sidecar --test phase_a tunnel_action_relays_data_end_to_end -q || true
ac_run_case "$status_tsv" passthrough_no_tls_mitm \
  cargo test -p mitm-sidecar --test phase_a tunnel_action_does_not_emit_tls_handshake_events -q || true
ac_run_case "$status_tsv" http3_passthrough_no_tls_mitm \
  cargo test -p mitm-sidecar --test http3_passthrough_mitm \
    http3_hint_forces_tunnel_passthrough_and_emits_telemetry -q || true

config_md=$'- strict_tools: '"${strict_tools}"$'\n- verification: tunnel bytes + no TLS handshake events in passthrough paths'

ac_finalize \
  "$status_tsv" \
  "$summary_md" \
  "$outcome_tsv" \
  "AC-06 Passthrough Unlisted Destination Integrity" \
  "$config_md"
