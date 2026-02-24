#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

source testing/acceptance/common.sh

report_dir="artifacts/p6-acceptance/ac05"
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

ac_run_case "$status_tsv" block_unit_contract \
  cargo test -p soth-mitm block_prevents_any_upstream_connect -q || true
ac_run_case "$status_tsv" block_integration_no_upstream_socket \
  cargo test -p mitm-sidecar --test phase_a blocked_host_never_opens_upstream_socket -q || true

config_md=$'- strict_tools: '"${strict_tools}"$'\n- verification: local upstream assertion (no upstream accept)'

ac_finalize \
  "$status_tsv" \
  "$summary_md" \
  "$outcome_tsv" \
  "AC-05 Block Action Prevents Upstream Connection" \
  "$config_md"
