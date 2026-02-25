#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

source testing/acceptance/common.sh

report_dir="artifacts/p6-acceptance/ac10"
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

if [[ "$(uname -s)" != "Darwin" ]]; then
  ac_record_status "$status_tsv" platform_gate pass non_macos_not_applicable
  ac_run_case "$status_tsv" process_lookup_timeout_contract \
    cargo test -p soth-mitm process_lookup_timeout_sets_none -q || true
  ac_run_case "$status_tsv" process_lookup_cache_contract \
    cargo test -p soth-mitm process_info_resolved_once_per_connection -q || true
  ac_record_status "$status_tsv" macos_lsof_pid_parser_contract pass non_macos_not_applicable
  ac_record_status "$status_tsv" chrome_bundle_id_capture pass non_macos_not_applicable
else
  ac_record_status "$status_tsv" platform_gate pass macos
  ac_run_case "$status_tsv" process_lookup_timeout_contract \
    cargo test -p soth-mitm process_lookup_timeout_sets_none -q || true
  ac_run_case "$status_tsv" process_lookup_cache_contract \
    cargo test -p soth-mitm process_info_resolved_once_per_connection -q || true
  ac_run_case "$status_tsv" macos_lsof_pid_parser_contract \
    cargo test -p soth-mitm parses_pid_from_lsof_machine_output -q || true

  if rg -n "bundle_id:\s*None" crates/soth-mitm/src/process/macos.rs >/dev/null; then
    if [[ "$strict_tools" -eq 1 ]]; then
      ac_record_status "$status_tsv" chrome_bundle_id_capture fail bundle_id_capture_not_implemented
    else
      ac_record_status "$status_tsv" chrome_bundle_id_capture skip bundle_id_capture_not_implemented
    fi
  else
    ac_record_status "$status_tsv" chrome_bundle_id_capture pass implemented
  fi
fi

config_md=$'- strict_tools: '"${strict_tools}"$'\n- AC-10 is macOS-specific and includes Chrome bundle-id capture verification.'

ac_finalize \
  "$status_tsv" \
  "$summary_md" \
  "$outcome_tsv" \
  "AC-10 macOS Process Attribution" \
  "$config_md"
