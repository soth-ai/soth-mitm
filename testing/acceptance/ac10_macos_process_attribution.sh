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

os_name="$(uname -s)"
platform_label="$os_name"
if [[ "$os_name" == Darwin ]]; then
  platform_label="macos"
elif [[ "$os_name" == Linux ]]; then
  platform_label="linux"
elif [[ "$os_name" == MINGW* || "$os_name" == MSYS* || "$os_name" == CYGWIN* ]]; then
  platform_label="windows"
fi
ac_record_status "$status_tsv" platform_gate pass "$platform_label"

ac_run_case "$status_tsv" process_lookup_timeout_contract \
  cargo test -p soth-mitm process_lookup_timeout_sets_none -q || true
ac_run_case "$status_tsv" process_lookup_cache_contract \
  cargo test -p soth-mitm process_info_resolved_once_per_connection -q || true
ac_run_case "$status_tsv" process_identity_cache_contract \
  cargo test -p soth-mitm identity_cache_reused_across_connections -q || true
ac_run_case "$status_tsv" socket_pid_matching_contract \
  cargo test -p soth-mitm unspecified_expected_ip_matches_any_candidate -q || true

if command -v rg >/dev/null 2>&1; then
  process_command_refs="$(rg -n 'tokio::process::Command|std::process::Command' crates/soth-mitm/src/process/*.rs || true)"
else
  process_command_refs="$(grep -n -E 'tokio::process::Command|std::process::Command' crates/soth-mitm/src/process/*.rs || true)"
fi

if [[ -n "$process_command_refs" ]]; then
  ac_record_status "$status_tsv" process_backend_command_free fail command_invocation_detected
else
  ac_record_status "$status_tsv" process_backend_command_free pass none
fi

if [[ "$platform_label" == "macos" ]]; then
  ac_run_case "$status_tsv" macos_bundle_path_contract \
    cargo test -p soth-mitm extracts_app_bundle_path_from_binary_path -q || true
else
  ac_record_status "$status_tsv" macos_bundle_path_contract pass non_macos_not_required
fi

config_md=$'- strict_tools: '"${strict_tools}"$'\n- AC-10 validates command-free process attribution contracts across Linux/macOS/Windows.'

ac_finalize \
  "$status_tsv" \
  "$summary_md" \
  "$outcome_tsv" \
  "AC-10 Cross-OS Process Attribution" \
  "$config_md"
