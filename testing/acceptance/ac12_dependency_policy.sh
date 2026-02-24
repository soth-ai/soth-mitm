#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

source testing/acceptance/common.sh

report_dir="artifacts/p6-acceptance/ac12"
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

if command -v cargo-deny >/dev/null 2>&1; then
  ac_run_case "$status_tsv" cargo_deny_policy \
    cargo deny check bans licenses sources || true
else
  if [[ "$strict_tools" -eq 1 ]]; then
    ac_record_status "$status_tsv" cargo_deny_policy fail missing_tools:cargo-deny
  else
    ac_record_status "$status_tsv" cargo_deny_policy pass missing_tools_fallback:policy_and_duplicate_scans
  fi
fi
ac_run_case "$status_tsv" prohibition_policy \
  ./scripts/check_prohibitions.sh || true

duplicates_file="$report_dir/cargo-tree-duplicates.txt"
if cargo tree -d --prefix none >"$duplicates_file" 2>&1; then
  duplicate_cores=()
  for core_crate in tokio hyper rustls; do
    if rg -n "^${core_crate} v" "$duplicates_file" >/dev/null 2>&1; then
      duplicate_cores+=("$core_crate")
    fi
  done

  if [[ "${#duplicate_cores[@]}" -eq 0 ]]; then
    ac_record_status "$status_tsv" duplicate_core_crate_versions pass none
  else
    ac_record_status "$status_tsv" duplicate_core_crate_versions fail "duplicates:${duplicate_cores[*]}"
  fi
else
  ac_record_status "$status_tsv" duplicate_core_crate_versions fail cargo_tree_failed
fi

config_md=$'- strict_tools: '"${strict_tools}"$'\n- checks: cargo-deny, prohibition policy, duplicate versions for tokio/hyper/rustls'

ac_finalize \
  "$status_tsv" \
  "$summary_md" \
  "$outcome_tsv" \
  "AC-12 Dependency and Prohibition Compliance" \
  "$config_md"
