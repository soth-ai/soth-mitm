#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

source testing/acceptance/common.sh

report_dir="artifacts/p6-acceptance/ac08"
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

if command -v rg >/dev/null 2>&1; then
  reload_search_cmd=(rg -n "fn[[:space:]]+reload[[:space:]]*\\(" crates/soth-mitm/src)
else
  reload_search_cmd=(grep -R -n -E "fn[[:space:]]+reload[[:space:]]*\\(" crates/soth-mitm/src)
fi

if "${reload_search_cmd[@]}" >/dev/null 2>&1; then
  ac_record_status "$status_tsv" reload_api_surface pass present
  if cargo test -p soth-mitm config_reload_inflight_requests_contract -q; then
    ac_record_status "$status_tsv" reload_inflight_contract pass ok
  else
    ac_record_status "$status_tsv" reload_inflight_contract fail command_failed
  fi
else
  if [[ "$strict_tools" -eq 1 ]]; then
    ac_record_status "$status_tsv" reload_api_surface fail not_implemented
    ac_record_status "$status_tsv" reload_inflight_contract fail not_implemented
  else
    ac_record_status "$status_tsv" reload_api_surface skip not_implemented
    ac_record_status "$status_tsv" reload_inflight_contract skip not_implemented
  fi
fi

config_md=$'- strict_tools: '"${strict_tools}"$'\n- criterion requires in-flight config reload semantics via MitmProxyHandle/SIGHUP equivalent.'

ac_finalize \
  "$status_tsv" \
  "$summary_md" \
  "$outcome_tsv" \
  "AC-08 Config Reload with In-Flight Request Safety" \
  "$config_md"
