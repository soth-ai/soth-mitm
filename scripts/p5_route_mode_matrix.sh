#!/usr/bin/env bash
set -euo pipefail

report_dir="artifacts/p5-route-mode-matrix"

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

run_case route_config_validation \
  cargo test -p mitm-core route_mode_requires_corresponding_endpoint -q
run_case route_config_rejects_unexpected_proxy_fields \
  cargo test -p mitm-core route_mode_rejects_unexpected_endpoint -q
run_case route_planner_unit_matrix \
  cargo test -p mitm-sidecar route_planner_ -q
run_case route_mode_integration_matrix \
  cargo test -p mitm-sidecar --test route_mode_matrix -q

failed="$(awk '$2 == "fail" {print $1}' "$status_tsv" || true)"
{
  echo "# Phase 5 Route Mode Matrix"
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
