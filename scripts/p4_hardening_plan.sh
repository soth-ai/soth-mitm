#!/usr/bin/env bash
set -euo pipefail

report_dir="artifacts/p4-hardening"
strict_tools=0
skip_network=0

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
    --skip-network)
      skip_network=1
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
run_case phase4_performance_gates ./scripts/p4_performance_gates.sh --report-dir "$report_dir/performance"
run_case phase4_failure_injection ./scripts/p4_failure_injection.sh --report-dir "$report_dir/failure-injection"
run_case phase4_differential_validation ./scripts/p4_differential_validation.sh --report-dir "$report_dir/differential"
run_case phase4_chaos_adversarial ./scripts/p4_chaos_adversarial.sh --report-dir "$report_dir/chaos"
run_case phase4_chaos_network_faults ./scripts/p4_chaos_network_faults.sh --report-dir "$report_dir/chaos-network"
if [[ "$strict_tools" -eq 1 ]]; then
  run_case phase4_tool_lanes ./scripts/p4_tool_lanes.sh --strict-tools --report-dir "$report_dir/tool-lanes"
else
  if [[ "$skip_network" -eq 1 ]]; then
    run_case phase4_tool_lanes ./scripts/p4_tool_lanes.sh --skip-network --report-dir "$report_dir/tool-lanes"
  else
    run_case phase4_tool_lanes ./scripts/p4_tool_lanes.sh --report-dir "$report_dir/tool-lanes"
  fi
fi

failed="$(awk '$2 != "pass" {print $1}' "$status_tsv" || true)"
{
  echo "# Phase 4 Hardening Plan Gate"
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
