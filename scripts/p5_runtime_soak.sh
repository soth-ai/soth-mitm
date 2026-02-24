#!/usr/bin/env bash
set -euo pipefail

report_dir="artifacts/p5-runtime-soak"
duration_seconds="${SOTH_MITM_SOAK_DURATION_SECONDS:-21600}"
min_iterations="${SOTH_MITM_SOAK_MIN_ITERATIONS:-1}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --report-dir)
      report_dir="$2"
      shift 2
      ;;
    --duration-seconds)
      duration_seconds="$2"
      shift 2
      ;;
    --min-iterations)
      min_iterations="$2"
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
run_log="$report_dir/run.log"

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

if ! run_case mixed_traffic_runtime_budget_soak \
  env \
    SOTH_MITM_SOAK_SECONDS="$duration_seconds" \
    SOTH_MITM_SOAK_MIN_ITERATIONS="$min_iterations" \
    cargo test -p mitm-sidecar --test mixed_traffic_soak \
      mixed_traffic_soak_respects_runtime_budget_envelope -q \
  >"$run_log" 2>&1; then
  true
fi

failed="$(awk '$2 != "pass" {print $1}' "$status_tsv" || true)"
{
  echo "# Phase 5 Runtime Soak Gate"
  echo
  echo "Generated: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo
  echo "Config:"
  echo "- duration_seconds: $duration_seconds"
  echo "- min_iterations: $min_iterations"
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
  echo
  echo "## Log"
  echo
  echo "See: $run_log"
} >"$summary_md"

if [[ -n "$failed" ]]; then
  exit 1
fi
