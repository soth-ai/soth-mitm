#!/usr/bin/env bash
set -euo pipefail

report_dir="artifacts/p6-reliability-integration"
strict_tools=0
soak_duration_seconds="${SOTH_MITM_SOAK_DURATION_SECONDS:-21600}"
soak_min_iterations="${SOTH_MITM_SOAK_MIN_ITERATIONS:-1}"
soak_exchange_timeout_seconds="${SOTH_MITM_SOAK_EXCHANGE_TIMEOUT_SECONDS:-60}"
soak_stage_timeout_seconds="${SOTH_MITM_SOAK_STAGE_TIMEOUT_SECONDS:-15}"
soak_h2_retries="${SOTH_MITM_SOAK_H2_RETRIES:-4}"
soak_h2_upstream_accept_timeout_seconds="${SOTH_MITM_SOAK_H2_UPSTREAM_ACCEPT_TIMEOUT_SECONDS:-10}"

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
    --duration-seconds)
      soak_duration_seconds="$2"
      shift 2
      ;;
    --min-iterations)
      soak_min_iterations="$2"
      shift 2
      ;;
    --exchange-timeout-seconds)
      soak_exchange_timeout_seconds="$2"
      shift 2
      ;;
    --stage-timeout-seconds)
      soak_stage_timeout_seconds="$2"
      shift 2
      ;;
    --h2-retries)
      soak_h2_retries="$2"
      shift 2
      ;;
    --h2-upstream-accept-timeout-seconds)
      soak_h2_upstream_accept_timeout_seconds="$2"
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
    echo -e "${lane}\tpass" >>"$status_tsv"
  else
    echo -e "${lane}\tfail" >>"$status_tsv"
    return 1
  fi
}

: >"$status_tsv"

run_case phase5_reliability_contract \
  ./scripts/p5_reliability_contract.sh \
  --report-dir "$report_dir/phase5-reliability-contract" || true

if [[ "$strict_tools" -eq 1 ]]; then
  run_case phase5_http2_resilience \
    ./scripts/p5_http2_resilience.sh \
    --strict-tools \
    --report-dir "$report_dir/phase5-http2-resilience" || true
else
  run_case phase5_http2_resilience \
    ./scripts/p5_http2_resilience.sh \
    --report-dir "$report_dir/phase5-http2-resilience" || true
fi

run_case phase5_runtime_soak \
  env \
    SOTH_MITM_SOAK_DURATION_SECONDS="$soak_duration_seconds" \
    SOTH_MITM_SOAK_MIN_ITERATIONS="$soak_min_iterations" \
    SOTH_MITM_SOAK_EXCHANGE_TIMEOUT_SECONDS="$soak_exchange_timeout_seconds" \
    ./scripts/p5_runtime_soak.sh \
    --report-dir "$report_dir/phase5-runtime-soak" || true

run_case mixed_traffic_close_reason_determinism \
  env \
    SOTH_MITM_SOAK_EXCHANGE_TIMEOUT_SECONDS="$soak_exchange_timeout_seconds" \
    SOTH_MITM_SOAK_STAGE_TIMEOUT_SECONDS="$soak_stage_timeout_seconds" \
    SOTH_MITM_SOAK_H2_RETRIES="$soak_h2_retries" \
    SOTH_MITM_SOAK_H2_UPSTREAM_ACCEPT_TIMEOUT_SECONDS="$soak_h2_upstream_accept_timeout_seconds" \
    cargo test -p mitm-sidecar --test mixed_traffic_soak \
      mixed_traffic_close_reasons_are_deterministic -q || true

run_case soth_mitm_reliability_fsm_contract \
  cargo test -p soth-mitm close_reason_summary_accepts_deterministic_stream_closes -q || true
run_case soth_mitm_reliability_timeout_budget_contract \
  cargo test -p soth-mitm runtime_timeout_budget_passes_for_expected_snapshot -q || true
run_case soth_mitm_reliability_http2_contract \
  cargo test -p soth-mitm http2_close_summary_accepts_stable_reasons -q || true

failed="$(awk '$2 != "pass" {print $1}' "$status_tsv" || true)"
{
  echo "# Phase 6 Reliability Integration Gate"
  echo
  echo "Generated: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo
  echo "Config:"
  echo "- strict_tools: ${strict_tools}"
  echo "- soak_duration_seconds: ${soak_duration_seconds}"
  echo "- soak_min_iterations: ${soak_min_iterations}"
  echo "- soak_exchange_timeout_seconds: ${soak_exchange_timeout_seconds}"
  echo "- soak_stage_timeout_seconds: ${soak_stage_timeout_seconds}"
  echo "- soak_h2_retries: ${soak_h2_retries}"
  echo "- soak_h2_upstream_accept_timeout_seconds: ${soak_h2_upstream_accept_timeout_seconds}"
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
