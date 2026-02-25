#!/usr/bin/env bash
set -euo pipefail

report_dir="artifacts/p5-runtime-soak"
duration_seconds="${SOTH_MITM_SOAK_DURATION_SECONDS:-21600}"
min_iterations="${SOTH_MITM_SOAK_MIN_ITERATIONS:-1}"
soak_exchanges="${SOTH_MITM_SOAK_EXCHANGES:-tunnel,forward,tls_http1,tls_sse,tls_h2}"
strict_gate=0
strict_min_duration_seconds="${SOTH_MITM_SOAK_STRICT_MIN_DURATION_SECONDS:-21600}"
strict_max_duration_seconds="${SOTH_MITM_SOAK_STRICT_MAX_DURATION_SECONDS:-43200}"
strict_required_exchanges="${SOTH_MITM_SOAK_STRICT_REQUIRED_EXCHANGES:-tunnel,forward,tls_http1,tls_sse,tls_h2}"

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
    --strict-gate)
      strict_gate=1
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
run_log="$report_dir/run.log"

is_uint() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

contains_required_exchanges() {
  local configured="$1"
  local required="$2"
  local exchange
  for exchange in ${required//,/ }; do
    [[ -z "$exchange" ]] && continue
    if [[ ",${configured}," != *",${exchange},"* ]]; then
      return 1
    fi
  done
  return 0
}

validate_strict_config() {
  if ! is_uint "$strict_min_duration_seconds" || ! is_uint "$strict_max_duration_seconds"; then
    echo "strict gate requires integer strict duration bounds, got min=${strict_min_duration_seconds} max=${strict_max_duration_seconds}" >&2
    return 1
  fi
  if ! is_uint "$duration_seconds"; then
    echo "strict gate requires integer --duration-seconds, got: $duration_seconds" >&2
    return 1
  fi
  if (( strict_max_duration_seconds < strict_min_duration_seconds )); then
    echo "strict gate duration bounds invalid: min=${strict_min_duration_seconds} max=${strict_max_duration_seconds}" >&2
    return 1
  fi
  if ! is_uint "$min_iterations"; then
    echo "strict gate requires integer --min-iterations, got: $min_iterations" >&2
    return 1
  fi
  if (( duration_seconds < strict_min_duration_seconds || duration_seconds > strict_max_duration_seconds )); then
    echo "strict gate duration must be between ${strict_min_duration_seconds}s and ${strict_max_duration_seconds}s, got: ${duration_seconds}s" >&2
    return 1
  fi
  if (( min_iterations < 1 )); then
    echo "strict gate requires min_iterations >= 1, got: ${min_iterations}" >&2
    return 1
  fi
  if ! contains_required_exchanges "$soak_exchanges" "$strict_required_exchanges"; then
    echo "strict gate requires exchanges to include: ${strict_required_exchanges}; got: ${soak_exchanges}" >&2
    return 1
  fi
  return 0
}

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

strict_config_ok=1
if [[ "$strict_gate" -eq 1 ]]; then
  if run_case strict_gate_config validate_strict_config; then
    strict_config_ok=1
  else
    strict_config_ok=0
  fi
fi

if [[ "$strict_config_ok" -eq 1 ]]; then
  if ! run_case mixed_traffic_runtime_budget_soak \
    env \
      SOTH_MITM_SOAK_SECONDS="$duration_seconds" \
      SOTH_MITM_SOAK_MIN_ITERATIONS="$min_iterations" \
      SOTH_MITM_SOAK_EXCHANGES="$soak_exchanges" \
      cargo test -p mitm-sidecar --test mixed_traffic_soak \
        mixed_traffic_soak_respects_runtime_budget_envelope -q \
    >"$run_log" 2>&1; then
    true
  fi
else
  echo -e "mixed_traffic_runtime_budget_soak\tfail" >>"$status_tsv"
  : >"$run_log"
fi

if [[ "$strict_gate" -eq 1 ]]; then
  if [[ "$strict_config_ok" -eq 0 ]]; then
    echo -e "strict_gate_no_skip\tfail" >>"$status_tsv"
    echo -e "strict_gate_test_result\tfail" >>"$status_tsv"
  else
    if rg -n "skipping mixed_traffic_soak_respects_runtime_budget_envelope" "$run_log" >/dev/null 2>&1; then
      echo -e "strict_gate_no_skip\tfail" >>"$status_tsv"
    else
      echo -e "strict_gate_no_skip\tpass" >>"$status_tsv"
    fi
    if rg -n "test result: ok\\." "$run_log" >/dev/null 2>&1; then
      echo -e "strict_gate_test_result\tpass" >>"$status_tsv"
    else
      echo -e "strict_gate_test_result\tfail" >>"$status_tsv"
    fi
  fi
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
  echo "- exchanges: $soak_exchanges"
  echo "- strict_gate: $strict_gate"
  if [[ "$strict_gate" -eq 1 ]]; then
    echo "- strict_min_duration_seconds: $strict_min_duration_seconds"
    echo "- strict_max_duration_seconds: $strict_max_duration_seconds"
    echo "- strict_required_exchanges: $strict_required_exchanges"
  fi
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
