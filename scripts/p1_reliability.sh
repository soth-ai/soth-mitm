#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

declare -a cargo_args=()
if [[ "${OFFLINE:-0}" == "1" ]]; then
  cargo_args+=(--offline)
fi

report_dir="${P1_REPORT_DIR:-artifacts/p1-reliability}"
summary_file="$report_dir/summary.txt"
status_file="$report_dir/status.tsv"
failed_file="$report_dir/failed.txt"

rm -rf "$report_dir"
mkdir -p "$report_dir"

{
  echo "p1_reliability_started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "rustc=$(rustc --version)"
  echo "cargo=$(cargo --version)"
  echo "platform=$(uname -a)"
} >"$summary_file"
echo -e "suite\tstatus" >"$status_file"

failures=()

run_suite() {
  local suite_name="$1"
  shift
  local log_file="$report_dir/${suite_name}.log"
  echo "[p1] running ${suite_name}" | tee -a "$summary_file"
  set +e
  "$@" 2>&1 | tee "$log_file"
  local cmd_status=${PIPESTATUS[0]}
  set -e
  echo -e "${suite_name}\t${cmd_status}" >>"$status_file"
  if [[ "$cmd_status" -ne 0 ]]; then
    failures+=("$suite_name")
  fi
}

run_cargo_suite() {
  local suite_name="$1"
  shift
  if [[ "${#cargo_args[@]}" -gt 0 ]]; then
    run_suite "$suite_name" cargo test "$@" "${cargo_args[@]}"
  else
    run_suite "$suite_name" cargo test "$@"
  fi
}

run_cargo_suite mitm_core -p mitm-core
run_cargo_suite mitm_tls -p mitm-tls
run_cargo_suite mitm_sidecar_lib -p mitm-sidecar --lib
run_cargo_suite phase_a_fixture -p mitm-sidecar --test phase_a
run_cargo_suite http1_mitm_fixture -p mitm-sidecar --test http1_mitm
run_cargo_suite tls_learning_guardrails_fixture -p mitm-sidecar --test tls_learning_guardrails
run_cargo_suite mitmproxy_tls_adapter_fixture -p mitm-sidecar --test mitmproxy_tls_adapter

if [[ "${#failures[@]}" -gt 0 ]]; then
  {
    echo "failed_suites=${#failures[@]}"
    printf '%s\n' "${failures[@]}"
  } >"$failed_file"
  echo "[p1] reliability gate failed; see ${report_dir}" | tee -a "$summary_file"
  exit 1
fi

echo "failed_suites=0" >"$failed_file"
echo "[p1] reliability gate passed" | tee -a "$summary_file"
