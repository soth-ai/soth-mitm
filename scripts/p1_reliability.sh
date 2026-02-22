#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo_args=()
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

run_suite mitm_core cargo test -p mitm-core "${cargo_args[@]}"
run_suite mitm_tls cargo test -p mitm-tls "${cargo_args[@]}"
run_suite mitm_sidecar_lib cargo test -p mitm-sidecar --lib "${cargo_args[@]}"
run_suite phase_a_fixture cargo test -p mitm-sidecar --test phase_a "${cargo_args[@]}"
run_suite http1_mitm_fixture cargo test -p mitm-sidecar --test http1_mitm "${cargo_args[@]}"
run_suite tls_learning_guardrails_fixture cargo test -p mitm-sidecar --test tls_learning_guardrails "${cargo_args[@]}"
run_suite mitmproxy_tls_adapter_fixture cargo test -p mitm-sidecar --test mitmproxy_tls_adapter "${cargo_args[@]}"

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
