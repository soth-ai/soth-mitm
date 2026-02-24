#!/usr/bin/env bash
set -euo pipefail

report_dir="artifacts/p4-differential"
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
run_case core_conformance cargo test -p mitm-core --test conformance_golden -q
run_case mitmproxy_tls_taxonomy cargo test -p mitm-sidecar --test mitmproxy_tls_adapter -q
run_case tls_learning_guardrails cargo test -p mitm-sidecar --test tls_learning_guardrails -q
run_case hudsucker_supported_surface_scope ./scripts/check_hudsucker_differential_scope.sh
run_case replay_drift_report ./scripts/p4_differential_replay.sh --report-dir "$report_dir/replay" --strict-input

failed="$(awk '$2 != "pass" {print $1}' "$status_tsv" || true)"
{
  echo "# Phase 4 Differential Validation"
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
