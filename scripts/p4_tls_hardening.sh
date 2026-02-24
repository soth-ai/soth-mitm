#!/usr/bin/env bash
set -euo pipefail

report_dir="artifacts/p4-tls-hardening"
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

check_or_skip_tool() {
  local lane="$1"
  local tool="$2"
  local version_cmd="$3"

  if ! command -v "$tool" >/dev/null 2>&1; then
    if [[ "$strict_tools" -eq 1 ]]; then
      record_status "$lane" "fail" "missing_tool:${tool}"
      return 1
    fi
    record_status "$lane" "skip" "missing_tool:${tool}"
    return 0
  fi

  if eval "$version_cmd" >"$report_dir/${tool}.version.txt" 2>&1; then
    record_status "$lane" "pass" "ok"
    return 0
  fi

  record_status "$lane" "fail" "tool_probe_failed:${tool}"
  return 1
}

: >"$status_tsv"
run_case tls_failure_fixture_matrix ./scripts/tls_failure_fixtures.sh --report-dir "$report_dir/tls-fixtures"
run_case tls_taxonomy_adapter cargo test -p mitm-sidecar --test mitmproxy_tls_adapter replayed_mitmproxy_failed_callbacks_match_native_taxonomy -q
run_case tls_learning_guardrails cargo test -p mitm-sidecar --test tls_learning_guardrails -q
check_or_skip_tool openssl_client_probe openssl "openssl version"
check_or_skip_tool testssl_probe testssl.sh "testssl.sh --version"

if [[ "$skip_network" -eq 1 ]]; then
  record_status badssl_probe skip network_checks_disabled
else
  if command -v curl >/dev/null 2>&1 && curl --fail --silent --show-error --max-time 10 https://badssl.com >/dev/null; then
    record_status badssl_probe pass reachable
  else
    if [[ "$strict_tools" -eq 1 ]]; then
      record_status badssl_probe fail badssl_unreachable
    else
      record_status badssl_probe skip badssl_unreachable
    fi
  fi
fi

failed="$(awk '$2 == "fail" {print $1}' "$status_tsv" || true)"
skipped="$(awk '$2 == "skip" {print $1}' "$status_tsv" || true)"
{
  echo "# Phase 4 TLS Hardening"
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
  if [[ -n "$skipped" ]]; then
    echo
    echo "Skipped lanes:"
    echo "$skipped"
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
