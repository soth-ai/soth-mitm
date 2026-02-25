#!/usr/bin/env bash
set -euo pipefail

report_dir="artifacts/p5-http2-resilience"
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

check_h2spec_probe() {
  local lane="h2spec_probe"
  if ! command -v h2spec >/dev/null 2>&1; then
    if [[ "$strict_tools" -eq 1 ]]; then
      record_status "$lane" "fail" "missing_tool:h2spec"
      return 1
    fi
    record_status "$lane" "skip" "missing_tool:h2spec"
    return 0
  fi
  if h2spec --help >"$report_dir/h2spec.help.txt" 2>&1; then
    record_status "$lane" "pass" "ok"
    return 0
  fi
  record_status "$lane" "fail" "tool_probe_failed:h2spec"
  return 1
}

run_h2spec_blocking_criteria() {
  local lane="h2spec_blocking_criteria"
  local command="${SOTH_MITM_H2SPEC_BLOCKING_COMMAND:-./scripts/h2spec_blocking_smoke.sh}"
  if [[ -z "$command" ]]; then
    record_status "$lane" "fail" "not_configured"
    return 1
  fi

  if ! command -v h2spec >/dev/null 2>&1; then
    if [[ "$strict_tools" -eq 1 ]]; then
      record_status "$lane" "fail" "missing_tool:h2spec"
      return 1
    fi
    record_status "$lane" "skip" "missing_tool:h2spec"
    return 0
  fi

  if [[ "$command" == "./scripts/h2spec_blocking_smoke.sh" ]]; then
    local missing=()
    command -v nghttpd >/dev/null 2>&1 || missing+=("nghttpd")
    command -v openssl >/dev/null 2>&1 || missing+=("openssl")
    if [[ "${#missing[@]}" -gt 0 ]]; then
      if [[ "$strict_tools" -eq 1 ]]; then
        record_status "$lane" "fail" "missing_tools:${missing[*]}"
        return 1
      fi
      record_status "$lane" "skip" "missing_tools:${missing[*]}"
      return 0
    fi
  fi

  if /bin/zsh -lc "$command" >"$report_dir/h2spec.blocking.log" 2>&1; then
    record_status "$lane" "pass" "ok"
    return 0
  fi
  record_status "$lane" "fail" "blocking_command_failed"
  return 1
}

: >"$status_tsv"

run_case h2_parallel_stream_stress \
  cargo test -p mitm-sidecar --test http2_mitm \
    http2_parallel_stream_stress_keeps_completed_close_and_byte_accounting -q
run_case h2_upstream_cancel_reset_nonfatal \
  cargo test -p mitm-sidecar --test http2_mitm \
    http2_upstream_cancel_reset_on_single_stream_is_nonfatal_for_flow -q
run_case h2_header_limit_guard \
  cargo test -p mitm-sidecar --test http2_mitm \
    http2_oversized_headers_emit_mitm_http_error_close -q

check_h2spec_probe || true
run_h2spec_blocking_criteria || true

failed="$(awk '$2 == "fail" {print $1}' "$status_tsv" || true)"
skipped="$(awk '$2 == "skip" {print $1}' "$status_tsv" || true)"
{
  echo "# Phase 5 HTTP/2 Resilience"
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
