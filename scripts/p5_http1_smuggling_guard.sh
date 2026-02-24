#!/usr/bin/env bash
set -euo pipefail

report_dir="artifacts/p5-http1-smuggling-guard"

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

{
  run_case http1_parser_api_smuggling_guards \
    cargo test -p mitm-sidecar http_head_parser_api_tests -q
  run_case http1_smuggling_fixture_corpus \
    cargo test -p mitm-sidecar --test http1_head_corpus -q
  run_case http1_forward_absolute_form_proxy_semantics \
    cargo test -p mitm-sidecar --test http1_mitm \
      forward_http_absolute_form_request_relays_without_connect -q
  run_case http1_forward_te_cl_smuggling_rejected \
    cargo test -p mitm-sidecar --test http1_mitm \
      forward_proxy_rejects_te_cl_smuggling_request_with_deterministic_400 -q
  run_case http1_forward_https_absolute_form_rejected \
    cargo test -p mitm-sidecar --test http1_mitm \
      forward_proxy_rejects_https_absolute_form_with_deterministic_400 -q
  run_case http1_intercept_te_cl_smuggling_rejected \
    cargo test -p mitm-sidecar --test http1_mitm \
      intercept_path_rejects_te_cl_smuggling_before_upstream_http_bytes -q
} >"$run_log" 2>&1 || true

failed="$(awk '$2 != "pass" {print $1}' "$status_tsv" || true)"
{
  echo "# Phase 5 HTTP/1 Smuggling Guard Gate"
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
  echo
  echo "## Log"
  echo
  echo "See: $run_log"
} >"$summary_md"

if [[ -n "$failed" ]]; then
  exit 1
fi
