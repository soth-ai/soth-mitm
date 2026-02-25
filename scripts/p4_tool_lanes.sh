#!/usr/bin/env bash
set -euo pipefail

export PATH="/usr/local/cargo/bin:/usr/local/go/bin:${PATH}"

report_dir="artifacts/p4-tool-lanes"
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

run_lane() {
  local lane="$1"
  shift
  if "$@"; then
    record_status "$lane" "pass" "ok"
  else
    local code=$?
    if [[ "$code" -eq 2 ]]; then
      return 0
    fi
    if ! awk -F '\t' -v lane="$lane" '$1 == lane {found=1} END {exit !found}' "$status_tsv"; then
      record_status "$lane" "fail" "command_failed"
    fi
    return 1
  fi
}

runtime_issue_or_fail() {
  local lane="$1"
  local detail="$2"
  if [[ "$strict_tools" -eq 1 ]]; then
    record_status "$lane" "fail" "$detail"
    return 1
  fi
  record_status "$lane" "skip" "$detail"
  return 2
}

skip_or_fail_missing_tools() {
  local lane="$1"
  shift
  local missing=()
  local tool
  for tool in "$@"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      missing+=("$tool")
    fi
  done

  if [[ "${#missing[@]}" -eq 0 ]]; then
    return 0
  fi

  local detail="missing_tools:${missing[*]}"
  if [[ "$strict_tools" -eq 1 ]]; then
    record_status "$lane" "fail" "$detail"
    return 1
  fi

  record_status "$lane" "skip" "$detail"
  return 2
}

lane_h2spec() {
  local lane="h2spec"
  skip_or_fail_missing_tools "$lane" h2spec nghttpd openssl || return $?
  h2spec --help >"$report_dir/h2spec.help.txt" 2>&1
  ./scripts/h2spec_blocking_smoke.sh >"$report_dir/h2spec.blocking.log" 2>&1
}

lane_h2load() {
  local lane="h2load"
  skip_or_fail_missing_tools "$lane" h2load || return $?
  h2load --version >/dev/null 2>&1
}

lane_curl_proxy_matrix() {
  local lane="curl_proxy_http2_http3"
  skip_or_fail_missing_tools "$lane" curl || return $?

  local version_file="$report_dir/curl.version.txt"
  curl --version >"$version_file"

  if ! grep -q 'HTTP2' "$version_file"; then
    local detail="missing_curl_features:http2"
    if [[ "$strict_tools" -eq 1 ]]; then
      record_status "$lane" "fail" "$detail"
      return 1
    fi
    record_status "$lane" "skip" "$detail"
    return 2
  fi

  if ! grep -q 'HTTP3' "$version_file"; then
    echo "curl HTTP/3 feature missing; HTTP/3 checks are covered by dedicated H3/passthrough lanes." \
      >"$report_dir/curl.http3.note.txt"
  fi
  curl --help all >/dev/null 2>&1
}

lane_websocket_tools() {
  local lane="websocat_autobahn"
  skip_or_fail_missing_tools "$lane" websocat || return $?
  websocat --version >/dev/null 2>&1
  if command -v wstest >/dev/null 2>&1 && wstest -h >/dev/null 2>&1; then
    return 0
  fi
  if python3 -c 'import websocket' >/dev/null 2>&1; then
    return 0
  fi
  runtime_issue_or_fail "$lane" "autobahn_cli_unusable_python3_and_no_websocket_client"
  return $?
}

lane_grpc_tools() {
  local lane="grpcurl_ghz"
  skip_or_fail_missing_tools "$lane" grpcurl ghz || return $?
  grpcurl -help >/dev/null 2>&1
  ghz --help >/dev/null 2>&1
}

lane_tls_tools() {
  local args=(--report-dir "$report_dir/tls-hardening")
  if [[ "$strict_tools" -eq 1 ]]; then
    args+=(--strict-tools)
  fi
  if [[ "$skip_network" -eq 1 ]]; then
    args+=(--skip-network)
  fi
  ./scripts/p4_tls_hardening.sh "${args[@]}"
}

lane_perf_tools() {
  local lane="wrk_hey"
  skip_or_fail_missing_tools "$lane" wrk hey || return $?
  command -v wrk >/dev/null 2>&1
  command -v hey >/dev/null 2>&1
}

lane_fault_tools() {
  local lane="toxiproxy_tc_netem"
  skip_or_fail_missing_tools "$lane" toxiproxy-cli tc || return $?
  toxiproxy-cli --help >/dev/null 2>&1
  tc -V >/dev/null 2>&1
}

lane_proptest_and_fuzz() {
  local lane="proptest_cargo_fuzz"
  cargo test -p mitm-core --test connect_parser_proptest -q
  cargo test -p mitm-http --test grpc_envelope_proptest -q
  cargo test -p mitm-http --test sse_parser_proptest -q
  cargo test -p mitm-tls --test tls_classification_proptest -q
  cargo check --manifest-path fuzz/Cargo.toml
  ./scripts/fuzz_decoder_layering_regression.sh --runs 64
  ./scripts/fuzz_corpus_maintenance.sh --report-dir "$report_dir/fuzz-corpus" --runs 32
}

: >"$status_tsv"

run_lane h2spec lane_h2spec || true
run_lane h2load lane_h2load || true
run_lane curl_proxy_http2_http3 lane_curl_proxy_matrix || true
run_lane websocat_autobahn lane_websocket_tools || true
run_lane grpcurl_ghz lane_grpc_tools || true
run_lane openssl_testssl_badssl lane_tls_tools || true
run_lane wrk_hey lane_perf_tools || true
run_lane toxiproxy_tc_netem lane_fault_tools || true
run_lane proptest_cargo_fuzz lane_proptest_and_fuzz || true

failed="$(awk '$2 == "fail" {print $1}' "$status_tsv" || true)"
skipped="$(awk '$2 == "skip" {print $1}' "$status_tsv" || true)"
{
  echo "# Phase 4 Tool Lanes"
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
