#!/usr/bin/env bash
set -euo pipefail

report_dir="artifacts/p4-chaos"
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
run_case connect_and_lifecycle cargo test -p mitm-sidecar --test phase_a -q
run_case charter_chaos_cases cargo test -p mitm-sidecar --test chaos_charter -q
run_case http2_adversarial cargo test -p mitm-sidecar --test http2_mitm -q
run_case grpc_split_frames_parser cargo test -p mitm-http -q
run_case sse_incremental cargo test -p mitm-sidecar --test sse_mitm -q
run_case parser_safety cargo test -p mitm-http -q
run_case layered_decoder_fuzz_regression ./scripts/fuzz_decoder_layering_regression.sh --runs 64
run_case fuzz_harness_build cargo check --manifest-path fuzz/Cargo.toml

failed="$(awk '$2 != "pass" {print $1}' "$status_tsv" || true)"
{
  echo "# Phase 4 Chaos and Adversarial Suite"
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
