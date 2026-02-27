#!/usr/bin/env bash
set -euo pipefail

report_dir="artifacts/p6-tls-compat-pack"

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

if [[ "$report_dir" != /* ]]; then
  report_dir="$(pwd)/$report_dir"
fi

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

run_case tls_revocation_matrix \
  ./scripts/p6_tls_revocation_matrix.sh --report-dir "$report_dir/tls-revocation" || true

run_case tls_mtls_matrix \
  ./scripts/p6_tls_mtls_matrix.sh --report-dir "$report_dir/tls-mtls" || true

run_case tls_fingerprint_parity \
  ./scripts/p6_tls_fingerprint_parity.sh --report-dir "$report_dir/tls-fingerprint-parity" || true

failed="$(awk '$2 != "pass" {print $1}' "$status_tsv" || true)"
{
  echo "# Phase 6 TLS Compatibility Pack"
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
