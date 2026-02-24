#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

matrix_file="${P2_MATRIX_FILE:-scripts/p2_protocol_matrix.tsv}"
report_root="${P2_REPORT_ROOT:-artifacts/p2-protocol}"
triage_output="${P2_TRIAGE_OUTPUT_DIR:-$report_root/triage}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --matrix)
      matrix_file="$2"
      shift 2
      ;;
    --report-root)
      report_root="$2"
      shift 2
      ;;
    --triage-output)
      triage_output="$2"
      shift 2
      ;;
    *)
      echo "[p2-matrix] unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ ! -f "$matrix_file" ]]; then
  echo "[p2-matrix] matrix file not found: $matrix_file" >&2
  exit 2
fi

rm -rf "$report_root"
mkdir -p "$report_root"

lane_failures=0
while IFS=$'\t' read -r lane _protocol _command; do
  if [[ -z "${lane:-}" ]] || [[ "${lane:0:1}" == "#" ]]; then
    continue
  fi
  echo "[p2-matrix] executing lane: $lane"
  set +e
  OFFLINE="${OFFLINE:-0}" \
    ./scripts/p2_protocol_gate.sh \
      --matrix "$matrix_file" \
      --lane "$lane" \
      --report-dir "$report_root/$lane"
  lane_status=$?
  set -e
  if [[ "$lane_status" -ne 0 ]]; then
    lane_failures=$((lane_failures + 1))
  fi
done <"$matrix_file"

set +e
./scripts/p2_protocol_triage.sh --input-root "$report_root" --output-dir "$triage_output"
triage_status=$?
set -e

if [[ "$lane_failures" -gt 0 ]] || [[ "$triage_status" -ne 0 ]]; then
  echo "[p2-matrix] protocol matrix failed; see $triage_output" >&2
  exit 1
fi

echo "[p2-matrix] protocol matrix passed; see $triage_output"
