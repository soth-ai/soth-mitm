#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

matrix_file="${P2_MATRIX_FILE:-scripts/p2_protocol_matrix.tsv}"
report_dir="${P2_REPORT_DIR:-artifacts/p2-protocol}"
selected_lane="${P2_PROTOCOL_LANE:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --matrix)
      matrix_file="$2"
      shift 2
      ;;
    --report-dir)
      report_dir="$2"
      shift 2
      ;;
    --lane)
      selected_lane="$2"
      shift 2
      ;;
    *)
      echo "[p2] unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ ! -f "$matrix_file" ]]; then
  echo "[p2] matrix file not found: $matrix_file" >&2
  exit 2
fi

rm -rf "$report_dir"
mkdir -p "$report_dir"

summary_file="$report_dir/summary.txt"
status_file="$report_dir/status.tsv"
failed_file="$report_dir/failed.txt"

{
  echo "p2_protocol_gate_started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "matrix_file=$matrix_file"
  echo "selected_lane=${selected_lane:-all}"
  echo "rustc=$(rustc --version)"
  echo "cargo=$(cargo --version)"
  echo "platform=$(uname -a)"
} >"$summary_file"
echo -e "lane\tprotocol\tstatus\tlog_path" >"$status_file"

failures=()
matched_lane=0

run_lane() {
  local lane="$1"
  local protocol="$2"
  local command="$3"

  local lane_dir="$report_dir/$lane"
  local log_file="$lane_dir/${lane}.log"
  mkdir -p "$lane_dir"

  if [[ "${OFFLINE:-0}" == "1" ]] && [[ "$command" == cargo\ * ]]; then
    command="${command} --offline"
  fi

  echo "[p2] running ${lane} (${protocol})" | tee -a "$summary_file"
  echo "[p2] command: ${command}" >>"$summary_file"

  set +e
  bash -lc "$command" 2>&1 | tee "$log_file"
  local cmd_status=${PIPESTATUS[0]}
  set -e

  echo -e "${lane}\t${protocol}\t${cmd_status}\t${log_file}" >>"$status_file"
  if [[ "$cmd_status" -ne 0 ]]; then
    failures+=("${lane}")
  fi
}

while IFS=$'\t' read -r lane protocol command; do
  if [[ -z "${lane:-}" ]] || [[ "${lane:0:1}" == "#" ]]; then
    continue
  fi
  if [[ -n "$selected_lane" ]] && [[ "$lane" != "$selected_lane" ]]; then
    continue
  fi
  matched_lane=1
  run_lane "$lane" "$protocol" "$command"
done <"$matrix_file"

if [[ "$matched_lane" -eq 0 ]]; then
  echo "[p2] no lane matched selection '${selected_lane}' in ${matrix_file}" >&2
  exit 2
fi

if [[ "${#failures[@]}" -gt 0 ]]; then
  {
    echo "failed_lanes=${#failures[@]}"
    printf '%s\n' "${failures[@]}"
  } >"$failed_file"
  echo "[p2] protocol gate failed; see ${report_dir}" | tee -a "$summary_file"
  exit 1
fi

echo "failed_lanes=0" >"$failed_file"
echo "[p2] protocol gate passed" | tee -a "$summary_file"
