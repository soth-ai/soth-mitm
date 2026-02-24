#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

input_root="${P2_TRIAGE_INPUT_ROOT:-artifacts/p2-protocol}"
output_dir="${P2_TRIAGE_OUTPUT_DIR:-artifacts/p2-protocol/triage}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --input-root)
      input_root="$2"
      shift 2
      ;;
    --output-dir)
      output_dir="$2"
      shift 2
      ;;
    *)
      echo "[p2-triage] unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ ! -d "$input_root" ]]; then
  echo "[p2-triage] input root does not exist: $input_root" >&2
  exit 2
fi

rm -rf "$output_dir"
mkdir -p "$output_dir"

summary_file="$output_dir/summary.md"
aggregate_file="$output_dir/status_aggregate.tsv"
failed_file="$output_dir/failed_lanes.txt"
missing_protocols_file="$output_dir/missing_protocols.txt"

required_protocols=(
  http2
  websocket
  sse
  http3_passthrough
  grpc_http2
  msgpack
)

echo -e "lane\tprotocol\tstatus\tlog_path\tsource_status_file" >"$aggregate_file"

status_files=()
while IFS= read -r status_file; do
  status_files+=("$status_file")
done < <(find "$input_root" -type f -name status.tsv | sort)

if [[ "${#status_files[@]}" -eq 0 ]]; then
  echo "[p2-triage] no status.tsv files found under $input_root" >&2
  exit 2
fi

for status_file in "${status_files[@]}"; do
  tail -n +2 "$status_file" | while IFS=$'\t' read -r lane protocol status log_path; do
    [[ -z "${lane:-}" ]] && continue
    echo -e "${lane}\t${protocol}\t${status}\t${log_path}\t${status_file}" >>"$aggregate_file"
  done
done

total_lanes="$(tail -n +2 "$aggregate_file" | wc -l | tr -d ' ')"
failed_lanes=()
observed_protocols=()

while IFS=$'\t' read -r lane _protocol status _log _source; do
  [[ "$lane" == "lane" ]] && continue
  observed_protocols+=("$_protocol")
  if [[ "$status" != "0" ]]; then
    failed_lanes+=("$lane")
  fi
done <"$aggregate_file"

missing_protocols=()
for required_protocol in "${required_protocols[@]}"; do
  protocol_found=0
  for observed_protocol in "${observed_protocols[@]}"; do
    if [[ "$observed_protocol" == "$required_protocol" ]]; then
      protocol_found=1
      break
    fi
  done
  if [[ "$protocol_found" -eq 0 ]]; then
    missing_protocols+=("$required_protocol")
  fi
done

{
  echo "# P2 Protocol Triage"
  echo
  echo "- generated_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "- input_root: \`$input_root\`"
  echo "- lanes_observed: ${total_lanes}"
  echo "- status_files_observed: ${#status_files[@]}"
  echo "- failed_lanes: ${#failed_lanes[@]}"
  echo "- required_protocols: ${#required_protocols[@]}"
  echo "- missing_protocols: ${#missing_protocols[@]}"
  echo
  echo "## Lane Status"
  echo
  echo "| lane | protocol | status | log | status source |"
  echo "| --- | --- | --- | --- | --- |"
  while IFS=$'\t' read -r lane protocol status log_path source_status_file; do
    [[ "$lane" == "lane" ]] && continue
    echo "| ${lane} | ${protocol} | ${status} | ${log_path} | ${source_status_file} |"
  done <"$aggregate_file"

  if [[ "${#missing_protocols[@]}" -gt 0 ]]; then
    echo
    echo "## Missing Required Protocol Coverage"
    echo
    for protocol in "${missing_protocols[@]}"; do
      echo "- ${protocol}"
    done
  fi
} >"$summary_file"

if [[ "${#failed_lanes[@]}" -gt 0 ]]; then
  printf '%s\n' "${failed_lanes[@]}" >"$failed_file"
  echo "[p2-triage] failures found (${#failed_lanes[@]}); see $summary_file" >&2
  exit 1
fi

: >"$failed_file"
if [[ "${#missing_protocols[@]}" -gt 0 ]]; then
  printf '%s\n' "${missing_protocols[@]}" >"$missing_protocols_file"
  echo "[p2-triage] required protocol coverage missing; see $summary_file" >&2
  exit 1
fi
: >"$missing_protocols_file"
echo "[p2-triage] protocol triage passed; summary at $summary_file"
