#!/usr/bin/env bash
set -euo pipefail

report_dir="artifacts/testing-artifacts"
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
index_tsv="$report_dir/index.tsv"
summary_md="$report_dir/summary.md"

sources=(
  artifacts/fixture-lab
  artifacts/tls-failure-fixtures
  artifacts/p2-protocol/triage
  artifacts/p4-performance
  artifacts/p4-failure-injection
  artifacts/p4-differential
  artifacts/p4-differential-replay
  artifacts/p4-chaos
  artifacts/p4-chaos-network
  artifacts/p4-tool-lanes
  artifacts/p4-hardening
  artifacts/p5-reliability-contract
  artifacts/p5-route-mode-matrix
  artifacts/p5-http2-resilience
  artifacts/p5-event-log-contract
  artifacts/p5-runtime-soak
  artifacts/fuzz-corpus
)

: >"$index_tsv"
printf 'source\tstatus_file\tsummary_file\n' >>"$index_tsv"

for source in "${sources[@]}"; do
  if [[ ! -d "$source" ]]; then
    printf '%s\t%s\t%s\n' "$source" "missing" "missing" >>"$index_tsv"
    continue
  fi

  status_file="${source}/status.tsv"
  summary_file="${source}/summary.md"

  status_value="missing"
  summary_value="missing"

  if [[ -f "$status_file" ]]; then
    base_name="$(echo "$source" | tr '/ ' '__')"
    cp "$status_file" "$report_dir/${base_name}.status.tsv"
    status_value="$status_file"
  fi

  if [[ -f "$summary_file" ]]; then
    base_name="$(echo "$source" | tr '/ ' '__')"
    cp "$summary_file" "$report_dir/${base_name}.summary.md"
    summary_value="$summary_file"
  fi

  printf '%s\t%s\t%s\n' "$source" "$status_value" "$summary_value" >>"$index_tsv"
done

missing_count="$(awk 'NR>1 && $2 == "missing" && $3 == "missing" {count++} END {print count+0}' "$index_tsv")"
present_count="$(awk 'NR>1 && ($2 != "missing" || $3 != "missing") {count++} END {print count+0}' "$index_tsv")"

{
  echo "# Testing Artifact Triage Bundle"
  echo
  echo "Generated: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo "Present sources: ${present_count}"
  echo "Missing sources: ${missing_count}"
  echo
  echo "## Index"
  echo
  echo '```tsv'
  cat "$index_tsv"
  echo '```'
} >"$summary_md"
