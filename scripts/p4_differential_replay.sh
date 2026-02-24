#!/usr/bin/env bash
set -euo pipefail

report_dir="artifacts/p4-differential-replay"
manifest="testing/differential/corpus/manifest.tsv"
input_root="testing/differential/samples"
strict_input=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --report-dir)
      report_dir="$2"
      shift 2
      ;;
    --manifest)
      manifest="$2"
      shift 2
      ;;
    --input-root)
      input_root="$2"
      shift 2
      ;;
    --strict-input)
      strict_input=1
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
drift_root="$report_dir/drift"
mkdir -p "$drift_root"

if [[ ! -f "$manifest" ]]; then
  echo "manifest not found: $manifest" >&2
  exit 2
fi

record_status() {
  local case_id="$1"
  local status="$2"
  local detail="$3"
  printf '%s\t%s\t%s\n' "$case_id" "$status" "$detail" >>"$status_tsv"
}

: >"$status_tsv"
printf 'case_id\tstatus\tdetail\n' >>"$status_tsv"

while IFS=$'\t' read -r case_id _description; do
  if [[ -z "${case_id:-}" ]] || [[ "${case_id:0:1}" == "#" ]]; then
    continue
  fi

  soth_file="$input_root/soth-mitm/${case_id}.events.tsv"
  mitm_file="$input_root/mitmproxy/${case_id}.events.tsv"

  if [[ ! -f "$soth_file" || ! -f "$mitm_file" ]]; then
    if [[ "$strict_input" -eq 1 ]]; then
      record_status "$case_id" "fail" "missing_input"
    else
      record_status "$case_id" "skip" "missing_input"
    fi
    continue
  fi

  if diff -u "$soth_file" "$mitm_file" >"$drift_root/${case_id}.diff"; then
    rm -f "$drift_root/${case_id}.diff"
    record_status "$case_id" "pass" "no_drift"
  else
    record_status "$case_id" "fail" "drift_detected"
  fi

done <"$manifest"

failed="$(awk 'NR>1 && $2 == "fail" {print $1}' "$status_tsv" || true)"
skipped="$(awk 'NR>1 && $2 == "skip" {print $1}' "$status_tsv" || true)"
{
  echo "# Differential Replay Drift Report"
  echo
  echo "Generated: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo
  if [[ -z "$failed" ]]; then
    echo "Status: PASS"
  else
    echo "Status: FAIL"
    echo
    echo "Drift detected in cases:"
    echo "$failed"
  fi
  if [[ -n "$skipped" ]]; then
    echo
    echo "Skipped cases:"
    echo "$skipped"
  fi
  echo
  echo "## Case Status"
  echo
  echo '```tsv'
  cat "$status_tsv"
  echo '```'
} >"$summary_md"

if [[ -n "$failed" ]]; then
  exit 1
fi
