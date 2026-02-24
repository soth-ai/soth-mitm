#!/usr/bin/env bash
set -euo pipefail

report_dir="artifacts/p5-event-log-contract"

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

: >"$status_tsv"

run_case observe_v2_deterministic_record \
  cargo test -p mitm-observe --test event_log_v2 deterministic_record_v2_ -q
run_case observe_v2_rotation_index \
  cargo test -p mitm-observe --test event_log_v2 \
    event_log_v2_consumer_writes_index_and_rotates_segments -q
run_case sidecar_automation_exit_contract \
  cargo test -p mitm-sidecar --test automation_contract -q
run_case differential_replay_v2_fixture_contract \
  ./scripts/p4_differential_replay.sh --report-dir "$report_dir/differential-replay" --strict-input

failed="$(awk '$2 == "fail" {print $1}' "$status_tsv" || true)"
{
  echo "# Phase 5 Event Log v2 + Automation Contract"
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
