#!/usr/bin/env bash
set -euo pipefail

report_dir="artifacts/p4-chaos-network"
strict_tools=0
enforce_faults=0

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
    --enforce-faults)
      enforce_faults=1
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
profiles_file="$report_dir/netem_profiles.tsv"
toxiproxy_plan_file="$report_dir/toxiproxy_profiles.tsv"

echo -e "profile\tcommand" >"$profiles_file"
echo -e "latency_100ms\ttc qdisc add dev lo root netem delay 100ms" >>"$profiles_file"
echo -e "loss_5pct\ttc qdisc change dev lo root netem loss 5%" >>"$profiles_file"
echo -e "reorder_10pct\ttc qdisc change dev lo root netem delay 40ms reorder 10% 50%" >>"$profiles_file"
echo -e "reset\ttc qdisc del dev lo root" >>"$profiles_file"

echo -e "profile\ttoxic" >"$toxiproxy_plan_file"
echo -e "latency_downstream\tlatency=150ms downstream" >>"$toxiproxy_plan_file"
echo -e "bandwidth_downstream\trate=256kbps downstream" >>"$toxiproxy_plan_file"
echo -e "timeout_upstream\ttimeout=1000ms upstream" >>"$toxiproxy_plan_file"
echo -e "reset_peer\treset_peer=1 downstream" >>"$toxiproxy_plan_file"

record_status() {
  local lane="$1"
  local status="$2"
  local detail="$3"
  printf '%s\t%s\t%s\n' "$lane" "$status" "$detail" >>"$status_tsv"
}

check_tool() {
  local lane="$1"
  local tool="$2"
  local version_cmd="$3"

  if ! command -v "$tool" >/dev/null 2>&1; then
    if [[ "$strict_tools" -eq 1 ]]; then
      record_status "$lane" "fail" "missing_tool:${tool}"
      return 1
    fi
    record_status "$lane" "skip" "missing_tool:${tool}"
    return 2
  fi

  if eval "$version_cmd" >"$report_dir/${tool}.version.txt" 2>&1; then
    record_status "$lane" "pass" "ok"
    return 0
  fi

  record_status "$lane" "fail" "version_probe_failed:${tool}"
  return 1
}

run_toxiproxy_live_probe() {
  local lane="toxiproxy_live_probe"
  if [[ "$enforce_faults" -ne 1 ]]; then
    record_status "$lane" "skip" "enforce_faults_disabled"
    return 0
  fi

  if ! command -v toxiproxy-server >/dev/null 2>&1 || ! command -v toxiproxy-cli >/dev/null 2>&1; then
    if [[ "$strict_tools" -eq 1 ]]; then
      record_status "$lane" "fail" "missing_tool:toxiproxy-server_or_cli"
      return 1
    fi
    record_status "$lane" "skip" "missing_tool:toxiproxy-server_or_cli"
    return 0
  fi

  local server_log="$report_dir/toxiproxy-server.log"
  toxiproxy-server -host 127.0.0.1 -port 8474 >"$server_log" 2>&1 &
  local server_pid=$!
  trap 'kill "$server_pid" >/dev/null 2>&1 || true' EXIT
  sleep 1

  if toxiproxy-cli -h 127.0.0.1:8474 list >"$report_dir/toxiproxy-list-before.txt" 2>&1; then
    record_status "$lane" "pass" "server_reachable"
  else
    record_status "$lane" "fail" "server_unreachable"
    return 1
  fi

  kill "$server_pid" >/dev/null 2>&1 || true
  trap - EXIT
  return 0
}

run_tc_live_probe() {
  local lane="tc_netem_live_probe"
  if [[ "$enforce_faults" -ne 1 ]]; then
    record_status "$lane" "skip" "enforce_faults_disabled"
    return 0
  fi

  if ! command -v tc >/dev/null 2>&1; then
    if [[ "$strict_tools" -eq 1 ]]; then
      record_status "$lane" "fail" "missing_tool:tc"
      return 1
    fi
    record_status "$lane" "skip" "missing_tool:tc"
    return 0
  fi

  if tc qdisc show dev lo >"$report_dir/tc-qdisc-before.txt" 2>&1; then
    record_status "$lane" "pass" "qdisc_visible"
  else
    record_status "$lane" "fail" "qdisc_probe_failed"
    return 1
  fi
}

: >"$status_tsv"
check_tool toxiproxy_tooling toxiproxy-cli "toxiproxy-cli --help" || true
check_tool tc_netem_tooling tc "tc -V" || true
record_status toxiproxy_fault_profile_plan "pass" "profiles_emitted"
record_status tc_netem_profile_plan "pass" "profiles_emitted"
run_toxiproxy_live_probe || true
run_tc_live_probe || true

failed="$(awk '$2 == "fail" {print $1}' "$status_tsv" || true)"
skipped="$(awk '$2 == "skip" {print $1}' "$status_tsv" || true)"
{
  echo "# Phase 4 Chaos Network Faults"
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
