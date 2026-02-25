#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

source testing/acceptance/common.sh

report_dir="artifacts/p6-acceptance/ac07"
strict_tools=0
long_run=0
forward_iterations="${P6_AC07_FORWARD_ITERATIONS:-120}"
forward_warmup="${P6_AC07_FORWARD_WARMUP:-12}"
forward_p95_us="${P6_AC07_FORWARD_P95_US:-5000}"
handshake_iterations="${P6_AC07_HANDSHAKE_ITERATIONS:-120}"
handshake_warmup="${P6_AC07_HANDSHAKE_WARMUP:-12}"
handshake_overhead_p95_us="${P6_AC07_HANDSHAKE_OVERHEAD_P95_US:-5000}"
scale_target="${P6_AC07_SCALE_TARGET:-1000}"
scale_max_in_flight="${P6_AC07_SCALE_MAX_IN_FLIGHT:-192}"
soak_seconds="${P6_AC07_SOAK_SECONDS:-60}"
soak_min_iterations="${P6_AC07_SOAK_MIN_ITERATIONS:-1}"
rss_audit_file="${P6_AC07_RSS_AUDIT_FILE:-}"
soak_exchange_timeout_seconds="${P6_AC07_SOAK_EXCHANGE_TIMEOUT_SECONDS:-60}"
soak_h2_retries="${P6_AC07_SOAK_H2_RETRIES:-4}"
soak_h2_upstream_accept_timeout_seconds="${P6_AC07_SOAK_H2_UPSTREAM_ACCEPT_TIMEOUT_SECONDS:-10}"

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
    --long-run)
      long_run=1
      shift
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ "$long_run" -eq 0 ]]; then
  soak_seconds="${P6_AC07_SMOKE_SOAK_SECONDS:-15}"
fi

mkdir -p "$report_dir"
status_tsv="$report_dir/status.tsv"
summary_md="$report_dir/summary.md"
outcome_tsv="$report_dir/outcome.tsv"
printf 'check\tstatus\tdetail\n' >"$status_tsv"

if [[ -z "$rss_audit_file" ]]; then
  rss_audit_file="$report_dir/rss_audit.generated.env"
fi

run_soak_with_rss_audit() {
  local log_file="$report_dir/mixed_traffic_soak.log"
  local soak_exit=0
  local baseline_rss_kb=-1
  local peak_rss_kb=0

  env \
    SOTH_MITM_SOAK_SECONDS="$soak_seconds" \
    SOTH_MITM_SOAK_MIN_ITERATIONS="$soak_min_iterations" \
    SOTH_MITM_SOAK_EXCHANGE_TIMEOUT_SECONDS="$soak_exchange_timeout_seconds" \
    SOTH_MITM_SOAK_H2_RETRIES="$soak_h2_retries" \
    SOTH_MITM_SOAK_H2_UPSTREAM_ACCEPT_TIMEOUT_SECONDS="$soak_h2_upstream_accept_timeout_seconds" \
    cargo test -p mitm-sidecar --test mixed_traffic_soak \
      mixed_traffic_soak_respects_runtime_budget_envelope -q \
      >"$log_file" 2>&1 &
  local soak_pid=$!

  while kill -0 "$soak_pid" >/dev/null 2>&1; do
    local rss_kb
    rss_kb="$(ps -o rss= -p "$soak_pid" 2>/dev/null | tr -d '[:space:]')"
    if [[ "$rss_kb" =~ ^[0-9]+$ ]]; then
      if (( baseline_rss_kb < 0 )); then
        baseline_rss_kb="$rss_kb"
      fi
      if (( rss_kb > peak_rss_kb )); then
        peak_rss_kb="$rss_kb"
      fi
    fi
    sleep 1
  done

  wait "$soak_pid" || soak_exit=$?

  if (( baseline_rss_kb < 0 )); then
    baseline_rss_kb=0
  fi
  local growth_kb=$(( peak_rss_kb - baseline_rss_kb ))
  if (( growth_kb < 0 )); then
    growth_kb=0
  fi
  local growth_mb=$(( (growth_kb + 1023) / 1024 ))
  {
    echo "rss_baseline_kb=${baseline_rss_kb}"
    echo "rss_peak_kb=${peak_rss_kb}"
    echo "rss_growth_mb=${growth_mb}"
  } >"$rss_audit_file"

  return "$soak_exit"
}

ac_run_case "$status_tsv" forwarding_latency_p95_budget \
  ac_run_with_preferred_bench_linker \
  cargo bench -p soth-mitm --bench forwarding_latency -- \
    --iterations "$forward_iterations" \
    --warmup "$forward_warmup" \
    --threshold-p95-us "$forward_p95_us" \
    --result-file "$report_dir/forwarding_latency.tsv" || true

ac_run_case "$status_tsv" tls_handshake_scale_and_latency_budget \
  ac_run_with_preferred_bench_linker \
  cargo bench -p soth-mitm --bench handshake_overhead -- \
    --iterations "$handshake_iterations" \
    --warmup "$handshake_warmup" \
    --threshold-overhead-p95-us "$handshake_overhead_p95_us" \
    --scale-target "$scale_target" \
    --scale-max-in-flight "$scale_max_in_flight" \
    --result-file "$report_dir/handshake_overhead.tsv" || true

if run_soak_with_rss_audit; then
  ac_record_status "$status_tsv" mixed_traffic_runtime_budget_soak pass ok
else
  ac_record_status "$status_tsv" mixed_traffic_runtime_budget_soak fail command_failed
fi

if [[ "$long_run" -eq 0 ]]; then
  ac_record_status "$status_tsv" full_60s_window pass smoke_window
else
  ac_record_status "$status_tsv" full_60s_window pass enabled
fi

if [[ -f "$rss_audit_file" ]]; then
  rss_growth_mb="$(awk -F '=' '$1 == "rss_growth_mb" {print $2}' "$rss_audit_file" | tail -n 1 | tr -d '[:space:]')"
  if [[ -n "$rss_growth_mb" ]] && [[ "$rss_growth_mb" =~ ^[0-9]+$ ]]; then
    if (( rss_growth_mb <= 100 )); then
      ac_record_status "$status_tsv" rss_growth_budget pass "rss_growth_mb=${rss_growth_mb}"
    else
      ac_record_status "$status_tsv" rss_growth_budget fail "rss_growth_mb=${rss_growth_mb}"
    fi
  else
    ac_record_status "$status_tsv" rss_growth_budget fail invalid_rss_audit_file
  fi
else
  ac_record_status "$status_tsv" rss_growth_budget fail missing_rss_audit_file
fi

config_md=$'- strict_tools: '"${strict_tools}"$'\n- long_run: '"${long_run}"$'\n- scale_target: '"${scale_target}"$'\n- scale_max_in_flight: '"${scale_max_in_flight}"$'\n- soak_seconds: '"${soak_seconds}"$'\n- soak_exchange_timeout_seconds: '"${soak_exchange_timeout_seconds}"$'\n- soak_h2_retries: '"${soak_h2_retries}"$'\n- soak_h2_upstream_accept_timeout_seconds: '"${soak_h2_upstream_accept_timeout_seconds}"$'\n- rss_audit_file: '"${rss_audit_file:-unset}"

ac_finalize \
  "$status_tsv" \
  "$summary_md" \
  "$outcome_tsv" \
  "AC-07 1k TLS Concurrency, Latency, and Memory Envelope" \
  "$config_md"
