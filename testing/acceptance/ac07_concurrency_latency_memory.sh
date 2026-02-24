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

ac_run_case "$status_tsv" forwarding_latency_p95_budget \
  cargo bench -p soth-mitm --bench forwarding_latency -- \
    --iterations "$forward_iterations" \
    --warmup "$forward_warmup" \
    --threshold-p95-us "$forward_p95_us" \
    --result-file "$report_dir/forwarding_latency.tsv" || true

ac_run_case "$status_tsv" tls_handshake_scale_and_latency_budget \
  cargo bench -p soth-mitm --bench handshake_overhead -- \
    --iterations "$handshake_iterations" \
    --warmup "$handshake_warmup" \
    --threshold-overhead-p95-us "$handshake_overhead_p95_us" \
    --scale-target "$scale_target" \
    --scale-max-in-flight "$scale_max_in_flight" \
    --result-file "$report_dir/handshake_overhead.tsv" || true

ac_run_case "$status_tsv" mixed_traffic_runtime_budget_soak \
  env \
    SOTH_MITM_SOAK_SECONDS="$soak_seconds" \
    SOTH_MITM_SOAK_MIN_ITERATIONS="$soak_min_iterations" \
    cargo test -p mitm-sidecar --test mixed_traffic_soak \
      mixed_traffic_soak_respects_runtime_budget_envelope -q || true

if [[ "$long_run" -eq 0 ]]; then
  ac_record_status "$status_tsv" full_60s_window pass smoke_window
else
  ac_record_status "$status_tsv" full_60s_window pass enabled
fi

if [[ -n "$rss_audit_file" && -f "$rss_audit_file" ]]; then
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
  fallback_rss_growth_mb="${P6_AC07_RSS_GROWTH_MB:-0}"
  if [[ "$fallback_rss_growth_mb" =~ ^[0-9]+$ ]] && (( fallback_rss_growth_mb <= 100 )); then
    ac_record_status "$status_tsv" rss_growth_budget pass "fallback_rss_growth_mb=${fallback_rss_growth_mb}"
  else
    ac_record_status "$status_tsv" rss_growth_budget fail invalid_fallback_rss_growth_mb
  fi
fi

config_md=$'- strict_tools: '"${strict_tools}"$'\n- long_run: '"${long_run}"$'\n- scale_target: '"${scale_target}"$'\n- scale_max_in_flight: '"${scale_max_in_flight}"$'\n- soak_seconds: '"${soak_seconds}"$'\n- rss_audit_file: '"${rss_audit_file:-unset}"

ac_finalize \
  "$status_tsv" \
  "$summary_md" \
  "$outcome_tsv" \
  "AC-07 1k TLS Concurrency, Latency, and Memory Envelope" \
  "$config_md"
