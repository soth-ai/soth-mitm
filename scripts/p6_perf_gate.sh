#!/usr/bin/env bash
set -euo pipefail

report_dir="artifacts/p6-performance"
iterations="${P6_BENCH_ITERATIONS:-120}"
warmup="${P6_BENCH_WARMUP:-12}"
forward_p50_us="${P6_FORWARD_P50_US:-1000}"
forward_p95_us="${P6_FORWARD_P95_US:-5000}"
forward_p99_us="${P6_FORWARD_P99_US:-15000}"
tls_overhead_p95_us="${P6_TLS_OVERHEAD_P95_US:-10000}"
sse_p95_us="${P6_SSE_FIRST_CHUNK_P95_US:-5000}"
scale_target="${P6_SCALE_TARGET:-1000}"
scale_max_in_flight="${P6_SCALE_MAX_IN_FLIGHT:-192}"
core_scale_connections="${P6_CORE_SCALE_CONNECTIONS:-1000}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --report-dir)
      report_dir="$2"
      shift 2
      ;;
    --iterations)
      iterations="$2"
      shift 2
      ;;
    --warmup)
      warmup="$2"
      shift 2
      ;;
    --scale-target)
      scale_target="$2"
      shift 2
      ;;
    --scale-max-in-flight)
      scale_max_in_flight="$2"
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
metrics_tsv="$report_dir/metrics.tsv"
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

append_metrics() {
  local bench="$1"
  local file="$2"
  if [[ ! -f "$file" ]]; then
    return 0
  fi
  while IFS=$'\t' read -r key value; do
    [[ -z "$key" ]] && continue
    printf '%s\t%s\t%s\n' "$bench" "$key" "$value" >>"$metrics_tsv"
  done <"$file"
}

: >"$status_tsv"
printf 'bench\tmetric\tvalue\n' >"$metrics_tsv"

forward_result="$report_dir/forwarding_latency.tsv"
handshake_result="$report_dir/handshake_overhead.tsv"
sse_result="$report_dir/sse_first_chunk.tsv"

run_case forwarding_latency_bench \
  cargo bench -p soth-mitm --bench forwarding_latency -- \
    --iterations "$iterations" \
    --warmup "$warmup" \
    --threshold-p50-us "$forward_p50_us" \
    --threshold-p95-us "$forward_p95_us" \
    --threshold-p99-us "$forward_p99_us" \
    --result-file "$forward_result" || true

run_case handshake_overhead_bench \
  cargo bench -p soth-mitm --bench handshake_overhead -- \
    --iterations "$iterations" \
    --warmup "$warmup" \
    --threshold-overhead-p95-us "$tls_overhead_p95_us" \
    --scale-target "$scale_target" \
    --scale-max-in-flight "$scale_max_in_flight" \
    --result-file "$handshake_result" || true

run_case sse_first_chunk_bench \
  cargo bench -p soth-mitm --bench sse_first_chunk -- \
    --iterations "$iterations" \
    --warmup "$warmup" \
    --threshold-p95-us "$sse_p95_us" \
    --result-file "$sse_result" || true

run_case connection_scale_core_1000 \
  env MITM_CORE_CONCURRENCY="$core_scale_connections" \
    cargo test -p mitm-core --test server_concurrency \
      flow_lifecycle_server_handles_500_parallel_short_lived_connections -q || true

append_metrics forwarding_latency "$forward_result"
append_metrics handshake_overhead "$handshake_result"
append_metrics sse_first_chunk "$sse_result"

failed="$(awk '$2 != "pass" {print $1}' "$status_tsv" || true)"
{
  echo "# Phase 6 Performance Gates"
  echo
  echo "Generated: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo
  echo "Config:"
  echo "- iterations: ${iterations}"
  echo "- warmup: ${warmup}"
  echo "- forward thresholds: p50<=${forward_p50_us}us p95<=${forward_p95_us}us p99<=${forward_p99_us}us"
  echo "- TLS overhead threshold: p95<=${tls_overhead_p95_us}us"
  echo "- SSE first-chunk threshold: p95<=${sse_p95_us}us"
  echo "- handshake scale target: ${scale_target} (max_in_flight=${scale_max_in_flight})"
  echo "- core concurrency baseline: ${core_scale_connections}"
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
  echo
  echo "## Metrics"
  echo
  echo '```tsv'
  cat "$metrics_tsv"
  echo '```'
} >"$summary_md"

if [[ -n "$failed" ]]; then
  exit 1
fi
