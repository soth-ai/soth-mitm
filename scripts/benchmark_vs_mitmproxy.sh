#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

report_root="${1:-artifacts/bench-vs-mitmproxy}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
report_dir="${report_root}/${timestamp}"
mkdir -p "$report_dir"

upstream_port="${UPSTREAM_PORT:-29080}"
soth_port="${SOTH_PROXY_PORT:-28080}"
mitm_port="${MITMPROXY_PORT:-28081}"
bind_host="${BENCH_BIND_HOST:-127.0.0.1}"

run_tsv="${report_dir}/runs.tsv"
summary_md="${report_dir}/summary.md"
raw_dir="${report_dir}/raw"
mkdir -p "$raw_dir"
ab_timeout_seconds="${AB_TIMEOUT_SECONDS:-180}"

cleanup() {
  if [[ -n "${soth_pid:-}" ]]; then
    kill "${soth_pid}" 2>/dev/null || true
    wait "${soth_pid}" 2>/dev/null || true
  fi
  if [[ -n "${mitm_pid:-}" ]]; then
    kill "${mitm_pid}" 2>/dev/null || true
    wait "${mitm_pid}" 2>/dev/null || true
  fi
  if [[ -n "${upstream_pid:-}" ]]; then
    kill "${upstream_pid}" 2>/dev/null || true
    wait "${upstream_pid}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

wait_for_port() {
  local host="$1"
  local port="$2"
  local name="$3"
  for _ in $(seq 1 120); do
    if nc -z "$host" "$port" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  echo "timed out waiting for ${name} on ${host}:${port}" >&2
  return 1
}

write_fixture_payloads() {
  local fixture_dir="$1"
  mkdir -p "$fixture_dir"
  python3 - "$fixture_dir" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
(root / "1k.txt").write_bytes(b"a" * 1024)
(root / "64k.txt").write_bytes(b"b" * (64 * 1024))
PY
}

start_upstream() {
  local fixture_dir="$1"
  python3 -m http.server "$upstream_port" \
    --bind "$bind_host" \
    --directory "$fixture_dir" \
    >"${report_dir}/upstream.log" 2>&1 &
  upstream_pid=$!
  wait_for_port "$bind_host" "$upstream_port" "upstream server"
}

start_soth_proxy() {
  SOTH_MITM_BENCH_BIND="${bind_host}:${soth_port}" \
  SOTH_MITM_BENCH_DEST="${bind_host}:${upstream_port}" \
  cargo run -p soth-mitm --example bench_proxy \
    >"${report_dir}/soth-proxy.log" 2>&1 &
  soth_pid=$!
  wait_for_port "$bind_host" "$soth_port" "soth-mitm benchmark proxy"
}

start_mitmproxy() {
  mitmdump \
    --quiet \
    --listen-host "$bind_host" \
    --listen-port "$mitm_port" \
    --set block_global=false \
    --set connection_strategy=lazy \
    --set flow_detail=0 \
    --set termlog_verbosity=error \
    >"${report_dir}/mitmproxy.log" 2>&1 &
  mitm_pid=$!
  wait_for_port "$bind_host" "$mitm_port" "mitmproxy"
}

ab_metric() {
  local file="$1"
  local key="$2"
  case "$key" in
    rps)
      awk -F': +' '/Requests per second:/ {print $2}' "$file" | awk '{print $1}' | head -n1
      ;;
    tpr_ms)
      awk '
        /Time per request:/ && $0 !~ /across all concurrent requests/ {
          print $4;
          exit 0;
        }
      ' "$file"
      ;;
    failed)
      awk '/Failed requests:/ {print $3}' "$file" | head -n1
      ;;
    p95_ms)
      awk '$1=="95%" {print $2; exit 0}' "$file"
      ;;
    *)
      return 1
      ;;
  esac
}

run_ab_case() {
  local proxy_name="$1"
  local proxy_port="$2"
  local case_name="$3"
  local path="$4"
  local requests="$5"
  local concurrency="$6"
  local keepalive_flag="$7"

  local keepalive_args=()
  if [[ "$keepalive_flag" == "1" ]]; then
    keepalive_args=(-k)
  fi

  local url="http://${bind_host}:${upstream_port}/${path}"
  local warmup_out="${raw_dir}/${proxy_name}.${case_name}.warmup.txt"
  if command -v timeout >/dev/null 2>&1; then
    timeout "$ab_timeout_seconds" \
      ab -q -X "${bind_host}:${proxy_port}" "${keepalive_args[@]}" -n 400 -c 30 "$url" \
      >"$warmup_out" 2>&1 || true
  else
    ab -q -X "${bind_host}:${proxy_port}" "${keepalive_args[@]}" -n 400 -c 30 "$url" \
      >"$warmup_out" 2>&1 || true
  fi

  local run
  for run in 1 2 3; do
    local out="${raw_dir}/${proxy_name}.${case_name}.run${run}.txt"
    if command -v timeout >/dev/null 2>&1; then
      timeout "$ab_timeout_seconds" \
        ab -X "${bind_host}:${proxy_port}" "${keepalive_args[@]}" -n "$requests" -c "$concurrency" "$url" \
        >"$out" 2>&1
    else
      ab -X "${bind_host}:${proxy_port}" "${keepalive_args[@]}" -n "$requests" -c "$concurrency" "$url" \
        >"$out" 2>&1
    fi
    local rps tpr failed p95
    rps="$(ab_metric "$out" rps)"
    tpr="$(ab_metric "$out" tpr_ms)"
    failed="$(ab_metric "$out" failed)"
    p95="$(ab_metric "$out" p95_ms)"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$proxy_name" \
      "$case_name" \
      "$run" \
      "$path" \
      "$requests" \
      "$concurrency" \
      "$rps" \
      "$tpr" \
      "$p95" \
      "$failed" >>"$run_tsv"
  done
}

summarize_case() {
  local case_name="$1"
  local metric="$2"
  awk -F'\t' -v case_name="$case_name" -v metric="$metric" '
    BEGIN {
      metric_idx = (metric == "rps") ? 7 : (metric == "tpr_ms") ? 8 : (metric == "p95_ms") ? 9 : 10;
    }
    $2 == case_name {
      key = $1;
      sum[key] += $metric_idx + 0.0;
      cnt[key] += 1;
    }
    END {
      for (k in sum) {
        if (cnt[k] > 0) {
          printf "%s\t%.3f\n", k, sum[k] / cnt[k];
        }
      }
    }
  ' "$run_tsv"
}

: >"$run_tsv"
printf 'proxy\tcase\trun\tpath\trequests\tconcurrency\trps\ttpr_ms\tp95_ms\tfailed\n' >"$run_tsv"

fixture_dir="${report_dir}/fixture"
write_fixture_payloads "$fixture_dir"
start_upstream "$fixture_dir"

start_soth_proxy
run_ab_case "soth-mitm" "$soth_port" "http_1k" "1k.txt" 3000 20 0
run_ab_case "soth-mitm" "$soth_port" "http_64k" "64k.txt" 1200 20 0
kill "$soth_pid" 2>/dev/null || true
wait "$soth_pid" 2>/dev/null || true
unset soth_pid

start_mitmproxy
run_ab_case "mitmproxy" "$mitm_port" "http_1k" "1k.txt" 3000 20 0
run_ab_case "mitmproxy" "$mitm_port" "http_64k" "64k.txt" 1200 20 0
kill "$mitm_pid" 2>/dev/null || true
wait "$mitm_pid" 2>/dev/null || true
unset mitm_pid

soth_1k_rps="$(summarize_case "http_1k" "rps" | awk '$1=="soth-mitm"{print $2}')"
mitm_1k_rps="$(summarize_case "http_1k" "rps" | awk '$1=="mitmproxy"{print $2}')"
soth_64k_rps="$(summarize_case "http_64k" "rps" | awk '$1=="soth-mitm"{print $2}')"
mitm_64k_rps="$(summarize_case "http_64k" "rps" | awk '$1=="mitmproxy"{print $2}')"

soth_1k_p95="$(summarize_case "http_1k" "p95_ms" | awk '$1=="soth-mitm"{print $2}')"
mitm_1k_p95="$(summarize_case "http_1k" "p95_ms" | awk '$1=="mitmproxy"{print $2}')"
soth_64k_p95="$(summarize_case "http_64k" "p95_ms" | awk '$1=="soth-mitm"{print $2}')"
mitm_64k_p95="$(summarize_case "http_64k" "p95_ms" | awk '$1=="mitmproxy"{print $2}')"

rps_delta_1k="$(awk -v a="$soth_1k_rps" -v b="$mitm_1k_rps" 'BEGIN { if (b==0) print "nan"; else printf "%.2f", ((a-b)/b)*100.0 }')"
rps_delta_64k="$(awk -v a="$soth_64k_rps" -v b="$mitm_64k_rps" 'BEGIN { if (b==0) print "nan"; else printf "%.2f", ((a-b)/b)*100.0 }')"

{
  echo "# Benchmark Comparison: soth-mitm vs mitmproxy"
  echo
  echo "- Timestamp (UTC): ${timestamp}"
  echo "- Host: $(uname -a)"
  echo "- Tool: ApacheBench ($(ab -V 2>&1 | head -n1))"
  echo "- Upstream: local python http.server on ${bind_host}:${upstream_port}"
  echo "- soth-mitm proxy: example \`bench_proxy\` on ${bind_host}:${soth_port}"
  echo "- mitmproxy: \`mitmdump 11.0.2\` on ${bind_host}:${mitm_port}"
  echo
  echo "## Results (average of 3 runs)"
  echo
  echo "| Case | soth-mitm RPS | mitmproxy RPS | Delta (soth vs mitm) | soth p95 (ms) | mitm p95 (ms) |"
  echo "| --- | ---:| ---:| ---:| ---:| ---:|"
  echo "| 1KiB response | ${soth_1k_rps} | ${mitm_1k_rps} | ${rps_delta_1k}% | ${soth_1k_p95} | ${mitm_1k_p95} |"
  echo "| 64KiB response | ${soth_64k_rps} | ${mitm_64k_rps} | ${rps_delta_64k}% | ${soth_64k_p95} | ${mitm_64k_p95} |"
  echo
  echo "## Notes"
  echo
  echo "- This is a loopback micro-benchmark, useful for relative dataplane overhead."
  echo "- Results are environment-sensitive; rerun on target hardware before publishing hard SLO claims."
  echo "- Raw per-run outputs: \`${raw_dir}\`"
  echo "- Raw metrics TSV: \`${run_tsv}\`"
} >"$summary_md"

echo "benchmark report: ${summary_md}"
