#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

report_root="${1:-artifacts/bench-tls-vs-mitmproxy}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
report_dir="${report_root}/${timestamp}"
raw_dir="${report_dir}/raw"
tls_dir="${report_dir}/tls"
mkdir -p "$raw_dir" "$tls_dir"

bind_host="${BENCH_BIND_HOST:-127.0.0.1}"
upstream_tls_port="${UPSTREAM_TLS_PORT:-29443}"
soth_port="${SOTH_PROXY_PORT:-28480}"
mitm_port="${MITMPROXY_PORT:-28481}"
ab_timeout_seconds="${AB_TIMEOUT_SECONDS:-180}"
mitm_ca_cert="${MITMPROXY_CA_CERT:-${HOME}/.mitmproxy/mitmproxy-ca-cert.pem}"

http_requests_1k="${HTTP_REQUESTS_1K:-2400}"
http_requests_64k="${HTTP_REQUESTS_64K:-900}"
http_concurrency="${HTTP_CONCURRENCY:-24}"
sse_requests="${SSE_REQUESTS:-240}"
sse_concurrency="${SSE_CONCURRENCY:-24}"

run_tsv="${report_dir}/runs.tsv"
summary_md="${report_dir}/summary.md"

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
  local label="$3"
  for _ in $(seq 1 160); do
    if nc -z "$host" "$port" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  echo "timed out waiting for ${label} on ${host}:${port}" >&2
  return 1
}

wait_for_file() {
  local path="$1"
  local label="$2"
  for _ in $(seq 1 120); do
    if [[ -s "$path" ]]; then
      return 0
    fi
    sleep 0.25
  done
  echo "timed out waiting for ${label}: ${path}" >&2
  return 1
}

generate_tls_material() {
  openssl req -x509 -newkey rsa:2048 -sha256 -days 3 -nodes \
    -keyout "${tls_dir}/upstream-ca.key" \
    -out "${tls_dir}/upstream-ca.crt" \
    -subj "/CN=soth-mitm-bench-upstream-ca" >/dev/null 2>&1

  openssl req -newkey rsa:2048 -nodes \
    -keyout "${tls_dir}/upstream.key" \
    -out "${tls_dir}/upstream.csr" \
    -subj "/CN=127.0.0.1" >/dev/null 2>&1

  cat >"${tls_dir}/upstream-san.ext" <<'EOF'
subjectAltName=IP:127.0.0.1,DNS:localhost
extendedKeyUsage=serverAuth
EOF

  openssl x509 -req \
    -in "${tls_dir}/upstream.csr" \
    -CA "${tls_dir}/upstream-ca.crt" \
    -CAkey "${tls_dir}/upstream-ca.key" \
    -CAcreateserial \
    -out "${tls_dir}/upstream.crt" \
    -days 3 \
    -sha256 \
    -extfile "${tls_dir}/upstream-san.ext" >/dev/null 2>&1
}

start_tls_upstream() {
  python3 - "${tls_dir}/upstream.crt" "${tls_dir}/upstream.key" "${bind_host}" "${upstream_tls_port}" \
    >"${report_dir}/upstream-tls.log" 2>&1 <<'PY' &
import http.server
import ssl
import sys
import time

cert_path, key_path, host, port_raw = sys.argv[1:5]
port = int(port_raw)
payload_1k = b"a" * 1024
payload_64k = b"b" * (64 * 1024)

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == "/1k.txt":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(payload_1k)))
            self.end_headers()
            self.wfile.write(payload_1k)
            return

        if self.path == "/64k.txt":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(payload_64k)))
            self.end_headers()
            self.wfile.write(payload_64k)
            return

        if self.path == "/sse":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            sent_ms = int(time.time() * 1000)
            self.wfile.write(f"data: {sent_ms}\n\n".encode())
            self.wfile.flush()
            time.sleep(0.01)
            self.wfile.write(b"data: tail\n\n")
            self.wfile.flush()
            return

        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        return

server = http.server.ThreadingHTTPServer((host, port), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
  upstream_pid=$!
  wait_for_port "$bind_host" "$upstream_tls_port" "TLS upstream"
}

start_soth() {
  local mode="$1"
  local destination=""
  case "$mode" in
    passthrough) destination="example.invalid:443" ;;
    mitm) destination="${bind_host}:${upstream_tls_port}" ;;
    *)
      echo "unsupported soth mode: $mode" >&2
      exit 2
      ;;
  esac

  SOTH_MITM_BENCH_BIND="${bind_host}:${soth_port}" \
  SOTH_MITM_BENCH_DEST="$destination" \
  SOTH_MITM_BENCH_PASSTHROUGH_UNLISTED=true \
  SOTH_MITM_BENCH_VERIFY_UPSTREAM_TLS=false \
  SOTH_MITM_BENCH_USE_CA=true \
  SOTH_MITM_BENCH_CA_CERT_PATH="${tls_dir}/upstream-ca.crt" \
  SOTH_MITM_BENCH_CA_KEY_PATH="${tls_dir}/upstream-ca.key" \
  cargo run -p soth-mitm --example bench_proxy \
    >"${report_dir}/soth-${mode}.log" 2>&1 &
  soth_pid=$!
  wait_for_port "$bind_host" "$soth_port" "soth-mitm ${mode} proxy"
}

start_mitm() {
  local mode="$1"

  local args=(
    --quiet
    --listen-host "$bind_host"
    --listen-port "$mitm_port"
    --set block_global=false
    --set connection_strategy=lazy
    --set flow_detail=0
    --set termlog_verbosity=error
    --set ssl_insecure=true
  )
  if [[ "$mode" == "passthrough" ]]; then
    args+=(--ignore-hosts "^${bind_host}:${upstream_tls_port}$")
  fi

  mitmdump "${args[@]}" >"${report_dir}/mitmproxy-${mode}.log" 2>&1 &
  mitm_pid=$!
  wait_for_port "$bind_host" "$mitm_port" "mitmproxy ${mode}"

  if [[ "$mode" == "mitm" ]]; then
    wait_for_file "${mitm_ca_cert}" "mitmproxy CA certificate"
  fi
}

run_python_http_bench() {
  local proxy_port="$1"
  local path="$2"
  local verify_bundle="$3"
  local requests="$4"
  local concurrency="$5"
  python3 - "$proxy_port" "$upstream_tls_port" "$path" "$verify_bundle" "$requests" "$concurrency" <<'PY'
import concurrent.futures
import json
import math
import threading
import time
import requests
import sys

proxy_port = int(sys.argv[1])
upstream_port = int(sys.argv[2])
path = sys.argv[3]
verify_bundle = sys.argv[4]
total_requests = int(sys.argv[5])
concurrency = int(sys.argv[6])
url = f"https://127.0.0.1:{upstream_port}/{path}"

proxies = {
    "http": f"http://127.0.0.1:{proxy_port}",
    "https": f"http://127.0.0.1:{proxy_port}",
}
verify = False if verify_bundle == "-" else verify_bundle
thread_local = threading.local()

def session():
    sess = getattr(thread_local, "sess", None)
    if sess is None:
        sess = requests.Session()
        sess.trust_env = False
        sess.proxies = proxies
        thread_local.sess = sess
    return sess

def one_call(_):
    started = time.perf_counter()
    try:
        resp = session().get(url, verify=verify, timeout=10)
        ok = resp.status_code == 200
        _ = resp.content
    except Exception:
        ok = False
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return ok, elapsed_ms

all_latencies = []
failures = 0
started = time.perf_counter()
with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
    for ok, latency_ms in pool.map(one_call, range(total_requests)):
        all_latencies.append(latency_ms)
        if not ok:
            failures += 1
elapsed = time.perf_counter() - started
all_latencies.sort()

def pct(values, q):
    if not values:
        return 0.0
    idx = int(math.ceil(q * len(values))) - 1
    idx = max(0, min(idx, len(values) - 1))
    return values[idx]

print(json.dumps({
    "requests": total_requests,
    "concurrency": concurrency,
    "failures": failures,
    "rps": (total_requests / elapsed) if elapsed > 0 else 0.0,
    "p95_ms": pct(all_latencies, 0.95),
    "mean_ms": (sum(all_latencies) / len(all_latencies)) if all_latencies else 0.0
}))
PY
}

run_python_sse_bench() {
  local proxy_port="$1"
  local verify_bundle="$2"
  local requests="$3"
  local concurrency="$4"
  python3 - "$proxy_port" "$upstream_tls_port" "$verify_bundle" "$requests" "$concurrency" <<'PY'
import concurrent.futures
import json
import math
import threading
import time
import requests
import sys

proxy_port = int(sys.argv[1])
upstream_port = int(sys.argv[2])
verify_bundle = sys.argv[3]
total_requests = int(sys.argv[4])
concurrency = int(sys.argv[5])
url = f"https://127.0.0.1:{upstream_port}/sse"

proxies = {
    "http": f"http://127.0.0.1:{proxy_port}",
    "https": f"http://127.0.0.1:{proxy_port}",
}
verify = False if verify_bundle == "-" else verify_bundle
thread_local = threading.local()

def session():
    sess = getattr(thread_local, "sess", None)
    if sess is None:
        sess = requests.Session()
        sess.trust_env = False
        sess.proxies = proxies
        thread_local.sess = sess
    return sess

def one_call(_):
    started = time.perf_counter()
    try:
        with session().get(url, verify=verify, stream=True, timeout=(5, 15)) as resp:
            if resp.status_code != 200:
                return False, (time.perf_counter() - started) * 1000.0
            for raw_line in resp.iter_lines(decode_unicode=True):
                if raw_line and raw_line.startswith("data:"):
                    return True, (time.perf_counter() - started) * 1000.0
            return False, (time.perf_counter() - started) * 1000.0
    except Exception:
        return False, (time.perf_counter() - started) * 1000.0

all_latencies = []
failures = 0
started = time.perf_counter()
with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
    for ok, latency_ms in pool.map(one_call, range(total_requests)):
        all_latencies.append(latency_ms)
        if not ok:
            failures += 1
elapsed = time.perf_counter() - started
all_latencies.sort()

def pct(values, q):
    if not values:
        return 0.0
    idx = int(math.ceil(q * len(values))) - 1
    idx = max(0, min(idx, len(values) - 1))
    return values[idx]

print(json.dumps({
    "requests": total_requests,
    "concurrency": concurrency,
    "failures": failures,
    "rps": (total_requests / elapsed) if elapsed > 0 else 0.0,
    "p95_ms": pct(all_latencies, 0.95),
    "mean_ms": (sum(all_latencies) / len(all_latencies)) if all_latencies else 0.0
}))
PY
}

append_runs() {
  local proxy="$1"
  local mode="$2"
  local case_name="$3"
  local requests="$4"
  local concurrency="$5"
  local verify_bundle="$6"
  local bench_kind="$7"
  local proxy_port="$8"

  local run
  for run in 1 2 3; do
    local result_json=""
    if [[ "$bench_kind" == "http" ]]; then
      result_json="$(run_python_http_bench "$proxy_port" "$case_name" "$verify_bundle" "$requests" "$concurrency")"
    else
      result_json="$(run_python_sse_bench "$proxy_port" "$verify_bundle" "$requests" "$concurrency")"
    fi
    local out="${raw_dir}/${proxy}.${mode}.${case_name}.run${run}.json"
    printf '%s\n' "$result_json" >"$out"
    python3 - "$run_tsv" "$proxy" "$mode" "$case_name" "$run" "$result_json" <<'PY'
import json
import sys

run_tsv, proxy, mode, case_name, run, raw_json = sys.argv[1:7]
data = json.loads(raw_json)
with open(run_tsv, "a", encoding="utf-8") as f:
    f.write(
        f"{proxy}\t{mode}\t{case_name}\t{run}\t"
        f"{data['requests']}\t{data['concurrency']}\t{data['rps']:.6f}\t"
        f"{data['p95_ms']:.6f}\t{data['mean_ms']:.6f}\t{int(data['failures'])}\n"
    )
PY
  done
}

build_summary() {
  python3 - "$run_tsv" "$summary_md" "$timestamp" "$report_dir" <<'PY'
import csv
import math
import os
import platform
import statistics
import sys
from collections import defaultdict

runs_tsv, summary_md, timestamp, report_dir = sys.argv[1:5]
rows = list(csv.DictReader(open(runs_tsv, encoding="utf-8"), delimiter="\t"))
groups = defaultdict(list)
for row in rows:
    groups[(row["mode"], row["case"], row["proxy"])].append(row)

def avg(metric, items):
    vals = [float(x[metric]) for x in items]
    return sum(vals) / len(vals) if vals else 0.0

def avg_fail(items):
    vals = [int(x["failures"]) for x in items]
    return sum(vals) / len(vals) if vals else 0.0

def fmt(v):
    return f"{v:.3f}"

def delta_pct(a, b):
    if b == 0:
        return "n/a"
    return f"{((a - b) / b) * 100.0:+.2f}%"

def table_for(mode, cases):
    lines = []
    lines.append("| Case | soth-mitm RPS | mitmproxy RPS | Delta (soth vs mitm) | soth p95 (ms) | mitm p95 (ms) | soth avg failures | mitm avg failures |")
    lines.append("| --- | ---:| ---:| ---:| ---:| ---:| ---:| ---:|")
    for case in cases:
        s_items = groups.get((mode, case, "soth-mitm"), [])
        m_items = groups.get((mode, case, "mitmproxy"), [])
        s_rps = avg("rps", s_items)
        m_rps = avg("rps", m_items)
        s_p95 = avg("p95_ms", s_items)
        m_p95 = avg("p95_ms", m_items)
        s_f = avg_fail(s_items)
        m_f = avg_fail(m_items)
        lines.append(
            f"| {case} | {fmt(s_rps)} | {fmt(m_rps)} | {delta_pct(s_rps, m_rps)} | "
            f"{fmt(s_p95)} | {fmt(m_p95)} | {fmt(s_f)} | {fmt(m_f)} |"
        )
    return "\n".join(lines)

with open(summary_md, "w", encoding="utf-8") as out:
    out.write("# TLS Benchmark Comparison: soth-mitm vs mitmproxy\n\n")
    out.write(f"- Timestamp (UTC): {timestamp}\n")
    out.write(f"- Host: {platform.platform()}\n")
    out.write("- Client benchmark engine: Python `requests` + thread pool\n")
    out.write("- Upstream: local HTTPS server with cert signed by local benchmark CA\n")
    out.write("- Proxy ports: soth-mitm `28480`, mitmproxy `28481`\n")
    out.write("- Runs: 3 runs per case\n\n")

    out.write("## CONNECT Passthrough (HTTPS tunnel)\n\n")
    out.write(table_for("passthrough", ["1k.txt", "64k.txt"]))
    out.write("\n\n")

    out.write("## Full MITM (HTTPS interception)\n\n")
    out.write(table_for("mitm", ["1k.txt", "64k.txt"]))
    out.write("\n\n")

    out.write("## SSE Over MITM (first chunk)\n\n")
    out.write(table_for("mitm", ["sse_first_chunk"]))
    out.write("\n\n")

    out.write("## Notes\n\n")
    out.write("- This benchmark captures TLS-relevant paths: CONNECT tunnel, full MITM, and SSE over MITM.\n")
    out.write("- Results are environment-sensitive and should be re-run on target deployment hardware.\n")
    out.write(f"- Raw runs TSV: `{runs_tsv}`\n")
    out.write(f"- Raw JSON outputs: `{os.path.join(report_dir, 'raw')}`\n")
PY
}

stop_soth() {
  if [[ -n "${soth_pid:-}" ]]; then
    kill "${soth_pid}" 2>/dev/null || true
    wait "${soth_pid}" 2>/dev/null || true
    unset soth_pid
  fi
}

stop_mitm() {
  if [[ -n "${mitm_pid:-}" ]]; then
    kill "${mitm_pid}" 2>/dev/null || true
    wait "${mitm_pid}" 2>/dev/null || true
    unset mitm_pid
  fi
}

prepare_mitm_bundle() {
  local _mode="$1"
  local out_bundle="$2"
  wait_for_file "$mitm_ca_cert" "mitmproxy CA cert"
  cat "${tls_dir}/upstream-ca.crt" "$mitm_ca_cert" >"$out_bundle"
}

printf 'proxy\tmode\tcase\trun\trequests\tconcurrency\trps\tp95_ms\tmean_ms\tfailures\n' >"$run_tsv"

generate_tls_material
start_tls_upstream

# CONNECT passthrough mode
start_soth passthrough
append_runs "soth-mitm" "passthrough" "1k.txt" "$http_requests_1k" "$http_concurrency" "${tls_dir}/upstream-ca.crt" "http" "$soth_port"
append_runs "soth-mitm" "passthrough" "64k.txt" "$http_requests_64k" "$http_concurrency" "${tls_dir}/upstream-ca.crt" "http" "$soth_port"
stop_soth

start_mitm passthrough
append_runs "mitmproxy" "passthrough" "1k.txt" "$http_requests_1k" "$http_concurrency" "${tls_dir}/upstream-ca.crt" "http" "$mitm_port"
append_runs "mitmproxy" "passthrough" "64k.txt" "$http_requests_64k" "$http_concurrency" "${tls_dir}/upstream-ca.crt" "http" "$mitm_port"
stop_mitm

# Full MITM mode
start_soth mitm
append_runs "soth-mitm" "mitm" "1k.txt" "$http_requests_1k" "$http_concurrency" "${tls_dir}/upstream-ca.crt" "http" "$soth_port"
append_runs "soth-mitm" "mitm" "64k.txt" "$http_requests_64k" "$http_concurrency" "${tls_dir}/upstream-ca.crt" "http" "$soth_port"
append_runs "soth-mitm" "mitm" "sse_first_chunk" "$sse_requests" "$sse_concurrency" "${tls_dir}/upstream-ca.crt" "sse" "$soth_port"
stop_soth

start_mitm mitm
mitm_bundle="${tls_dir}/mitmproxy-mitm-bundle.pem"
prepare_mitm_bundle "mitm" "$mitm_bundle"
append_runs "mitmproxy" "mitm" "1k.txt" "$http_requests_1k" "$http_concurrency" "$mitm_bundle" "http" "$mitm_port"
append_runs "mitmproxy" "mitm" "64k.txt" "$http_requests_64k" "$http_concurrency" "$mitm_bundle" "http" "$mitm_port"
append_runs "mitmproxy" "mitm" "sse_first_chunk" "$sse_requests" "$sse_concurrency" "$mitm_bundle" "sse" "$mitm_port"
stop_mitm

build_summary
echo "tls benchmark report: ${summary_md}"
