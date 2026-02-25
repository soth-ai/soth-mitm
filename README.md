# soth-mitm

[![CI](https://img.shields.io/github/actions/workflow/status/soth-ai/soth-mitm/ci.yml?branch=main&label=ci)](https://github.com/soth-ai/soth-mitm/actions/workflows/ci.yml)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-orange.svg)](LICENSE)
[![Rust 1.75+](https://img.shields.io/badge/rust-1.75%2B-blue.svg)](docs/MSRV.md)

Rust intercepting proxy workspace for SOTH, built for deterministic policy enforcement, transport normalization, and production hardening.

## What This Repo Is

- A reusable proxy core (`soth-mitm` crate) that exposes stable handler/config/runtime contracts.
- A protocol/runtime engine stack (`mitm-*` crates) for HTTP(S) interception and tunnel control.
- A testing and hardening system with acceptance, chaos, differential, and compliance gates.

## What This Repo Is Not

- Not provider-specific AI logic.
- Not bundle ownership for product semantics.
- Not an all-in-one app framework.

Product-specific behavior belongs in downstream consumers (see `docs/consumer/soth-proxy-adapter-contract.md`).

## Core Capabilities

- HTTP `CONNECT` tunnel handling with intercept/tunnel/block policy outcomes.
- TLS MITM path with process-aware interception gate:
  - `should_intercept_tls(host, process_info)`
  - `on_tls_failure(host, error)`
- HTTP/1.1 and HTTP/2 forwarding/interception paths.
- WebSocket upgrade interception and frame-level stream events.
- Stream normalization hooks for:
  - SSE
  - NDJSON
  - gRPC message framing
- HTTP/3 passthrough hint support (passthrough mode).
- Eager connection metadata with socket family and optional process attribution.
- Runtime controls:
  - hot reload
  - graceful shutdown with drain timeout
  - metrics snapshots

## Public API Surface (`soth-mitm`)

### Input/Output Contracts

- `RawRequest`: method/path/headers/body + `connection_meta`
- `RawResponse`: status/headers/body + `connection_meta`
- `StreamChunk`: `connection_id`, `payload`, `sequence`, `frame_kind`
- `ConnectionMeta`: `connection_id`, `socket_family`, `process_info`, `tls_info`

### Handler Contract

- `should_intercept_tls(&self, host, process_info) -> bool`
- `on_tls_failure(&self, host, error)`
- `on_request(&self, &RawRequest) -> Future<Output = HandlerDecision>`
- `on_stream_chunk(&self, &StreamChunk) -> Future<Output = ()>`
- `on_stream_end(&self, connection_id) -> Future<Output = ()>`
- `on_response(&self, &RawResponse) -> Future<Output = ()>`
- `on_connection_open(&self, &ConnectionMeta)`
- `on_connection_close(&self, connection_id)`

### Decision Contract

- `HandlerDecision::Allow`
- `HandlerDecision::Block { status, body }`

### Runtime Control Contract

- `MitmProxyBuilder::new(config, handler).build()`
- `MitmProxy::run()` / `MitmProxy::start() -> MitmProxyHandle`
- `MitmProxyHandle::reload(config)`
- `MitmProxyHandle::current_config()`
- `MitmProxyHandle::metrics()`
- `MitmProxyHandle::shutdown(timeout)`

## Configuration Contract

Top-level config type: `MitmConfig`

- `bind`, `unix_socket_path`
- `interception`:
  - `destinations`
  - `passthrough_unlisted`
- `process_attribution`:
  - `enabled`
  - `lookup_timeout_ms`
- `tls`:
  - `ca_cert_path`
  - `ca_key_path`
  - `min_version`
  - `capture_fingerprint`
- `upstream`:
  - `timeout_ms`
  - `connect_timeout_ms`
  - `retry_on_failure`
  - `retry_delay_ms`
  - `verify_upstream_tls`
- `connection_pool`:
  - `max_connections_per_host`
  - `idle_timeout_ms`
  - `max_idle_per_host`
- `body`:
  - `max_size_bytes`
  - `buffer_request_bodies`
- `handler`:
  - `request_timeout_ms`
  - `response_timeout_ms`
  - `recover_from_panics`

## Quick Start

### 1. Add Dependency

```toml
[dependencies]
soth-mitm = "0.1.0"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "time"] }
bytes = "1"
```

### 2. Minimal Integration

```rust
use std::time::Duration;

use bytes::Bytes;
use soth_mitm::{
    HandlerDecision, InterceptHandler, MitmConfig, MitmProxyBuilder, ProcessInfo, RawRequest,
};

struct Gate;

impl InterceptHandler for Gate {
    fn should_intercept_tls(&self, host: &str, process_info: Option<&ProcessInfo>) -> bool {
        let _ = host;
        process_info.and_then(|p| p.exe_name.as_deref()) != Some("trusted-local-agent")
    }

    async fn on_request(&self, request: &RawRequest) -> HandlerDecision {
        if request.path.contains("/blocked") {
            return HandlerDecision::Block {
                status: 403,
                body: Bytes::from_static(b"blocked by policy"),
            };
        }
        HandlerDecision::Allow
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = MitmConfig::default();
    config
        .interception
        .destinations
        .push("api.example.com:443".to_string());

    let proxy = MitmProxyBuilder::new(config, Gate).build()?;
    let handle = proxy.start().await?;

    let _metrics = handle.metrics();
    handle.shutdown(Duration::from_secs(2)).await?;
    Ok(())
}
```

Compilable example:
- `crates/soth-mitm/examples/soth_proxy_integration.rs`

## Workspace Layout

- `crates/soth-mitm`: public crate and stable contract surface.
- `crates/mitm-core`: core transport and flow engine.
- `crates/mitm-sidecar`: protocol relay, parsers, and runtime wiring.
- `crates/mitm-http`: protocol constants and HTTP primitives.
- `crates/mitm-policy`: policy decision layer.
- `crates/mitm-observe`: deterministic event model and sinks.
- `crates/mitm-tls`: TLS/cert handling primitives.
- `crates/soth-detect`: detection-side integration surface.

## Build and Validation

### Fast Local Validation

```bash
cargo check --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -W clippy::all
cargo test --workspace
./scripts/phase_a_smoke.sh
./scripts/tls_failure_fixtures.sh
./scripts/p1_reliability.sh
```

### Full Reliability/Hardening Sweep

```bash
./scripts/p2_protocol_matrix.sh
./scripts/p4_differential_validation.sh
./scripts/p4_performance_gates.sh
./scripts/p4_failure_injection.sh
./scripts/p4_chaos_network_faults.sh
./scripts/p4_chaos_adversarial.sh
./scripts/p5_reliability_contract.sh
./scripts/p5_event_log_contract.sh
./scripts/p5_runtime_soak.sh --duration-seconds 300
./scripts/p6_perf_gate.sh
./scripts/p6_acceptance_matrix.sh --report-dir artifacts/p6-acceptance
```

### Release Readiness

```bash
./scripts/p6_release_readiness.sh --report-dir artifacts/p6-release-readiness
```

## Docker Tooling

Build tool image:

```bash
./scripts/docker_build_tools.sh
```

Run testing plans in container:

```bash
./scripts/docker_run_testing.sh --profile stress
./scripts/docker_run_testing.sh --profile parity --profile benchmark --strict-tools
SOTH_MITM_SOAK_DURATION_SECONDS=300 ./scripts/docker_run_testing.sh --profile soak
./scripts/docker_run_testing.sh --list-lanes
```

Lane registry and defaults:

- `testing/lanes/registry.tsv`
- `testing/test-plan.env`
- `scripts/run_testing_plan.sh`

## CI Matrix

GitHub Actions (`.github/workflows/ci.yml`) runs:

- Linux + macOS + Windows feature checks/tests/smoke/reliability.
- Compliance gates (`cargo deny`, `cargo audit`, `cargo machete`).
- Protocol matrix lanes and triage.
- Differential, performance, failure-injection, and chaos lanes.
- Phase-6 perf + acceptance matrices.

## Benchmark Snapshot

Latest TLS-relevant side-by-side run versus `mitmproxy` (3 runs per case, all runs had `0` failed requests):

### CONNECT Passthrough (HTTPS tunnel)

| Case | soth-mitm RPS | mitmproxy RPS | Delta (soth vs mitm) | soth p95 (ms) | mitm p95 (ms) |
| --- | ---:| ---:| ---:| ---:| ---:|
| 1KiB response | 1993.420 | 1959.733 | +1.72% | 23.463 | 22.928 |
| 64KiB response | 1470.978 | 1408.606 | +4.43% | 27.887 | 28.039 |

### Full HTTPS MITM (decrypt + inspect + re-encrypt)

| Case | soth-mitm RPS | mitmproxy RPS | Delta (soth vs mitm) | soth p95 (ms) | mitm p95 (ms) |
| --- | ---:| ---:| ---:| ---:| ---:|
| 1KiB response | 1900.936 | 631.214 | +201.16% | 23.950 | 43.384 |
| 64KiB response | 1341.737 | 522.238 | +156.92% | 29.115 | 53.466 |

### SSE Over MITM (first chunk)

| Case | soth-mitm RPS | mitmproxy RPS | Delta (soth vs mitm) | soth p95 (ms) | mitm p95 (ms) |
| --- | ---:| ---:| ---:| ---:| ---:|
| SSE first chunk | 356.699 | 51.727 | +589.58% | 127.862 | 533.329 |

Method:

- Client benchmark engine: Python `requests` + thread pool
- Upstream: local HTTPS server with cert signed by local benchmark CA
- Proxy target `soth-mitm`: `crates/soth-mitm/examples/bench_proxy.rs` on `127.0.0.1:28080`
- Proxy target `mitmdump 11.0.2`: on `127.0.0.1:28081` with `--quiet --set flow_detail=0 --set termlog_verbosity=error --set ssl_insecure=true`
- HTTP workload `1KiB`: `n=2400`, `c=24`
- HTTP workload `64KiB`: `n=900`, `c=24`
- SSE workload `sse_first_chunk`: `n=240`, `c=24`

Reproduce:

```bash
./scripts/benchmark_tls_vs_mitmproxy.sh
./scripts/benchmark_vs_mitmproxy.sh
```

Run artifact:

- TLS benchmark report: `artifacts/bench-tls-vs-mitmproxy/20260225T211452Z/summary.md`
- HTTP loopback dataplane report: `artifacts/bench-vs-mitmproxy/20260225T210145Z/summary.md`

Notes:

- TLS benchmark covers the paths that matter in production: CONNECT passthrough, full MITM, and SSE over MITM.
- HTTP loopback dataplane benchmark is retained as a baseline reference.
- Re-run on target hardware and network before using results as production SLO claims.

## Documentation Index

- Aggregated implementation/hardening plan: `docs/SOTH_MITM_AGGREGATED_PLAN_AND_HARDENING.md`
- CI gate definitions: `docs/testing/ci-gates.md`
- Acceptance matrix: `docs/testing/p6-acceptance.md`
- Reliability invariants: `docs/testing/reliability-invariants.md`
- Protocol matrix: `docs/testing/protocol-matrix.md`
- Hardening plan: `docs/testing/hardening-plan.md`
- Differential validation contract: `docs/testing/differential-validation.md`
- Differential replay runbook: `docs/testing/differential-vs-mitmproxy.md`
- TLS taxonomy: `docs/testing/tls-taxonomy.md`
- Performance baselines: `docs/testing/perf-baselines.md`
- Artifact triage: `docs/testing/artifact-triage.md`
- Consumer adapter contract: `docs/consumer/soth-proxy-adapter-contract.md`
- Cutover playbook: `docs/migration/soth-cutover.md`
- Versioning/MSRV policy: `docs/policies/versioning-and-msrv.md`

## Repository Rules

- Max file length is `400` lines for core Rust source files under `crates/*/src/**/*.rs`.
- Oversized core Rust files must be split before merge.
- Guard command: `./scripts/check_max_file_lines.sh`

## Community

- Contributing: `CONTRIBUTING.md`
- Code of conduct: `CODE_OF_CONDUCT.md`
- Security policy: `SECURITY.md`
- Support guide: `SUPPORT.md`
- Pull request template: `.github/pull_request_template.md`
- Issue templates: `.github/ISSUE_TEMPLATE/`

## License

Mozilla Public License 2.0 (`LICENSE`).
