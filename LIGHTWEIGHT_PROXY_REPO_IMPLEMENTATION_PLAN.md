# Lightweight Proxy Repo Implementation Plan

## Goal
Build and own a lightweight MITM-capable proxy (inspired by hudsucker and mitmproxy behavior) as a separate repository, then consume it in `soth` through a stable contract.

Hudsucker is not sufficient for required protocol coverage (SSE, HTTP/2, HTTP/3, gRPC), so `soth-mitm` must implement these capabilities directly.
Hudsucker also lacks a direct client TLS failure callback (mitmproxy-style `tls_failed_client` equivalent), which limits TLS failure attribution accuracy in hudsucker fallback mode.
For TLS operations and failure attribution, mitmproxy should be treated as the preferred/authoritative path.

This plan is for:
1. Better interception reliability and TLS diagnostics.
2. Explicit control over pinning bypass, protocol behavior, and cert handling.
3. Cleaner separation so proxy core can evolve independently and be reused.

## Why Separate Repo
1. Keep proxy transport concerns isolated from SOTH detection/enrichment/business logic.
2. Allow dedicated CI, benchmarks, fuzzing, and release cadence for network stack changes.
3. Avoid coupling `soth` releases to low-level proxy internals.
4. Remove protocol-scope constraints from current hudsucker-based path (SSE/HTTP2/HTTP3/gRPC gaps).

## Proposed Repo
Repo name: `soth-mitm`

### Crates
1. `mitm-core`
   - TCP accept loop, CONNECT handling, tunnel/MITM decision hooks.
2. `mitm-tls`
   - CA/leaf cert issuance, TLS handshake wiring, TLS failure classification.
3. `mitm-http`
   - HTTP/1.1 + HTTP/2 request/response parsing, streaming body plumbing, WS upgrade support.
4. `mitm-policy`
   - Generic routing primitives (`intercept`, `tunnel`, `block`) and host/path matcher engine (`tunnel` covers metadata-only passthrough).
5. `mitm-observe`
   - Event stream emitted by proxy core (transport lifecycle + parsed HTTP metadata).
6. `mitm-sidecar` (optional)
   - Process mode with UDS/gRPC control/event API for non-Rust consumers.

## Integration Contract with `soth`
`soth` remains source of truth for:
1. Bundle rules and detection IDs (`soth-oisp`).
2. Downstream assembly and upload contracts.
3. Collector logic and cloud sync.

`soth-mitm` provides:
1. Interception engine.
2. TLS/cert lifecycle.
3. Transport events + parsed request/response streams.

### Adapter in `soth`
Create `crates/soth-proxy-adapter` (or refactor current `soth-proxy`) that:
1. Feeds downstream rule decisions into generic proxy handler interfaces.
2. Converts proxy events into downstream pipeline inputs.
3. Applies SOTH-specific policy/budget/identity checks outside proxy core.

## Required Behavior (Parity + Improvements)
1. TLS failure learning only on classified TLS failures (not raw CONNECT retries).
2. Explicit `ignore_hosts` bypass list for true pinning/problem hosts.
3. Detailed TLS failure taxonomy (`unknown_ca`, cert validation, handshake alert, timeout, EOF/reset).
4. Protocol knobs:
   - `http2_enabled`
   - `http2_max_header_list_size`
   - `http3_passthrough` (initially tunnel-only)
5. Strong CA trust guidance for OS + app-level trust stores.
6. Deterministic request lifecycle events for HTTP, WS, SSE, streamable HTTP, and HTTP/2.
7. WebSocket turn aggregation in proxy core (hudsucker gap) for deterministic conversational grouping.
8. Native support plan for SSE, HTTP/2, HTTP/3 passthrough, and gRPC stream observation.
9. Parser layer coverage for:
   - gRPC message framing (5-byte envelope, compression flag, length).
   - SSE stream parsing (event/id/retry/data semantics).
   - anti-hijack prefix handling for JSON-style payload guards.
   - msgpack payload detection/decoding where content-type or heuristics indicate binary structured data.
   - layered decoders (transfer/content encoding + protocol framing + payload parser).
10. When running on hudsucker fallback path, do not perform automated TLS failure learning from ambiguous client-side handshake symptoms.
11. TLS ops strategy:
   - use mitmproxy callback surface as authoritative TLS failure signal source where available.
   - mark all non-mitmproxy TLS outcomes as inferred unless proven equivalent.

## Event API from Proxy Core
Minimal event set to emit:
1. `connect_received`
2. `connect_decision`
3. `tls_handshake_started`
4. `tls_handshake_succeeded`
5. `tls_handshake_failed` (+ classified reason)
6. `request_headers`
7. `request_body_chunk`
8. `response_headers`
9. `response_body_chunk`
10. `stream_closed`

Each event must include:
1. `flow_id`
2. `client_addr`
3. `server_host`
4. `server_port`
5. `protocol` (http1/http2/ws/sse/streamable_http/tunnel)
6. timestamps

## Phase Plan
### Phase 0: Repo Bootstrap
1. Create `soth-mitm` workspace with crates above.
2. Add baseline config schema + serde contract.
3. Add integration smoke harness with fixture upstream servers.

### Phase 1: Transport Core
1. CONNECT pipeline with `intercept|tunnel|block`.
2. MITM path for HTTP/1.1.
3. TLS failure classifier and per-host counters.
4. `ignore_hosts` support.
5. Mitmproxy TLS-ops adapter path (`tls_handshake_started/succeeded/failed`) for authoritative classification.

### Phase 2: Protocol Expansion
1. HTTP/2 support and tuning.
2. WS frame pass-through + metadata observation.
3. WS turn aggregator with deterministic boundaries and flush semantics.
4. SSE and chunked stream handling.
5. gRPC over HTTP/2 metadata/stream observation (headers, message boundaries/lengths, status/trailers).
6. HTTP/3 passthrough policy + telemetry (initially tunnel-only; no decrypt).
7. Parser subsystem:
   - decoder chain ordering (`chunked`/`gzip`/`br`/`deflate` -> protocol frame parser -> payload parser).
   - gRPC framing parser + error classification.
   - SSE parser with incremental state machine.
   - anti-hijack stripping/sanitization pass.
   - msgpack parser hooks and fallback behavior.

### Phase 3: SOTH Adapter
1. Replace direct hudsucker dependency in `soth` with adapter to `soth-mitm`.
2. Wire OISP decision engine into adapter callback path.
3. Preserve current downstream contract and event semantics.

### Phase 4: Hardening
1. Fuzz parsers and CONNECT/TLS state machine (including gRPC framing/SSE/msgpack/layered decode paths).
2. Load/perf tests (connection churn, long streams, header stress).
3. Failure-injection tests (reset/timeout/invalid cert chains).

## Versioning and Consumption
1. Publish tagged releases from `soth-mitm`.
2. Consume from `soth` as:
   - crates.io version (preferred once stable), or
   - pinned git tag during early rollout.
3. Keep backward-compatible API across minor versions.

## Migration Strategy from Current Proxy
1. Dual mode in `soth`:
   - `proxy_engine: hudsucker` (current)
   - `proxy_engine: soth-mitm` (new)
2. Shadow mode: run new engine in diagnostic mode first, compare decisions and TLS outcomes.
3. Cutover by cohort/channel after parity checks.
4. Keep fallback to hudsucker until `soth-mitm` reaches stability target, but do not route SSE/HTTP2/HTTP3/gRPC cohorts to hudsucker.
5. During hudsucker fallback, TLS diagnostics are best-effort inference only; use `soth-mitm` path for authoritative client TLS failure taxonomy.
6. Prefer mitmproxy-backed TLS cohorts first during shadow/cutover for reliable TLS-learning signals.

## Risks and Controls
1. TLS edge-case regressions
   - Mitigation: corpus + per-host failure reason telemetry + fast rollback.
2. Performance regressions under streaming
   - Mitigation: benchmark gates in CI.
3. Behavioral drift with downstream consumer pipeline
   - Mitigation: adapter conformance tests with fixed golden flows.

## Immediate Next Actions
1. Create `soth-mitm` skeleton repo.
2. Freeze integration API between adapter and `soth-mitm`.
3. Add WS turn-aggregation event contract (`ws_turn_started`/`ws_turn_completed`) before full WS rollout.
4. Implement Phase 1 before adding advanced protocol features.
