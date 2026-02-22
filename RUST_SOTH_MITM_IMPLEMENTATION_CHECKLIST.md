# Rust `soth-mitm` Implementation Checklist

This checklist turns `LIGHTWEIGHT_PROXY_REPO_IMPLEMENTATION_PLAN.md` into an execution plan for a Rust-native implementation.

## 0) Naming and Workspace Contract

- [ ] Repo name is `soth-mitm` and all docs/config/labels use this naming consistently.
- [ ] Rust workspace created with crates:
  - [ ] `mitm-core`
  - [ ] `mitm-tls`
  - [ ] `mitm-http`
  - [ ] `mitm-policy`
  - [ ] `mitm-observe`
  - [ ] `mitm-sidecar` (optional).
- [ ] `soth` integration crate agreed: `crates/soth-proxy-adapter`.

## 1) Runtime and Dependency Baseline

- [ ] Pin toolchain:
  - [ ] `rust-toolchain.toml`
  - [ ] MSRV policy documented.
- [ ] Pin core runtime libs:
  - [ ] `tokio` (async runtime)
  - [ ] `hyper` + `hyper-util` (HTTP/1.1 + HTTP/2 plumbing)
  - [ ] `h2` (fine HTTP/2 control if needed)
  - [ ] `tokio-rustls` + `rustls` (TLS)
  - [ ] `rcgen` (default CA/leaf issuance path)
  - [ ] optional `openssl` path behind feature flag
  - [ ] `serde`/`serde_json` (contracts)
  - [ ] `tracing` + `metrics` (telemetry).
- [ ] Record current hudsucker capability gaps as hard requirements for `soth-mitm`:
  - [ ] SSE support
  - [ ] HTTP/2 support
  - [ ] HTTP/3 passthrough handling
  - [ ] gRPC stream observation.
- [ ] Use direct custom stack path in `mitm-core`/`mitm-http` for required protocols (no hudsucker dependency for these paths).
- [ ] Capture hudsucker TLS observability constraint in design docs:
  - [ ] `should_intercept` is available for CONNECT decision.
  - [ ] no direct client-TLS-failure callback (no `tls_failed_client` equivalent).
  - [ ] hudsucker TLS-failure attribution must be treated as inferred/best-effort.
- [ ] Adopt TLS-ops source priority:
  - [ ] `mitmproxy` callbacks as authoritative (`tls_failed_client` class surface).
  - [ ] custom/native path next when semantics are equivalent and validated.
  - [ ] hudsucker path marked inferred.

## 2) Config and Contract Freeze

- [ ] Define config schema with serde + validation:
  - [ ] listen addr/port
  - [ ] `ignore_hosts`
  - [ ] `http2_enabled`
  - [ ] `http2_max_header_list_size`
  - [ ] `http3_passthrough` (initially tunnel-only)
  - [ ] certificate paths/rotation settings
  - [ ] event sink settings (UDS/gRPC/file/queue).
- [ ] Freeze event schema (`v1`) before heavy implementation.
- [ ] Define compatibility policy for minor/patch versions.

## 3) Event API (Must Be Deterministic)

- [ ] Implement event types:
  - [ ] `connect_received`
  - [ ] `connect_decision`
  - [ ] `tls_handshake_started`
  - [ ] `tls_handshake_succeeded`
  - [ ] `tls_handshake_failed`
  - [ ] `request_headers`
  - [ ] `request_body_chunk`
  - [ ] `response_headers`
  - [ ] `response_body_chunk`
  - [ ] `stream_closed`.
- [ ] Ensure every event includes:
  - [ ] `flow_id`
  - [ ] `client_addr`
  - [ ] `server_host`
  - [ ] `server_port`
  - [ ] `protocol`
  - [ ] timestamp.
- [ ] Add ordering invariants and sequence ids for replay/debug.
- [ ] Add WebSocket turn-level event contract:
  - [ ] `ws_turn_started`
  - [ ] `ws_turn_completed`
  - [ ] turn id, initiator direction, frame counts, byte counts, start/end timestamps.

## 4) Phase 0: Bootstrap

- [ ] Create workspace skeleton and crate boundaries.
- [x] Add CI jobs:
  - [x] `cargo fmt --check`
  - [x] `cargo clippy -- -D warnings`
  - [x] `cargo test`
  - [x] integration smoke tests.
- [ ] Add fixture harness:
  - [x] Phase A CONNECT fixtures (`block`, `tunnel`, parse-failure, 500 concurrent short-lived tunnels).
  - [ ] HTTP/1.1 upstream
  - [ ] HTTP/2 upstream
  - [ ] WS/SSE upstream
  - [ ] TLS failure fixtures (unknown CA, invalid chain, timeout/reset).

## 5) Phase 1: Transport Core (Rust)

- [x] Phase A kickoff slice completed (initial implementation baseline):
  - [x] strict CONNECT request parsing (`host:port`, bracketed IPv6, header boundary detection)
  - [x] sidecar TCP listener with per-connection task handling
  - [x] policy-driven `block` response path
  - [x] policy-driven `tunnel` relay path (`copy_bidirectional`)
  - [x] parse-failure lifecycle (`connect_parse_failed` + `stream_closed` reason code)
  - [x] `stream_closed` event emission for blocked, upstream-fail, relay-eof, and relay-error paths
  - [x] Phase A integration tests for `block`, parse-failure, relay, and concurrency
  - [x] smoke harness script (`scripts/phase_a_smoke.sh`) + CI wiring (`.github/workflows/ci.yml`)
  - [x] workspace tests passing in offline mode (`cargo test --workspace --offline`)
  - [x] HTTP/1.1 MITM baseline implemented for `intercept` decision path (downstream TLS terminate + upstream TLS relay + HTTP lifecycle events)
  - [x] CA-backed certificate store implemented (load/generate, leaf cache, force-rotate hook, cache hit/miss metrics)

- [ ] `P1-01` Listener and flow lifecycle in `mitm-core`.
  - [ ] Scope: TCP accept loop, flow id allocation, connect/disconnect lifecycle events.
  - [ ] Deliverables: `mitm_core::server` module + integration test for concurrent connections.
  - [ ] Acceptance: 500 parallel short-lived connections complete without panics or leaked tasks.
- [ ] `P1-02` CONNECT parser and policy dispatch.
  - [ ] Scope: parse `host:port`, call policy engine, emit `connect_received` + `connect_decision`.
  - [ ] Deliverables: CONNECT parser with strict/lenient modes, policy decision trace fields.
  - [ ] Acceptance: golden tests for valid/invalid CONNECT lines and deterministic decisions.
- [ ] `P1-03` Action handlers: `block` and `tunnel`.
  - [ ] Scope: deterministic deny response for `block`, raw relay for `tunnel`.
  - [ ] Deliverables: response templates, structured reason codes, bypass metrics.
  - [ ] Acceptance: blocked hosts never open upstream sockets; tunneled hosts never trigger MITM path.
- [x] `P1-04` HTTP/1.1 MITM baseline.
  - [x] Scope: downstream TLS termination + upstream TLS/client relay for HTTP/1.1.
  - [x] Deliverables: request/response forwarding with header and body chunk event emission.
  - [x] Acceptance: fixture suite passes for plain HTTP/1.1 and HTTPS-over-CONNECT.
- [x] `P1-05` Certificate authority and leaf issuance.
  - [x] Scope: CA load/generate, leaf issuance by SNI/target host, cache strategy.
  - [x] Deliverables: cert store module, rotation hooks, cache hit/miss metrics.
  - [x] Hardening: persisted-CA reload derives issuer metadata from disk cert (config subject drift-safe).
  - [x] Hardening: cache-disabled mode and timed auto-rotation regression coverage.
  - [x] Hardening: invalid partial CA path configuration rejected with deterministic error.
  - [x] Acceptance: cert SAN/CN correctness tests pass for domain, wildcard, and IP targets.
- [x] `P1-06` TLS handshake eventing and taxonomy.
  - [x] Scope: `tls_handshake_started/succeeded/failed` and classifier for failure reasons.
  - [x] Deliverables: taxonomy mapper (`unknown_ca`, cert validation, handshake, timeout, EOF/reset, other).
  - [x] Hardening: `TlsHandshakeFailed` events now include normalized `tls_failure_reason` + raw `detail`.
  - [x] Acceptance: fixture corpus maps failures to expected categories with >= 95% match.
- [x] `P1-07` TLS diagnostics metadata and counters.
  - [x] Scope: per-host rolling counters + metadata fields `tls_failure_source` and `tls_ops_provider`.
  - [x] Deliverables: diagnostics struct, metrics export, event schema updates.
  - [x] Hardening: `TlsHandshakeFailed` events include host/source/reason/global counter snapshots.
  - [x] Acceptance: every TLS-failed event includes source/provider + host-scoped counter increments.
- [x] `P1-08` TLS learning guardrails.
  - [x] Scope: allow learning only from authoritative failures; suppress inferred hudsucker signals.
  - [x] Deliverables: policy gate in learner path + audit logs when events are ignored.
  - [x] Hardening: ignored signals emit `TlsLearningAudit` with decision/reason and raw signal metadata.
  - [x] Acceptance: inferred events never update learning state in integration tests.
- [x] `P1-09` mitmproxy TLS-ops adapter bridge.
  - [x] Scope: ingest mitmproxy TLS lifecycle callbacks and normalize into internal taxonomy.
  - [x] Deliverables: adapter module + provider error passthrough fields.
  - [x] Hardening: adapter-fed failed callbacks integrate with diagnostics + TLS learning guardrails and emit `TlsLearningAudit` for ignored non-authoritative provider signals.
  - [x] Acceptance: replayed callback fixtures produce same taxonomy as native path for covered cases.
- [x] `P1-10` Phase-1 reliability test gate.
  - [x] Scope: run all P1 integration tests in CI with deterministic fixtures.
  - [x] Deliverables: CI job + failure report artifact.
  - [x] Acceptance: green on Linux/macOS runners and reproducible locally.

## 6) Phase 2: Protocol Expansion

- [x] `P2-01` HTTP/2 transport enablement in `mitm-http`.
  - [x] Scope: config-driven enable/disable and per-connection H2 negotiation.
  - [x] Deliverables: H2 path wiring + protocol markers in events.
  - [x] Hardening: HTTP/2 relay maps transport-close EOF/reset/broken-pipe conditions to deterministic `mitm_http_completed` close semantics.
  - [x] Acceptance: H2 fixture traffic passes end-to-end with protocol=`http2`.
- [x] `P2-02` HTTP/2 limits and flow-control tuning.
  - [x] Scope: `http2_max_header_list_size` and backpressure-safe stream handling.
  - [x] Deliverables: configurable limits + stress tests for large headers and parallel streams.
  - [x] Hardening: explicit HPACK-style header-list enforcement for request/response headers before forwarding.
  - [x] Acceptance: large-header and parallel-stream fixtures pass with deterministic close semantics and byte accounting.
- [ ] `P2-03` WebSocket interception baseline.
  - [ ] Scope: upgrade detection, frame pass-through, websocket lifecycle events.
  - [ ] Deliverables: WS flow model + message metadata events.
  - [ ] Acceptance: WS echo and binary fixtures pass without frame corruption.
- [ ] `P2-04` WebSocket turn aggregator.
  - [ ] Scope: deterministic turn boundaries independent of hudsucker.
  - [ ] Deliverables: `ws_turn_started`/`ws_turn_completed` emission with flush on close/error/idle.
  - [ ] Acceptance: client-initiated and server-initiated turn tests match expected boundaries.
- [ ] `P2-05` SSE streaming parser.
  - [ ] Scope: incremental `text/event-stream` parsing (`event`, `id`, `retry`, multi-line `data`).
  - [ ] Deliverables: SSE parser state machine + deterministic stream-close flush.
  - [ ] Acceptance: long-lived SSE fixtures produce correct event records with no full-body buffering.
- [ ] `P2-06` HTTP/3 passthrough mode.
  - [ ] Scope: tunnel-only for HTTP/3 with explicit passthrough telemetry.
  - [ ] Deliverables: policy integration + protocol/mode indicators in emitted events.
  - [ ] Acceptance: HTTP/3 flows are tunneled and never decrypted in integration tests.
- [ ] `P2-07` gRPC flow observation over HTTP/2.
  - [ ] Scope: detect gRPC (`content-type`, path patterns), capture headers/trailers deterministically.
  - [ ] Deliverables: gRPC metadata event schema additions.
  - [ ] Acceptance: unary + streaming fixtures emit stable header/trailer ordering.
- [ ] `P2-08` gRPC envelope framing parser.
  - [ ] Scope: parse 5-byte envelope (`compressed`, `message_length`) across chunk boundaries.
  - [ ] Deliverables: parser + malformed-frame classification + boundary tests.
  - [ ] Acceptance: partial-frame and malformed-frame tests pass with expected classifications.
- [ ] `P2-09` Layered decoder chain.
  - [ ] Scope: deterministic order: transfer/content decode -> protocol frame parse -> payload parse.
  - [ ] Deliverables: decoder pipeline registry and per-stage failure reporting.
  - [ ] Acceptance: decoder-order invariants enforced by unit tests.
- [ ] `P2-10` Anti-hijack sanitization stage.
  - [ ] Scope: detect and strip known anti-hijack prefixes before JSON parsing.
  - [ ] Deliverables: sanitizer module + `sanitized=true/false` metadata field.
  - [ ] Acceptance: anti-hijack fixture payloads parse successfully with provenance flag set.
- [ ] `P2-11` MsgPack decode path.
  - [ ] Scope: content-type/heuristic detection, bounded decode limits, safe fallback to raw bytes.
  - [ ] Deliverables: msgpack parser module + limit configuration knobs.
  - [ ] Acceptance: malformed/oversized msgpack inputs fail safely without process instability.
- [ ] `P2-12` Phase-2 protocol test gate.
  - [ ] Scope: protocol matrix CI for HTTP/2, WS, SSE, HTTP/3 passthrough, gRPC, msgpack.
  - [ ] Deliverables: matrix test job + failure triage output artifact.
  - [ ] Acceptance: all P2 protocol fixtures green on CI before Phase 3 adapter integration.

## 7) Phase 3: SOTH Adapter

- [ ] Adapter consumes bundle rules and maps to `mitm-policy`.
- [ ] Adapter converts proxy events to Exchange inputs without semantic drift.
- [ ] Preserve existing SOTH identity/budget/routing checks.
- [ ] Add conformance tests with golden flow fixtures.

## 8) Phase 4: Hardening

- [ ] Fuzz targets:
  - [ ] CONNECT parser/state machine
  - [ ] TLS classification parser
  - [ ] HTTP header parsing boundaries.
  - [ ] gRPC framing parser boundaries (length mismatches, chunk splits, compression flag handling).
  - [ ] SSE incremental parser boundaries (line breaks, partial fields, very long events).
  - [ ] msgpack decoder bounds (depth, map size, malformed input).
  - [ ] layered decoder ordering/interaction invariants.
- [ ] Performance gates:
  - [ ] connection churn
  - [ ] long-lived streams
  - [ ] header stress
  - [ ] memory ceiling checks.
- [ ] Failure injection:
  - [ ] reset/timeout
  - [ ] invalid cert chains
  - [ ] upstream EOF mid-stream.
- [ ] Adopt and execute `PROXY_TESTING_AND_HARDENING_PLAN.md` as the authoritative hardening work plan.
- [ ] Implement required tool lanes from plan:
  - [ ] `h2spec`
  - [ ] `h2load`
  - [ ] `curl` (`--proxy`, `--http2`, `--http3`)
  - [ ] `websocat` + Autobahn Test Suite
  - [ ] `grpcurl` + `ghz`
  - [ ] `openssl s_client` + `testssl.sh` + `badssl.com`
  - [ ] `wrk` + `hey`
  - [ ] `toxiproxy` + `tc netem`
  - [ ] `proptest` + `cargo-fuzz`.
- [ ] Differential validation lanes:
  - [ ] compare `soth-mitm` vs mitmproxy event ordering on shared fixture corpus
  - [ ] compare TLS taxonomy and source-confidence metadata
  - [ ] keep hudsucker comparison lane scoped to supported protocol/mode surface only.
- [ ] Do not use deprecated mitmproxy `pathod/pathoc` tooling for new test harnesses.

## 9) Migration in `soth`

- [ ] Dual engine config:
  - [ ] `proxy_engine: hudsucker`
  - [ ] `proxy_engine: soth-mitm`.
- [ ] Shadow mode:
  - [ ] compare decisions
  - [ ] compare TLS outcomes
  - [ ] compare emitted events/order.
- [ ] Cutover gates:
  - [ ] parity threshold hit
  - [ ] soak period passes
  - [ ] rollback tested.
- [ ] Do not route SSE/HTTP2/HTTP3/gRPC traffic to hudsucker during migration cohorts.
- [ ] Do not use hudsucker cohorts as source-of-truth for TLS failure learning metrics.
- [ ] Start TLS-learning rollouts with mitmproxy-backed cohorts first.

## 10) Definition of Done

- [ ] Rust proxy emits all required events with deterministic ordering.
- [ ] TLS taxonomy correctness validated by fixture corpus.
- [ ] Pinning bypass behavior validated for known problematic hosts.
- [ ] Performance + memory budgets pass in CI.
- [ ] `soth` adapter parity accepted and default cutover approved.
- [ ] SSE/HTTP2/HTTP3/gRPC requirements met without relying on hudsucker fallback.

## Primary Rust Sources

- https://github.com/omjadas/hudsucker
- https://docs.rs/hudsucker/latest/hudsucker/
- https://github.com/hyperium/hyper
- https://hyper.rs/guides/1/
- https://github.com/rustls/tokio-rustls
- https://docs.rs/tokio-rustls/latest/tokio_rustls/
- https://github.com/rustls/rcgen
- https://docs.rs/rcgen/latest/rcgen/
