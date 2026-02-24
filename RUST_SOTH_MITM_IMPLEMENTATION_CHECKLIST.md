# Rust `soth-mitm` Implementation Checklist

This checklist turns `LIGHTWEIGHT_PROXY_REPO_IMPLEMENTATION_PLAN.md` into an execution plan for a Rust-native implementation.

## 0) Naming and Workspace Contract

- [x] Repo name is `soth-mitm` and all docs/config/labels use this naming consistently.
- [x] Rust workspace created with crates:
  - [x] `mitm-core`
  - [x] `mitm-tls`
  - [x] `mitm-http`
  - [x] `mitm-policy`
  - [x] `mitm-observe`
  - [x] `mitm-sidecar` (optional).
- [x] Consumer integration crate contract agreed (implemented outside proxy core; see `docs/consumer/soth-proxy-adapter-contract.md`, e.g. `soth-proxy-adapter` in `soth` repo).

## 1) Runtime and Dependency Baseline

- [x] Pin toolchain:
  - [x] `rust-toolchain.toml`
  - [x] MSRV policy documented.
- [x] Pin core runtime libs:
  - [x] `tokio` (async runtime)
  - [x] `hyper` + `hyper-util` (HTTP/1.1 + HTTP/2 plumbing)
  - [x] `h2` (fine HTTP/2 control if needed)
  - [x] `tokio-rustls` + `rustls` (TLS)
  - [x] `rcgen` (default CA/leaf issuance path)
  - [x] optional `openssl` path behind feature flag
  - [x] `serde`/`serde_json` (contracts)
  - [x] `tracing` + `metrics` (telemetry).
- [x] Record current hudsucker capability gaps as hard requirements for `soth-mitm`:
  - [x] SSE support
  - [x] HTTP/2 support
  - [x] HTTP/3 passthrough handling
  - [x] gRPC stream observation.
- [x] Use direct custom stack path in `mitm-core`/`mitm-http` for required protocols (no hudsucker dependency for these paths).
- [x] Capture hudsucker TLS observability constraint in design docs:
  - [x] `should_intercept` is available for CONNECT decision.
  - [x] no direct client-TLS-failure callback (no `tls_failed_client` equivalent).
  - [x] hudsucker TLS-failure attribution must be treated as inferred/best-effort.
- [x] Adopt TLS-ops source priority:
  - [x] `mitmproxy` callbacks as authoritative (`tls_failed_client` class surface).
  - [x] custom/native path next when semantics are equivalent and validated.
  - [x] hudsucker path marked inferred.

## 2) Config and Contract Freeze

- [x] Define config schema with serde + validation:
  - [x] listen addr/port
  - [x] `ignore_hosts`
  - [x] `http2_enabled`
  - [x] `http2_max_header_list_size`
  - [x] `http3_passthrough` (initially tunnel-only)
  - [x] certificate paths/rotation settings
  - [x] event sink settings (UDS/gRPC/file/queue).
- [x] Freeze event schema (`v1`) before heavy implementation.
- [x] Define compatibility policy for minor/patch versions.

## 3) Event API (Must Be Deterministic)

- [x] Implement event types:
  - [x] `connect_received`
  - [x] `connect_decision`
  - [x] `tls_handshake_started`
  - [x] `tls_handshake_succeeded`
  - [x] `tls_handshake_failed`
  - [x] `request_headers`
  - [x] `request_body_chunk`
  - [x] `response_headers`
  - [x] `response_body_chunk`
  - [x] `stream_closed`.
- [x] Ensure every event includes:
  - [x] `flow_id`
  - [x] `client_addr`
  - [x] `server_host`
  - [x] `server_port`
  - [x] `protocol`
  - [x] timestamp.
- [x] Add ordering invariants and sequence ids for replay/debug.
- [x] Add WebSocket turn-level event contract:
  - [x] `ws_turn_started`
  - [x] `ws_turn_completed`
  - [x] turn id, initiator direction, frame counts, byte counts, start/end timestamps.

## 4) Phase 0: Bootstrap

- [x] Create workspace skeleton and crate boundaries.
- [x] Add CI jobs:
  - [x] `cargo fmt --check`
  - [x] `cargo clippy -- -D warnings`
  - [x] `cargo test`
  - [x] integration smoke tests.
- [x] Add fixture harness:
  - [x] Phase A CONNECT fixtures (`block`, `tunnel`, parse-failure, 500 concurrent short-lived tunnels).
  - [x] HTTP/1.1 upstream
  - [x] HTTP/2 upstream
  - [x] WS/SSE upstream
  - [x] TLS failure fixtures (unknown CA, invalid chain, timeout/reset).

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

- [x] `P1-01` Listener and flow lifecycle in `mitm-core`.
  - [x] Scope: TCP accept loop, flow id allocation, connect/disconnect lifecycle events.
  - [x] Deliverables: `mitm_core::server` module + integration test for concurrent connections.
  - [x] Acceptance: 500 parallel short-lived connections complete without panics or leaked tasks.
- [x] `P1-02` CONNECT parser and policy dispatch.
  - [x] Scope: parse `host:port`, call policy engine, emit `connect_received` + `connect_decision`.
  - [x] Deliverables: CONNECT parser with strict/lenient modes, policy decision trace fields.
  - [x] Acceptance: golden tests for valid/invalid CONNECT lines and deterministic decisions.
- [x] `P1-03` Action handlers: `block` and `tunnel`.
  - [x] Scope: deterministic deny response for `block`, raw relay for `tunnel`.
  - [x] Deliverables: response templates, structured reason codes, bypass metrics.
  - [x] Acceptance: blocked hosts never open upstream sockets; tunneled hosts never trigger MITM path.
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
- [x] `P2-03` WebSocket interception baseline.
  - [x] Scope: upgrade detection, frame pass-through, websocket lifecycle events.
  - [x] Deliverables: WS flow model + message metadata events.
  - [x] Hardening: frame parser handles variable length headers, mask keys, and close frame semantics without mutating payload bytes.
  - [x] Acceptance: WS echo and binary fixtures pass without frame corruption.
- [x] `P2-04` WebSocket turn aggregator.
  - [x] Scope: deterministic turn boundaries independent of hudsucker.
  - [x] Deliverables: `ws_turn_started`/`ws_turn_completed` emission with flush on close/error/idle.
  - [x] Hardening: observer pipeline flushes pending turn state on close frames, relay errors, and idle timeouts without emitting post-close phantom turns.
  - [x] Acceptance: client-initiated and server-initiated turn tests match expected boundaries.
- [x] `P2-05` SSE streaming parser.
  - [x] Scope: incremental `text/event-stream` parsing (`event`, `id`, `retry`, multi-line `data`).
  - [x] Deliverables: SSE parser state machine + deterministic stream-close flush.
  - [x] Hardening: parser ignores comment lines and invalid retry fields while preserving stream continuity.
  - [x] Acceptance: long-lived SSE fixtures produce correct event records with no full-body buffering.
- [x] `P2-06` HTTP/3 passthrough mode.
  - [x] Scope: tunnel-only for HTTP/3 with explicit passthrough telemetry.
  - [x] Deliverables: policy integration + protocol/mode indicators in emitted events.
  - [x] Hardening: passthrough override respects policy blocks and records source hint + prior policy action for auditability.
  - [x] Acceptance: HTTP/3-designated flows are tunneled and never decrypted in integration tests.
- [x] `P2-07` gRPC flow observation over HTTP/2.
  - [x] Scope: detect gRPC (`content-type`, path patterns), capture headers/trailers deterministically.
  - [x] Deliverables: gRPC metadata event schema additions.
  - [x] Acceptance: unary + streaming fixtures emit stable header/trailer ordering.
- [x] `P2-08` gRPC envelope framing parser.
  - [x] Scope: parse 5-byte envelope (`compressed`, `message_length`) across chunk boundaries.
  - [x] Deliverables: parser + malformed-frame classification + boundary tests.
  - [x] Acceptance: partial-frame and malformed-frame tests pass with expected classifications.
- [x] `P2-09` Layered decoder chain.
  - [x] Scope: deterministic order: transfer/content decode -> protocol frame parse -> payload parse.
  - [x] Deliverables: decoder pipeline registry and per-stage failure reporting.
  - [x] Acceptance: decoder-order invariants enforced by unit tests.
- [x] `P2-10` Anti-hijack sanitization stage.
  - [x] Scope: detect and strip known anti-hijack prefixes before JSON parsing.
  - [x] Deliverables: sanitizer module + `sanitized=true/false` metadata field.
  - [x] Acceptance: anti-hijack fixture payloads parse successfully with provenance flag set.
- [x] `P2-11` MsgPack decode path.
  - [x] Scope: content-type/heuristic detection, bounded decode limits, safe fallback to raw bytes.
  - [x] Deliverables: msgpack parser module + limit configuration knobs.
  - [x] Acceptance: malformed/oversized msgpack inputs fail safely without process instability.
- [x] `P2-12` Phase-2 protocol test gate.
  - [x] Scope: protocol matrix CI for HTTP/2, WS, SSE, HTTP/3 passthrough, gRPC, msgpack.
  - [x] Deliverables: matrix test job + failure triage output artifact.
  - [x] Acceptance: gate enforces all required P2 protocol fixtures and fails on missing coverage or failing lanes.
- [x] `P2-13` Protocol triage aggregation.
  - [x] Scope: merge lane artifacts into a single actionable summary.
  - [x] Deliverables: `status_aggregate.tsv`, `summary.md`, `failed_lanes.txt`, `missing_protocols.txt`.
  - [x] Acceptance: triage job exits non-zero on lane failures or missing required protocol coverage.
- [x] `P2-14` Local Phase-2 matrix orchestrator.
  - [x] Scope: deterministic local execution of all P2 protocol lanes.
  - [x] Deliverables: `scripts/p2_protocol_matrix.sh`.
  - [x] Acceptance: local command runs all lanes then triage with a single pass/fail result.
- [x] `P2-15` Required protocol-coverage assertions.
  - [x] Scope: enforce `http2`, `websocket`, `sse`, `http3_passthrough`, `grpc_http2`, `msgpack`.
  - [x] Deliverables: triage-time required-protocol coverage checks.
  - [x] Acceptance: missing protocol coverage hard-fails the gate.
- [x] `P2-16` CI lane matrix job.
  - [x] Scope: split Phase-2 protocol suites into per-lane CI jobs.
  - [x] Deliverables: `phase2_protocol_matrix` GitHub Actions job.
  - [x] Acceptance: one artifact package uploaded per lane.
- [x] `P2-17` CI triage aggregation job.
  - [x] Scope: collect lane artifacts and compute final protocol-gate verdict.
  - [x] Deliverables: `phase2_protocol_triage` GitHub Actions job + triage artifact upload.
  - [x] Acceptance: CI gate fails when triage identifies failing lanes or missing protocol coverage.
- [x] `P2-18` Protocol matrix runbook.
  - [x] Scope: document matrix lanes, required coverage, and local usage.
  - [x] Deliverables: `docs/testing/protocol-matrix.md`.
  - [x] Acceptance: runbook maps every required protocol to its lane command.
- [x] `P2-19` CI gates runbook.
  - [x] Scope: document CI job contract and triage artifact schema.
  - [x] Deliverables: `docs/testing/ci-gates.md`.
  - [x] Acceptance: runbook covers job roles, fail conditions, and artifact paths.
- [x] `P2-20` Developer testing entrypoint update.
  - [x] Scope: expose new P2 commands in top-level docs.
  - [x] Deliverables: `README.md` testing section updates.
  - [x] Acceptance: README includes direct local commands for Phase-2 gate execution.
- [x] `P2-21` Matrix manifest-driven lane source of truth.
  - [x] Scope: centralize lane definitions in a versioned manifest.
  - [x] Deliverables: `scripts/p2_protocol_matrix.tsv`.
  - [x] Acceptance: lane runner and local orchestrator both read the same manifest file.

## 7) Phase 3: Consumer Adapter Surface (Proxy-Core First)

- [x] Expose stable handler interfaces for decisions (`intercept|tunnel|block`) without product-specific rule logic (`tunnel` is metadata-only passthrough mode).
- [x] Expose stable event-consumer interfaces for deterministic proxy event streams.
- [x] Keep `soth-mitm` free of vendor/product-specific behavior; downstream consumers map their own rules into proxy handlers.
- [x] Add consumer-agnostic conformance tests with golden flow fixtures.

## 8) Phase 4: Hardening

- [x] Fuzz targets:
  - [x] CONNECT parser/state machine
  - [x] TLS classification parser
  - [x] HTTP header parsing boundaries.
  - [x] gRPC framing parser boundaries (length mismatches, chunk splits, compression flag handling).
  - [x] SSE incremental parser boundaries (line breaks, partial fields, very long events).
  - [x] msgpack decoder bounds (depth, map size, malformed input).
  - [x] layered decoder ordering/interaction invariants.
- [x] Performance gates:
  - [x] connection churn
  - [x] long-lived streams
  - [x] header stress
  - [x] memory ceiling checks.
- [x] Failure injection:
  - [x] reset/timeout
  - [x] invalid cert chains
  - [x] upstream EOF mid-stream.
- [x] Adopt and execute `PROXY_TESTING_AND_HARDENING_PLAN.md` as the authoritative hardening work plan.
- [x] Implement required tool lanes from plan:
  - [x] `h2spec`
  - [x] `h2load`
  - [x] `curl` (`--proxy`, `--http2`, `--http3`)
  - [x] `websocat` + Autobahn Test Suite
  - [x] `grpcurl` + `ghz`
  - [x] `openssl s_client` + `testssl.sh` + `badssl.com`
  - [x] `wrk` + `hey`
  - [x] `toxiproxy` + `tc netem`
  - [x] `proptest` + `cargo-fuzz`.
- [x] Differential validation lanes:
  - [x] compare `soth-mitm` vs mitmproxy event ordering on shared fixture corpus
  - [x] compare TLS taxonomy and source-confidence metadata
  - [x] keep hudsucker comparison lane scoped to supported protocol/mode surface only.
- [x] Do not use deprecated mitmproxy `pathod/pathoc` tooling for new test harnesses.

## 9) Migration in `soth`

- [x] Migration/cutover playbook documented in `docs/migration/soth-cutover.md`.
- [x] Dual engine config:
  - [x] `proxy_engine: hudsucker`
  - [x] `proxy_engine: soth-mitm`.
- [x] Shadow mode:
  - [x] compare decisions
  - [x] compare TLS outcomes
  - [x] compare emitted events/order.
- [x] Cutover gates:
  - [x] parity threshold hit
  - [x] soak period passes
  - [x] rollback tested.
- [x] Do not route SSE/HTTP2/HTTP3/gRPC traffic to hudsucker during migration cohorts.
- [x] Do not use hudsucker cohorts as source-of-truth for TLS failure learning metrics.
- [x] Start TLS-learning rollouts with mitmproxy-backed cohorts first.

## 10) Definition of Done

- [x] Rust proxy emits all required events with deterministic ordering.
- [x] TLS taxonomy correctness validated by fixture corpus.
- [x] Pinning bypass behavior validated for known problematic hosts.
- [x] Performance + memory budgets pass in CI.
- [ ] Consumer adapter parity accepted and downstream cutover approved.
- [x] SSE/HTTP2/HTTP3/gRPC requirements met without relying on hudsucker fallback.

## 11) Principal Engineer Charter Deltas

- [x] Protocol coverage baseline aligned with charter:
  - [x] HTTP/1 + HTTP/2 transport correctness and deterministic close semantics.
  - [x] WebSocket interception with deterministic turn aggregation.
  - [x] SSE incremental parsing with deterministic close flush.
  - [x] HTTP/3 passthrough-only policy with explicit telemetry.
  - [x] gRPC header/trailer observation over HTTP/2.
- [x] Deterministic event contract hardening:
  - [x] Every event includes `flow_id`.
  - [x] Add global per-flow `sequence_id` across all emitted events.
  - [x] Move timestamps to monotonic ordering semantics for replay stability.
  - [x] Add replay assertions proving identical event sequence on deterministic fixture replays.
- [x] Flow state machine invariants:
  - [x] Encode explicit flow state machine (`Accepted -> ... -> Closed`) in core flow runtime.
  - [x] Add debug assertions for illegal transitions.
  - [x] Prove every flow path terminates with exactly one `stream_closed`.
- [x] Risk budget enforcement:
  - [x] Add explicit per-flow memory ceilings (body buffers, decoder buffers, pending metadata).
  - [x] Add global in-flight byte and concurrent flow caps.
  - [x] Replace unbounded channels in core protocol paths with bounded/backpressure-aware queues.
- [x] TLS contract parity with charter:
  - [x] Learning ignores inferred providers.
  - [x] Host-scoped TLS failure counters present.
  - [x] Normalize field set to include: `normalized_reason`, `raw_provider_error`, `provider_identity`, `source_confidence`.
- [x] Decoder chain discipline:
  - [x] Complete `P2-08` gRPC 5-byte envelope parser with chunk-split and mismatch classification.
  - [x] Complete `P2-09` layered decoder chain with stage-level failure events.
  - [x] Complete `P2-10` anti-hijack sanitization with provenance metadata.
  - [x] Complete `P2-11` msgpack parser with bounded decode/fallback safety.
  - [x] Complete `P2-12`..`P2-21` protocol matrix/triage gate, CI lanes, and runbooks for Phase-2 coverage.
- [x] Self-observability and differential validation:
  - [x] Expose queue depth, flow duration, decoder failure, backpressure activation, and memory watermark metrics.
  - [x] Build replay/differential lane (`soth-mitm` vs mitmproxy; hudsucker limited to supported surface).
- [x] Chaos and adversarial suite:
  - [x] Add charter scenarios (TLS fragmenting, malformed HPACK, gRPC split frames, infinite SSE, jitter/loss).
  - [x] Gate merges/releases on no panic + deterministic close semantics under chaos corpus.

## 12) Phase 5: Feature-First Mitigation Packs (from mitmproxy Top-100 Audit)

- [ ] `P5-01` Runtime budget envelope everywhere.
  - [ ] Scope: extend runtime-governor enforcement across all protocol paths (`HTTP/1`, `HTTP/2`, `WS`, `SSE`, gRPC relay).
  - [ ] Deliverables: per-protocol budget hooks + leak tripwire metrics + soak-gate assertions.
  - [ ] Acceptance: no unbounded RSS/queue growth in 6-12h mixed-traffic soak.
  - [x] Implementation start: runtime budget hooks wired into HTTP body relay (`content-length`, `chunked`, `close-delimited`), WebSocket frame/payload relay, and HTTP/2 data/trailer forwarding.
  - [x] Implementation start: runtime tripwire metric `budget_denial_count` added and incremented on in-flight reservation denial + flow-permit saturation.
  - [x] Implementation closure: mixed-traffic soak gate lane added (`crates/mitm-sidecar/tests/mixed_traffic_soak.rs`, `scripts/p5_runtime_soak.sh`) and wired into configurable profiles (`testing/lanes/registry.tsv`, `scripts/run_testing_plan.sh`).
  - [x] Reliability contract `1-6` implementation:
    - [x] failure-class matrix and hard invariants documented (`docs/testing/reliability-invariants.md`).
    - [x] invariants wired to executable gate lane (`scripts/p5_reliability_contract.sh`, `testing/lanes/registry.tsv`).
    - [x] central idle watchdog wrappers enforced across core relay/parser I/O paths.
    - [x] per-stream stage timeout budget wrapper enforced on HTTP/2 relay stages.
    - [x] structured stuck-flow telemetry counters and timeout close reason codes (`idle_watchdog_timeout`, `stream_stage_timeout`).
    - [x] parity guidance codified as invariant-first, not blind lockstep parity.
  - [ ] Pending: execute and gate the full 6-12h mixed-traffic soak for final `P5-01` completion.
- [x] `P5-02` Flow FSM + transition validator.
  - [x] Scope: explicit protocol state machines with legal transition checks and deterministic close mapping.
  - [x] Deliverables: flow transition tables + invariants + panic-free terminalization path.
    - [x] protocol-machine-aware transition validator implemented in `crates/mitm-core/src/flow_state.rs`.
    - [x] dedicated transition-table doc added: `docs/testing/flow-fsm-transition-table.md`.
    - [x] panic-free terminalization path on illegal transitions (`StreamClosing` fallback + invalid-transition counters).
  - [x] Acceptance: exactly one `stream_closed` per flow and no illegal transition panics under chaos lanes.
    - [x] single-close guardrail test: `suppresses_duplicate_stream_closed_for_same_flow`.
    - [x] illegal-transition terminalization test: `invalid_transition_terminalizes_without_panic_and_allows_close`.
    - [x] `phase5_reliability_contract` lane now runs FSM validator + single-close guardrail checks.
- [x] `P5-03` HTTP/1 canonicalization + smuggling guard.
  - [x] Scope: strict request/response head canonicalization and TE/CL conflict handling.
  - [x] Deliverables: centralized parser/canonicalizer + malformed/smuggling fixture corpus.
  - [x] Acceptance: RFC-conflict fixtures hard-fail deterministically; absolute-form proxy semantics preserved.
  - [x] Implementation start:
    - [x] centralized header canonicalization path added (`crates/mitm-sidecar/src/http_head_parser_smuggling.rs`).
    - [x] request/response TE+CL conflict hard-fail and unsupported transfer-coding rejection.
    - [x] conflicting multi-value `Content-Length` hard-fail; identical repeated values accepted.
    - [x] folded header rejection and strict header-name/value validation.
    - [x] parser fixture coverage expanded in `http_head_parser_api_tests` for smuggling/absolute-form behavior.
  - [x] Implementation closure:
    - [x] strict parser guards extended for signed `Content-Length`, duplicate `chunked`, and header-name colon whitespace.
    - [x] fixture corpus lane added (`crates/mitm-sidecar/tests/http1_head_corpus.rs`) covering malformed/smuggling request+response heads.
    - [x] deterministic runtime rejection fixtures added (`crates/mitm-sidecar/tests/http1_mitm_cases/smuggling_guards.rs`) for forward-proxy and intercept paths.
    - [x] gate lane added (`scripts/p5_http1_smuggling_guard.sh`, `testing/lanes/registry.tsv`) and validated through `run_testing_plan`.
    - [x] absolute-form proxy semantics preserved in relay fixture (`crates/mitm-sidecar/tests/http1_mitm_cases/success_paths.rs`).
- [x] `P5-04` TLS policy matrix + cert compatibility profiles.
  - [x] Scope: formal `strict|default|compat` TLS profiles with explicit SNI/cipher/protocol policy and cert profile controls.
  - [x] Deliverables: profile config schema + matrix tests (`openssl`, `badssl`, fixture cert chains).
    - [x] profile schema added in `mitm-core` (`tls_profile`, `upstream_sni_mode`, `downstream_cert_profile`) with strict/SNI validation.
    - [x] upstream policy builder added in `mitm-tls` (`build_http_client_config_with_policy`) with deterministic protocol/cipher + SNI behavior.
    - [x] downstream cert compatibility profiles wired (`modern|compat`) into CA leaf issuance path.
    - [x] sidecar handshake path now enforces TLS profile policy and emits deterministic handshake taxonomy on profile failures.
    - [x] profile-matrix lane added (`scripts/p5_tls_profile_matrix.sh`, `testing/lanes/registry.tsv`) with `openssl` and optional `badssl` probe coverage.
  - [x] Acceptance: deterministic TLS taxonomy outcomes across profile matrix with no unexpected handshake regressions.
    - [x] `cargo test -p mitm-sidecar --test tls_profile_matrix -q` passes.
    - [x] `./scripts/p5_tls_profile_matrix.sh --report-dir testing/reports/phase5_tls_profile_matrix --skip-network` passes (`badssl_probe` skipped by explicit flag).
- [x] `P5-05` Upstream route planner abstraction.
  - [x] Scope: route modes `direct|reverse|upstream-http|upstream-socks5` with immutable per-flow route binding.
  - [x] Deliverables: route planner module + config validation + deterministic policy integration.
    - [x] route-mode config schema and strict validation added in `mitm-core` (`route_mode`, `reverse_upstream`, `upstream_http_proxy`, `upstream_socks5_proxy`).
    - [x] immutable per-flow route binding implemented in sidecar route planner (`FlowRoutePlanner::bind_once`) with explicit rebind rejection.
    - [x] CONNECT tunnel + intercept + forward HTTP paths now route through shared planner (`direct`, `reverse`, upstream HTTP CONNECT chain, upstream SOCKS5 chain).
    - [x] policy integration remains target-based in chained mode (policy input uses `target_host:target_port`, never proxy next-hop).
  - [x] Acceptance: route mode matrix passes; host allow/ignore semantics remain correct in chained mode.
    - [x] `cargo test -p mitm-sidecar --test route_mode_matrix -q` passes.
    - [x] `./scripts/p5_route_mode_matrix.sh --report-dir testing/reports/phase5_route_mode_matrix` passes.
- [x] `P5-06` HTTP/2 resilience pack.
  - [x] Scope: stream lifecycle hardening, GOAWAY/reset handling, and header-limit parity.
    - [x] stream-task error handling now classifies benign remote GOAWAY/reset paths and avoids escalating them to flow-fatal errors.
    - [x] non-fatal stream-level failures now reset only affected streams (no connection-wide abort for benign cancel/refused/stream-closed paths).
    - [x] per-stream header-limit violations now hard-reset the offending stream deterministically.
  - [x] Deliverables: H2 state/flow-control improvements + `h2spec` blocking criteria.
    - [x] H2 resilience helpers added (`is_h2_nonfatal_stream_error`, benign stream-io classification, downstream reset reason mapping).
    - [x] HTTP/2 relay path hardened for upstream sender readiness, send-request failures, response-header awaits, and downstream response send failures.
    - [x] new integration fixture added: upstream `RST_STREAM(CANCEL)` on one stream does not fail whole flow.
    - [x] resilience lane added: `scripts/p5_http2_resilience.sh` + `testing/lanes/registry.tsv` + `docs/testing/h2spec-blocking-criteria.md`.
  - [x] Acceptance: no assertion/panic under parallel H2 stream stress; protocol matrix remains green.
    - [x] `cargo test -p mitm-sidecar --test http2_mitm -q` passes.
    - [x] `./scripts/p5_http2_resilience.sh --report-dir testing/reports/phase5_http2_resilience` passes.
- [x] `P5-07` Deterministic event log v2 + automation contract.
  - [x] Scope: stream-aware stable serialization and machine-readable failure/exit contracts.
    - [x] deterministic event log v2 serializer added in `mitm-observe` (`schema: soth-mitm-event-log-v2`) with protocol-aware `stream_key` derivation.
    - [x] sidecar now emits structured status lines (`SOTH_MITM_STATUS\t<json>`) with deterministic exit classes/codes for automation.
  - [x] Deliverables: deterministic event serialization spec + replay indexability + parent-process output guarantees.
    - [x] event log v2 sink supports flush cadence and byte-based segment rotation with index rows (`segment_id`, `byte_offset`, `line_bytes`).
    - [x] differential replay lane now prefers `.events.v2.jsonl` fixtures and falls back to legacy `.events.tsv`.
    - [x] contract docs + lane added (`docs/testing/event-log-v2-contract.md`, `scripts/p5_event_log_contract.sh`, `testing/lanes/registry.tsv`).
  - [x] Acceptance: replay diffs are stable across repeated runs; automation can classify failures via exit/status contracts.
    - [x] `cargo test -p mitm-observe --test event_log_v2 -q` passes.
    - [x] `cargo test -p mitm-sidecar --test automation_contract -q` passes.
    - [x] `./scripts/p5_event_log_contract.sh --report-dir testing/reports/phase5_event_log_contract` passes.
- [ ] `P5-08` Compatibility override layer.
  - [ ] Scope: controlled per-host policy overrides (`force_tunnel`, `disable_h2`, strict header mode, sanctioned TLS overrides).
  - [ ] Deliverables: override schema + rule provenance/audit fields in emitted events.
  - [ ] Acceptance: targeted problematic hosts recover without global behavior regressions.
- [ ] `P5-09` Cross-platform socket/net hardening.
  - [ ] Scope: IPv6, Windows socket lifecycle, and FD/concurrency pressure robustness.
  - [ ] Deliverables: platform-specific socket guards + matrix tests + pressure instrumentation.
  - [ ] Acceptance: Linux/macOS/Windows matrix passes lifecycle and stress gates with deterministic close semantics.
- [ ] `P5-10` Control-plane boundary guards (conditional surface).
  - [ ] Scope: only if management/control endpoints are exposed.
  - [ ] Deliverables: anti-rebinding defaults + host/origin allowlists + boundary tests.
  - [ ] Acceptance: control-plane endpoints are non-bypassable by default.

Reference:
- `docs/research/mitmproxy-feature-first-mitigation-plan-2026-02-24.md`

## Primary Rust Sources

- https://github.com/omjadas/hudsucker
- https://docs.rs/hudsucker/latest/hudsucker/
- https://github.com/hyperium/hyper
- https://hyper.rs/guides/1/
- https://github.com/rustls/tokio-rustls
- https://docs.rs/tokio-rustls/latest/tokio_rustls/
- https://github.com/rustls/rcgen
- https://docs.rs/rcgen/latest/rcgen/
