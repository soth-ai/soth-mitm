# soth-mitm Aggregated Plan, Hardening, and Test Guide

This file consolidates planning, hardening, checklist, protocol matrix, performance notes, and fuzz guidance into a single reference.

## Included Sources

- `LIGHTWEIGHT_PROXY_REPO_IMPLEMENTATION_PLAN.md`
- `MITMPROXY_LESSONS_LEARNED_FOR_SOTH_MITM.md`
- `PROXY_TESTING_AND_HARDENING_PLAN.md`
- `RUST_SOTH_MITM_IMPLEMENTATION_CHECKLIST.md`
- `docs/PROXY_PERFORMANCE_RESEARCH_NOTES.md`
- `docs/testing/protocol-matrix.md`
- `fuzz/README.md`

---

## Source: `LIGHTWEIGHT_PROXY_REPO_IMPLEMENTATION_PLAN.md`

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
   - layered decoders (transfer/content encoding + protocol framing + transport sanitization).
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
   - decoder chain ordering (`chunked`/`gzip`/`br`/`deflate` -> protocol frame parser -> transport sanitizer).
   - gRPC framing parser + error classification.
   - SSE parser with incremental state machine.
   - anti-hijack stripping/sanitization pass.

### Phase 3: SOTH Adapter
1. Replace direct hudsucker dependency in `soth` with adapter to `soth-mitm`.
2. Wire OISP decision engine into adapter callback path.
3. Preserve current downstream contract and event semantics.

### Phase 4: Hardening
1. Fuzz parsers and CONNECT/TLS state machine (including gRPC framing/SSE/layered decode paths).
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

---

## Source: `MITMPROXY_LESSONS_LEARNED_FOR_SOTH_MITM.md`

# mitmproxy Lessons Learned for `soth-mitm`

This document summarizes practical lessons extracted from the full `mitmproxy` git history and current code/docs.

## Scope of Analysis

- Repo analyzed: `https://github.com/mitmproxy/mitmproxy`
- Local clone path: `/tmp/mitmproxy-full`
- Commit count analyzed: `11,096`
- Timespan analyzed: `2010-02-16` to `2026-02-10`
- Revert/rollback/undo commits observed: `42`

## What History Says Matters Most

- Most change activity clusters around proxy core, addons, and tooling (path-level hotspots: `mitmproxy/proxy`, `mitmproxy/addons`, `mitmproxy/tools`).
- Protocol features (especially HTTP/2, QUIC/HTTP/3, TLS, WebSocket, streaming) repeatedly received follow-up bugfixes after initial delivery.
- Fuzzing appears repeatedly as a bug discovery mechanism for HTTP/TLS parsing and state handling.
- Dependency pinning/updating is continuous and operationally important (regular upper-bound bumps and compatibility fixes).

## Major Lessons (Do / Do Not)

## 1) Architecture and Refactors

Do:
- Keep protocol logic separate from I/O and transport orchestration.
- Keep layers explicit (CONNECT, TLS, HTTP, WS, QUIC) with typed events between layers.
- Invest in test harnesses before and during large refactors.

Do not:
- Ship big protocol rewrites without dense protocol and regression tests.
- Mix flow semantics, transport semantics, and UI semantics in one module.

Evidence:
- `d159897d9` (`2020-12-14`) "nuke legacy protocol stack" touched a very large cross-section of proxy/test code.
- Changelog for `6.0` notes protocol logic separation into sans-io internals and emphasizes race/test benefits (`CHANGELOG.md` around `2020-12` entries).

## 2) TLS Operations and Failure Attribution

Do:
- Treat client and server TLS handshake lifecycle as separate signals.
- Keep dedicated hooks/events for start/success/failure per side.
- Preserve original TLS error context and classify separately.
- Gate learning/auto-actions by confidence of failure source.

Do not:
- Infer client TLS failure from generic connect failures when direct callback signals are unavailable.
- Collapse client/server handshake failures into one bucket.

Evidence:
- Hook split commit: `3cb87f5a2` (`2021-11-22`) split TLS handshake events into client/server success/failure variants.
- Hook classes in code: `mitmproxy/proxy/layers/tls.py` defines `TlsStart*`, `TlsEstablished*`, and `TlsFailed*`.
- Multiple recurring TLS/cert fixes in history (`tlsconfig`, OpenSSL compatibility, certificate parsing, SAN/punycode fixes).

## 3) HTTP/2, HTTP/3, QUIC: Ship Incrementally with Kill Switches

Do:
- Treat HTTP/2 and HTTP/3 as independent maturity tracks.
- Add protocol-specific stress/fuzz tests before broad rollout.
- Keep feature flags and mode-level toggles for rapid rollback.

Do not:
- Assume parity across modes immediately, especially for HTTP/3/QUIC.
- Ship protocol modes without targeted soak tests and telemetry.

Evidence:
- QUIC/H3 had concentrated iteration waves and compatibility fixes (`2022` onward).
- `ff0155b1f` (`2023-06-27`) temporarily disabled broken HTTP/3 modes.
- Repeated HTTP/2 flow-control and frame behavior fixes (example: `8cf0cca70`, `cc6da7a81`, `c5402a490`).

## 4) Streaming Semantics and SSE

Do:
- Explicitly model streaming mode as a different event-ordering contract.
- Document that request/response hooks may reorder under streaming conditions.
- Add explicit SSE parser/behavior instead of relying on generic HTTP body handling.

Do not:
- Assume buffered-body behavior for streamed flows.
- Treat SSE as "just another text response."

Evidence:
- HTTP hook docs in `mitmproxy/proxy/layers/http/_hooks.py` note event ordering changes under streaming.
- SSE warning addon explicitly states SSE limitations without streaming:
  - `mitmproxy/addons/server_side_events.py`
  - commit `02d2b6d31` (`2022-04-06`).
- Repeated streaming fixes over many years (`2014`, `2017`, `2021`, `2022`, `2024`, `2025`).

## 5) WebSocket Correctness Is Mostly State/Ordering

Do:
- Reassemble fragmented frames before higher-level events.
- Track connection state transitions and close reasons explicitly.
- Test race conditions in broadcaster/subscriber paths.

Do not:
- Assume frame boundaries map to message boundaries.
- Ignore close/half-close edge behavior.

Evidence:
- WebSocket layer code reassembles frames and emits message-level hooks:
  - `mitmproxy/proxy/layers/websocket.py`
- Race fix example: `61b094ac3` (`2024-04-12`) "fix race in websocket broadcaster".

## 6) Parser Stack: Layered Decode Is Non-Optional

Do:
- Use deterministic decode pipeline ordering:
  - transfer/content decoding
  - protocol framing
  - payload parser
- Keep parser fallbacks and malformed-input handling explicit.
- Fuzz parser boundaries (frame lengths, split chunks, malformed encodings).

Do not:
- Couple decompression, framing, and semantic parsing in one opaque step.
- Fail closed on non-critical decode errors when pass-through is acceptable.

Evidence:
- gRPC/protobuf/msgpack contentview evolution and parser adjustments across releases.
- gRPC zstd handling fix: `ac3af2afd` (`2023-06-24`).
- Changelog `12.0.0` details replacement of gRPC/protobuf views and interactive msgpack/protobuf work.

## 7) Security Hardening Is Continuous, Not One-Time

Do:
- Centralize header validation and apply consistently across protocol versions.
- Keep secure defaults and make unsafe knobs explicit/auditable.
- Track parser and protocol CVEs in dependency policies.

Do not:
- Let version-specific validation rules drift.
- Leave ambiguous behavior around malformed headers/framing.

Evidence:
- Hardening commit `8fa4717fc` (`2024-11-24`) unified header validation across HTTP versions.
- Security-related fixes include h11 security bump and strict header handling.
- `validate_inbound_headers` option in `mitmproxy/addons/proxyserver.py` indicates explicit anti-smuggling posture.

## 8) Dependency and Release Hygiene Is Core Engineering Work

Do:
- Pin dependency ranges with explicit upper bounds and regular bump cadence.
- Keep protocol libraries (h2, quic, tls libs) under close compatibility testing.
- Maintain CI that catches ecosystem breaks early.

Do not:
- Assume transitive dependency drift is harmless for a proxy stack.
- Delay compatibility updates for crypto/protocol libraries.

Evidence:
- `pyproject.toml` shows strict range management for key protocol/security packages.
- High volume of dependency update commits (`Bump...`, requirement updates).

## Implications for `soth-mitm`

Do now:
- Build with explicit layer boundaries and deterministic event contracts.
- Keep TLS attribution metadata (`provider`, `source_confidence`) in all TLS failure events.
- Make protocol toggles first-class (`http2`, `http3_passthrough`, streaming controls).
- Implement parser subsystem as pluggable layered decoders (gRPC framing, SSE framing, anti-hijack sanitization) and keep semantic payload parsing in `soth-detect`.
- Add fuzz/property tests early for CONNECT/TLS/HTTP2/gRPC framing/SSE parsing.

Avoid now:
- Big-bang protocol enablement without staged rollout and shadow metrics.
- Using inferred TLS failures as source-of-truth for automated learning.
- Shipping SSE/gRPC handling without parser-level tests for chunk boundaries and malformed frames.

## Selected Reference Commits

- `d159897d9` - nuke legacy protocol stack
- `3cb87f5a2` - split TLS handshake hook into client/server success/fail
- `8cf0cca70` - HTTP/2 large-data slowdown fix
- `ff0155b1f` - temporarily disable broken HTTP/3 modes
- `61b094ac3` - websocket broadcaster race fix
- `8fa4717fc` - hardening: unify header validation across HTTP versions
- `02d2b6d31` - SSE warning behavior when not streaming
- `ac3af2afd` - gRPC zstd decompression support

---

## Source: `PROXY_TESTING_AND_HARDENING_PLAN.md`

# `soth-mitm` Proxy Testing and Hardening Plan

## 1) Objective

Define and execute a complete validation and hardening strategy for `soth-mitm` so that:

1. protocol behavior is correct (`HTTP/1.1`, `HTTP/2`, `HTTP/3 passthrough`, `WebSocket`, `SSE`, `gRPC`)
2. parser behavior is safe (`gRPC framing`, `SSE`, `anti-hijack`, layered decoders)
3. TLS diagnostics are trustworthy and actionable
4. rollout from hudsucker to `soth-mitm` is measurable and reversible

## 2) Key Constraints and Design Inputs

1. Rust-native implementation is required. Python components are only for reference and differential testing.
2. Hudsucker is not sufficient for required protocol coverage:
   - no WebSocket turn aggregator
   - no SSE
   - no complete `HTTP/2`, `HTTP/3`, and `gRPC` coverage target for this project
3. Hudsucker exposes `should_intercept` for CONNECT decisions but does not expose direct client-TLS-failure callbacks equivalent to mitmproxy `tls_failed_client`.
4. TLS operations source priority:
   - authoritative: mitmproxy callback surface for TLS learning and taxonomy validation
   - accepted: native `soth-mitm` path once parity is demonstrated
   - inferred only: hudsucker fallback path

## 3) Coverage Targets

## 3.1 Protocol Matrix

| Protocol / Mode | Test Depth | Minimum Pass Criteria |
| --- | --- | --- |
| CONNECT (intercept, tunnel, block) | unit + integration + failure injection | deterministic decisions, no bypass leaks |
| HTTP/1.1 | unit + integration + load | no parse corruption, stable event ordering |
| HTTP/2 | conformance + integration + load | `h2spec` pass target met, no stream leaks |
| HTTP/3 passthrough | integration + chaos | always tunneled, never decrypted |
| WebSocket | integration + fragmentation + race | frame integrity + turn boundaries correct |
| SSE | incremental parser + long-lived stream | no full-buffering, correct event flush semantics |
| gRPC over HTTP/2 | framing parser + unary + streaming | envelope boundaries and trailers correct |
| Opaque binary payload handoff | parser-boundary tests | proxy keeps transport-only behavior and never applies semantic payload decoding |
| Anti-hijack payloads | parser + sanitizer tests | prefixes sanitized with provenance flags |
| Layered decoders | unit + property tests | fixed decode order and stable failure semantics |

## 3.2 TLS Matrix

| TLS Scenario | Expected Outcome |
| --- | --- |
| trusted chain | `tls_handshake_succeeded` |
| unknown CA | classified failure: `unknown_ca` |
| expired / not yet valid | cert validation failure |
| hostname mismatch | cert validation failure |
| handshake alert | handshake failure |
| timeout | timeout failure |
| EOF / reset mid-handshake | eof/reset failure |
| ALPN mismatch / unsupported | classified protocol/TLS failure |

All TLS failures must include:

1. `tls_failure_source` (`mitmproxy_authoritative`, `native_authoritative`, `hudsucker_inferred`)
2. `tls_ops_provider` (`mitmproxy`, `soth-mitm`, `hudsucker`)
3. taxonomy reason
4. flow and host identity metadata

## 4) Tooling Plan

## 4.1 Required Toolchain

| Tool | Role | Required | Notes |
| --- | --- | --- | --- |
| `cargo test` | unit/integration baseline | yes | every PR |
| `cargo nextest` | parallel deterministic runner | yes | CI speed + stability |
| `proptest` | property tests for parsers/state machines | yes | parser invariants |
| `cargo-fuzz` (`libFuzzer`) | fuzz harnesses | yes | nightly + corpus growth |
| `criterion` | microbench regressions | yes | parser and hot path profiling |
| `tracing` + metrics exporters | observability assertions | yes | required for CI artifact diff |

## 4.2 Protocol and Interop Tools

| Tool | Role | Required | Test Scope |
| --- | --- | --- | --- |
| `curl` (`--proxy`, `--http2`, `--http3`) | broad HTTP interop smoke | yes | H1/H2/H3 passthrough |
| `h2spec` | HTTP/2 conformance | yes | frame/protocol rules |
| `h2load` | HTTP/2 load and multiplexing stress | yes | stream pressure |
| `websocat` | WebSocket functional tests | yes | upgrades and message exchange |
| `Autobahn Test Suite` | WebSocket protocol compliance | yes | fragmentation/close edge cases |
| `grpcurl` | gRPC functional tests | yes | unary/headers/trailers |
| `ghz` | gRPC load tests | yes | streaming and throughput stress |
| `openssl s_client` | TLS manual diagnostics | yes | cert and handshake sanity |
| `testssl.sh` | TLS config/cipher checks | yes | hardening baseline |
| `badssl.com` endpoints | TLS edge-case fixtures | yes | cert failure taxonomy |
| `wrk` | HTTP throughput perf | yes | sustained load |
| `hey` | request burst perf | yes | quick perf checks |
| `k6` or `vegeta` | scripted scenario load | optional | staged soak testing |
| `toxiproxy` | network failure injection | yes | timeout/reset/latency |
| `tc netem` | packet-level chaos | yes | jitter/loss/reorder |

## 4.3 Mitmproxy Reference Lanes

The following are included for differential testing against mitmproxy behavior:

| Tool | Role | Required | Notes |
| --- | --- | --- | --- |
| `uv run tox` | run mitmproxy test environments | optional | reference lane only |
| `uv run pytest` | focused mitmproxy fixtures | optional | reference lane only |
| `hypothesis` | fuzz/property style in mitmproxy tests | optional | use for corpus seeding |

Historical note:

1. `pathod/pathoc` were useful historically but are deprecated/removed in modern mitmproxy and are not part of this plan.

## 5) Test Harness Architecture

## 5.1 Local Lab Topology

1. Proxy under test: `soth-mitm`
2. Upstream fixture services:
   - HTTP/1.1 echo
   - HTTP/2 service with streaming endpoints
   - HTTP/3 endpoint (passthrough verification)
   - WebSocket echo and fragmented-frame server
   - SSE server with long-lived streams and retry/id semantics
   - gRPC server for unary + client-stream + server-stream + bidi-stream
3. Certificate lab:
   - valid CA
   - unknown CA
   - expired cert
   - hostname mismatch
   - malformed chain fixtures
4. Fault layer:
   - `toxiproxy` for deterministic faults
   - `tc netem` for packet impairments
5. Telemetry sink:
   - event stream capture (JSONL)
   - metrics and traces
   - memory and fd stats snapshots

## 5.2 Differential Harness

Replay identical traffic through:

1. `soth-mitm`
2. mitmproxy reference path
3. hudsucker fallback (only for supported modes)

Compare:

1. decision parity (`intercept`/`tunnel`/`block`)
2. event ordering and cardinality
3. TLS taxonomy and source-confidence metadata

## 6) Detailed Test Suites

## 6.1 Unit and Parser Suites

### CONNECT parser

1. valid host:port
2. IPv6 and bracket forms
3. invalid/malformed request lines
4. strict vs lenient mode behavior
5. overflow and large token boundaries

### TLS taxonomy classifier

1. reason mapping completeness
2. source-confidence tagging
3. classification determinism under repeated failures

### gRPC framing parser

1. 5-byte envelope parsing
2. chunk split across all byte boundaries
3. compressed-flag handling
4. declared-length mismatch
5. oversized message limits
6. malformed frame resilience

### SSE parser

1. `event`, `id`, `retry`, `data` fields
2. multi-line `data` join semantics
3. CRLF and LF line ending variants
4. partial line chunks
5. stream-close flush behavior
6. long-event memory bounds

### Anti-hijack sanitizer

1. known anti-hijack prefixes stripped when configured
2. no false stripping for normal payloads
3. provenance flag emitted (`sanitized=true/false`)

### Semantic payload boundary guard

1. transport normalization applies without semantic payload parsing
2. opaque binary payloads pass through without format-specific decoding
3. no msgpack-specific attributes or parser outcomes emitted by proxy core
4. no panic on adversarial binary input

### Layered decoder pipeline

1. fixed ordering (`transfer/content decode -> frame parse -> payload parse`)
2. stage-level error reporting
3. no stage skipping under partial chunks
4. idempotence and deterministic output

## 6.2 Integration Suites

1. CONNECT decision path:
   - `intercept` opens MITM path
   - `tunnel` bypasses MITM path entirely
   - `block` never opens upstream socket
2. HTTP/1.1 full lifecycle event ordering
3. HTTP/2 stream lifecycle and multiplexing correctness
4. WebSocket upgrades, fragmentation, close handshake, and injected messages
5. WebSocket turn aggregator:
   - client-initiated turns
   - server-initiated turns
   - flush on idle timeout
   - flush on close/error
6. SSE long-lived stream behavior (hours-scale simulated)
7. gRPC unary and streaming parity with expected headers/trailers
8. HTTP/3 passthrough:
   - protocol detected
   - no decryption attempted
   - tunnel telemetry emitted

## 6.3 Security Hardening Suites

1. header smuggling (`CL/TE`, duplicate/ambiguous headers)
2. invalid chunked framing and transfer-encoding edge cases
3. compression bomb controls (`gzip`, `br`, `deflate`)
4. websocket frame flood and fragment flood controls
5. gRPC length bomb and SSE oversized-event controls
6. strict parsing with safe fallback where required
7. cert handling hardening and invalid-chain behaviors
8. policy bypass attempts across host/path matcher boundaries
9. event schema validation on malformed upstream traffic

## 6.4 Failure Injection and Chaos

With `toxiproxy` and `tc netem`:

1. latency spikes
2. packet loss
3. packet reorder
4. abrupt reset during headers
5. reset during body stream
6. upstream timeout
7. DNS failure simulations
8. proxy process restarts with in-flight streams
9. charter chaos corpus:
   - TLS fragmenting (`tls_fragmented_client_hello_emits_failed_handshake_close`)
   - malformed HPACK (`malformed_hpack_payload_emits_http2_error_close`)
   - gRPC split frames (`grpc_http2_mitm` split-frame coverage)
   - infinite SSE stream budget enforcement (`infinite_sse_stream_hits_decoder_budget_and_closes_deterministically`)
   - jitter/loss tunnel behavior (`jitter_and_loss_in_tunnel_path_emit_relay_error_close`)

Expected:

1. no panic
2. bounded retry behavior
3. deterministic `stream_closed` reason codes
4. stable memory after fault storms

Execution lane:

1. `./scripts/p4_chaos_adversarial.sh` (CI job `phase4_chaos_adversarial`)

## 6.5 Performance and Soak

1. throughput tests (`wrk`, `hey`, `h2load`, `ghz`)
2. long-lived streams (WS/SSE/gRPC bidi) for leak detection
3. connection churn (short-lived bursts)
4. large header and metadata stress
5. memory and fd plateau assertions
6. CPU profile snapshots on hot paths

## 7) CI and Release Gates

## 7.1 PR Fast Lane (required for merge)

1. `cargo fmt --check`
2. `cargo clippy -- -D warnings`
3. `cargo test` / `cargo nextest` for unit + core integration
4. parser property tests (`proptest`)
5. smoke interop (`curl`, basic `grpcurl`, basic `websocat`)

## 7.2 Nightly Deep Lane

1. `cargo-fuzz` time-boxed fuzz runs
2. `h2spec` full conformance lane
3. extended gRPC streaming and SSE matrix
4. TLS matrix against local cert lab + `badssl.com`
5. load tests (`wrk`, `h2load`, `ghz`)
6. differential lane vs mitmproxy (selected corpus)

## 7.3 Weekly Chaos Lane

1. `toxiproxy` full fault matrix
2. `tc netem` perturbation profiles
3. 6-12h soak with mixed protocol traffic
4. memory and fd leak checks

## 7.4 Release Candidate Gate

Release is blocked unless all are true:

1. zero panic/crash in PR, nightly, and weekly lanes
2. TLS taxonomy accuracy target met (`>= 95%` against fixture corpus)
3. parser fuzz regressions are zero at RC commit
4. performance regressions are within accepted budget
5. differential drift vs mitmproxy is reviewed and accepted
6. hudsucker-inferred TLS events are excluded from automated learning

## 8) Metrics and SLO-style Quality Targets

1. Event ordering correctness: `100%` in deterministic fixture replay
2. Parser safety: `0` panics in fuzz and property tests
3. TLS classification correctness: `>= 95%` fixture agreement
4. WS turn aggregation correctness: `100%` expected-turn match in fixture matrix
5. Memory growth under 6h soak: bounded plateau (target threshold documented per environment)
6. Connection/file descriptor leaks: `0` net growth after steady-state cleanup window

## 9) Execution Backlog (Testing and Hardening Work Items)

| ID | Work Item | Deliverable | Exit Criteria |
| --- | --- | --- | --- |
| TH-01 | Fixture lab bootstrap | docker-compose or local harness | all fixture services reachable through proxy |
| TH-02 | CONNECT parser suite | unit + golden tests | 100% pass for valid/invalid corpus |
| TH-03 | TLS classifier suite | fixture corpus and assertions | taxonomy matches expected outcomes |
| TH-04 | WS turn aggregator suite | integration scenarios | expected turn boundaries match |
| TH-05 | SSE parser suite | incremental-state tests | multi-line and partial-chunk semantics validated |
| TH-06 | gRPC framing suite | parser + stream tests | envelope boundary correctness validated |
| TH-07 | anti-hijack suite | sanitizer tests | sanitize flag + output verified |
| TH-08 | semantic payload boundary suite | transport-vs-semantic boundary tests | no detect-owned payload parser behavior in proxy core |
| TH-09 | layered decoder suite | ordering tests | stage order invariant enforced |
| TH-10 | HTTP/2 conformance lane | `h2spec` job | pass threshold accepted |
| TH-11 | HTTP/2 load lane | `h2load` scenarios | no uncontrolled memory growth |
| TH-12 | HTTP/3 passthrough suite | integration tests | always tunnel-only, no decrypt |
| TH-13 | gRPC functional lane | `grpcurl` scripts | unary + streaming green |
| TH-14 | gRPC load lane | `ghz` runs | load budget and stability met |
| TH-15 | WS compliance lane | `websocat` + Autobahn | compliance profile accepted |
| TH-16 | TLS hardening lane | `openssl`, `testssl.sh`, `badssl` | expected classifications and policy behavior |
| TH-17 | chaos lane | `toxiproxy` + `tc netem` | no panic + deterministic close reasons |
| TH-18 | perf baseline lane | `wrk` + `hey` + metrics | baseline numbers committed and tracked |
| TH-19 | fuzz lane | `cargo-fuzz` targets | no known crashes, corpus persisted |
| TH-20 | property lane | `proptest` parsers/state | invariants hold across generated inputs |
| TH-21 | differential lane | compare with mitmproxy | drift report generated per nightly run |
| TH-22 | hudsucker fallback guard tests | inference suppression tests | inferred TLS does not update learning state |
| TH-23 | CI artifacts and triage docs | saved logs/traces/corpus | actionable artifact package on failure |
| TH-24 | RC gate automation | release checklist script | all gate checks pass before tag |
| TH-25 | post-cutover regression lane | production-like canary replay | no high-severity regressions detected |

## 9.1 Source-Backed Implementation Notes (TH-01..TH-25)

| ID | Source-backed implementation note | Primary references |
| --- | --- | --- |
| TH-01 | Build fixture lab with independent H1/H2/H3, WS, SSE, and gRPC upstream services plus cert-failure fixtures so protocol behavior can be isolated and replayed deterministically. | [Hyper](https://github.com/hyperium/hyper), [h2](https://github.com/hyperium/h2), [Quinn](https://github.com/quinn-rs/quinn), [h3](https://github.com/hyperium/h3), [mitmproxy cert concepts](https://docs.mitmproxy.org/stable/concepts/certificates/) |
| TH-02 | CONNECT parser must enforce RFC authority-form host:port semantics and reject ambiguous/invalid forms in strict mode. | [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110), [MDN CONNECT](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/CONNECT) |
| TH-03 | TLS classifier should map raw handshake errors into stable taxonomy and tag each event with source confidence (`mitmproxy` authoritative vs inferred fallback). | [TLS 1.3 RFC 8446](https://www.rfc-editor.org/rfc/rfc8446), [rustls](https://github.com/rustls/rustls), `MITMPROXY_LESSONS_LEARNED_FOR_SOTH_MITM.md` |
| TH-04 | WS turn aggregation should be direction-aware and boundary-safe under fragmentation, ping/pong, and close-handshake transitions. | [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455), [websocat](https://github.com/vi/websocat), [Autobahn](https://github.com/crossbario/autobahn-testsuite) |
| TH-05 | SSE parser should run incrementally and preserve `event/id/retry/data` semantics without full-body buffering, including partial-line chunk boundaries. | [MDN SSE](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events) |
| TH-06 | gRPC framing tests must validate 5-byte envelope handling across chunk splits and malformed-length conditions for unary and streaming flows. | [gRPC over HTTP/2 protocol](https://grpc.github.io/grpc/core/md_doc__p_r_o_t_o_c_o_l-_h_t_t_p2.html), [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113) |
| TH-07 | Anti-hijack stage should strip configured JSON guard prefixes with explicit provenance metadata and no false positives on clean payloads. | [OWASP JSON Hijacking](https://owasp.org/www-community/attacks/JSON_Hijacking) |
| TH-08 | Proxy must remain transport-only for payload semantics: gRPC/SSE framing and anti-hijack sanitization are allowed, but semantic payload decoding belongs to `soth-detect`. | `../soth/soth-detect-definitive.md` |
| TH-09 | Layered decoder invariants should enforce deterministic order: transfer/content decode before protocol framing and payload parsing. | [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112), [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) |
| TH-10 | Conformance lane should execute `h2spec` scenarios and track accepted exceptions explicitly instead of silently ignoring failures. | [h2spec](https://github.com/summerwind/h2spec), [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113) |
| TH-11 | H2 load lane should stress multiplexing/flow-control with stream-count and header-size ramps and validate memory stability. | [h2load docs](https://nghttp2.org/documentation/h2load-howto.html), [nghttp2](https://github.com/nghttp2/nghttp2) |
| TH-12 | HTTP/3 suite should prove passthrough-only behavior (no decryption) while preserving policy and telemetry correctness. | [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114), [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000), [RFC 9298](https://www.rfc-editor.org/rfc/rfc9298) |
| TH-13 | Functional gRPC lane should use repeatable scripted calls to validate metadata, trailers, status mapping, and parser outputs. | [grpcurl](https://github.com/fullstorydev/grpcurl), [gRPC over HTTP/2 protocol](https://grpc.github.io/grpc/core/md_doc__p_r_o_t_o_c_o_l-_h_t_t_p2.html) |
| TH-14 | gRPC load lane should include unary and streaming pressure runs to surface parser/backpressure regressions early. | [ghz](https://github.com/bojand/ghz) |
| TH-15 | WS compliance lane should combine simple functional probes with protocol compliance scenarios for fragmentation and close edge cases. | [websocat](https://github.com/vi/websocat), [Autobahn](https://github.com/crossbario/autobahn-testsuite), [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455) |
| TH-16 | TLS hardening lane should verify cipher/protocol posture and cert-failure taxonomy against both synthetic and public edge-case endpoints. | [OpenSSL s_client](https://www.openssl.org/docs/manmaster/man1/openssl-s_client.html), [testssl.sh](https://github.com/drwetter/testssl.sh), [badssl.com](https://badssl.com), [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) |
| TH-17 | Chaos lane should inject latency/loss/reorder/reset faults and assert deterministic close reasons with zero panic behavior. | [toxiproxy](https://github.com/Shopify/toxiproxy), [tc netem](https://man7.org/linux/man-pages/man8/tc-netem.8.html) |
| TH-18 | Perf baseline lane should include both max-throughput and fixed-QPS modes and report p50/p99/p999 plus resource counters. | [wrk](https://github.com/wg/wrk), [wrk2](https://github.com/giltene/wrk2), [fortio](https://github.com/fortio/fortio), [h2load](https://nghttp2.org/documentation/h2load-howto.html) |
| TH-19 | Fuzz lane should maintain persistent corpora and crash minimization artifacts for parser/state-machine targets. | [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) |
| TH-20 | Property lane should encode invariants for parsers and lifecycle state transitions to catch logic drift beyond fixture coverage. | [proptest](https://github.com/proptest-rs/proptest) |
| TH-21 | Differential lane should replay the same corpus through `soth-mitm` and mitmproxy and emit structured drift reports. | [mitmproxy](https://github.com/mitmproxy/mitmproxy), [mitmproxy docs](https://docs.mitmproxy.org/stable/) |
| TH-22 | Fallback guard tests should enforce that hudsucker-inferred TLS failures never feed automated learning state. | [hudsucker](https://github.com/omjadas/hudsucker), `MITMPROXY_LESSONS_LEARNED_FOR_SOTH_MITM.md` |
| TH-23 | CI artifact policy should preserve logs/traces/corpus snapshots for fast triage and reproducible debugging. | [GitHub Actions artifacts](https://docs.github.com/en/actions/using-workflows/storing-workflow-data-as-artifacts), [tracing](https://github.com/tokio-rs/tracing) |
| TH-24 | RC automation should hard-block releases on red gates (taxonomy accuracy, fuzz regressions, perf budget breaches, differential drift). | `RUST_SOTH_MITM_IMPLEMENTATION_CHECKLIST.md`, `PROXY_TESTING_AND_HARDENING_PLAN.md` |
| TH-25 | Post-cutover lane should replay canary-like traffic to detect semantic/perf regressions before defaulting cohorts. | [fortio](https://github.com/fortio/fortio), [wrk](https://github.com/wg/wrk), `LIGHTWEIGHT_PROXY_REPO_IMPLEMENTATION_PLAN.md` |

## 10) Documentation and Runbooks

Required docs to maintain with this plan:

1. `docs/testing/fixture-lab.md`
2. `docs/testing/protocol-matrix.md`
3. `docs/testing/tls-taxonomy.md`
4. `docs/testing/failure-injection.md`
5. `docs/testing/perf-baselines.md`
6. `docs/testing/differential-vs-mitmproxy.md`
7. `docs/testing/ci-gates.md`
8. `docs/testing/reliability-invariants.md`
9. `docs/testing/flow-fsm-transition-table.md`

## 11) Definition of Done for This Plan

This plan is considered implemented when:

1. TH-01 through TH-25 are complete
2. all required CI lanes are active
3. release gate blocks are enforced in automation
4. `soth-mitm` can run shadow and cutover cohorts with measurable confidence
5. TLS learning consumes only authoritative signals

---

## Source: `RUST_SOTH_MITM_IMPLEMENTATION_CHECKLIST.md`

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
- [x] `P2-11` Detect-boundary payload cleanup.
  - [x] Scope: keep proxy payload handling transport-only; remove detect-owned semantic payload decoding from proxy core.
  - [x] Deliverables: remove msgpack decode surface and align protocol/fuzz lanes with transport-only ownership.
  - [x] Acceptance: no msgpack parser surface remains in `soth-mitm` protocol gates or exported APIs.
- [x] `P2-12` Phase-2 protocol test gate.
  - [x] Scope: protocol matrix CI for HTTP/2, WS, SSE, HTTP/3 passthrough, gRPC.
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
  - [x] Scope: enforce `http2`, `websocket`, `sse`, `http3_passthrough`, `grpc_http2`.
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
  - [x] Complete `P2-11` detect-boundary payload cleanup (remove proxy msgpack semantic decoding).
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
- [x] `P5-08` Compatibility override layer.
  - [x] Scope: controlled per-host policy overrides (`force_tunnel`, `disable_h2`, strict header mode, sanctioned TLS overrides).
    - [x] per-host override schema added in `mitm-core` (`CompatibilityOverrideConfig`) with strict validation for `rule_id`, `host_pattern`, and no-op override rejection.
    - [x] connect decision path now applies compatibility overrides after base policy evaluation and before action dispatch.
  - [x] Deliverables: override schema + rule provenance/audit fields in emitted events.
    - [x] `connect_decision` events now emit deterministic audit fields: `action`, `override_rule_id`, `override_host_pattern`, `override_force_tunnel`, `override_disable_h2`, `override_strict_header_mode`, `override_skip_upstream_verify`.
    - [x] sidecar intercept path now enforces per-flow overrides for `disable_h2` and `skip_upstream_verify` without global config mutation.
    - [x] lane added: `scripts/p5_compat_override_layer.sh` + `testing/lanes/registry.tsv`.
  - [x] Acceptance: targeted problematic hosts recover without global behavior regressions.
    - [x] `cargo test -p mitm-core --lib compatibility_override_decision_emits_provenance_fields -q` passes.
    - [x] `cargo test -p mitm-sidecar --test http2_mitm host_override_disable_h2_forces_http1_without_global_toggle -q` passes.
    - [x] `cargo test -p mitm-sidecar --test tls_profile_matrix host_override_skip_upstream_verify_allows_self_signed_upstream -q` passes.
- [x] `P5-09` Cross-platform socket/net hardening.
  - [x] Scope: IPv6, Windows socket lifecycle, and FD/concurrency pressure robustness.
    - [x] listener binding moved to hardened `TcpSocket` path with resolution-backed address selection and IPv6 dual-stack attempt (`set_only_v6(false)` best-effort).
    - [x] connection-level socket hardening applied on accept/connect (`TCP_NODELAY`) and benign close-path error classification added for deterministic lifecycle noise suppression.
  - [x] Deliverables: platform-specific socket guards + matrix tests + pressure instrumentation.
    - [x] socket hardening module added (`crates/mitm-sidecar/src/socket_hardening.rs`) with lifecycle guard tests.
    - [x] IPv6/dual-stack integration coverage added (`crates/mitm-sidecar/tests/socket_hardening.rs`).
    - [x] lane added: `scripts/p5_socket_net_hardening.sh` + `testing/lanes/registry.tsv`; pressure instrumentation coverage carried via `runtime_governor` contract lane.
  - [x] Acceptance: Linux/macOS/Windows matrix passes lifecycle and stress gates with deterministic close semantics.
    - [x] `cargo test -p mitm-sidecar --test socket_hardening -q` passes.
    - [x] `cargo test -p mitm-sidecar --test route_mode_matrix upstream_socks5_mode_honors_ignore_host_and_relays_tunnel -q` passes.
    - [x] `cargo test -p mitm-sidecar --test runtime_governor -q` passes.
- [x] `P5-10` Control-plane boundary guards (conditional surface).
  - [x] Scope: only if management/control endpoints are exposed.
    - [x] current product surface has no management/control listener; boundary guard is enforced as an explicit negative-surface contract.
  - [x] Deliverables: anti-rebinding defaults + host/origin allowlists + boundary tests.
    - [x] conditional guard lane added: `scripts/p5_control_plane_boundary.sh` + `testing/lanes/registry.tsv` to fail on introduction of unmanaged control-plane tokens/surfaces.
  - [x] Acceptance: control-plane endpoints are non-bypassable by default.
    - [x] with zero exposed control endpoints, bypass surface is structurally absent and lane-enforced.

## 13) Phase 7: Local Capture and Transparent Mode

- [ ] Scope constraints (explicit):
  - [x] Mobile interception/pinning bypass is out of scope for `soth-mitm` core.
  - [x] WireGuard capture mode is deferred unless explicitly approved in a separate phase.
  - [x] FreeBSD transparent-mode support is out of scope for this phase.
- [ ] `P7-01` Local-capture architecture contract and invariants.
  - [ ] Mitigates: `#2597`, `#6531`
  - [ ] Scope: define supported capture modes, OS backends, and deterministic failure classes.
  - [ ] Deliverables:
    - [ ] `docs/testing/local-capture-architecture.md`
    - [ ] `docs/testing/local-capture-failure-taxonomy.md`
  - [ ] Acceptance: unsupported environment paths fail fast with explicit actionable reasons.
- [ ] `P7-02` Original-destination resolution abstraction.
  - [ ] Mitigates: `#2597`
  - [ ] Scope: per-OS original-destination resolver with strict normalization and telemetry.
  - [ ] Deliverables:
    - [ ] `crates/mitm-sidecar/src/local_capture/original_dst.rs`
    - [ ] `crates/mitm-sidecar/tests/local_capture_original_dst.rs`
  - [ ] Acceptance: resolved destination parity against fixture corpus with deterministic fallback behavior.
- [ ] `P7-03` Local-capture preflight and dependency checks.
  - [ ] Mitigates: `#4063`
  - [ ] Scope: startup preflight for required OS capabilities/files/permissions.
  - [ ] Deliverables:
    - [ ] `crates/mitm-sidecar/src/local_capture/preflight.rs`
    - [ ] `scripts/p7_local_capture_preflight.sh`
  - [ ] Acceptance: missing prerequisites produce non-zero startup with stable error codes/messages.
- [ ] `P7-04` Route-change and VPN drift resilience.
  - [ ] Mitigates: `#2528`
  - [ ] Scope: detect route-table drift, rebind capture plumbing safely, preserve in-flight correctness.
  - [ ] Deliverables:
    - [ ] `crates/mitm-sidecar/src/local_capture/route_watcher.rs`
    - [ ] `crates/mitm-sidecar/tests/local_capture_route_drift.rs`
  - [ ] Acceptance: route churn and VPN toggles do not deadlock capture path or corrupt flow decisions.
- [ ] `P7-05` Host self-traffic capture with loop guards.
  - [ ] Mitigates: `#1261`
  - [ ] Scope: optional self-traffic interception mode with explicit loop prevention and bypass exemptions.
  - [ ] Deliverables:
    - [ ] `crates/mitm-sidecar/src/local_capture/self_traffic.rs`
    - [ ] `crates/mitm-sidecar/tests/local_capture_self_traffic.rs`
  - [ ] Acceptance: host-origin traffic is capturable when enabled and never forms capture loops.
- [ ] `P7-06` macOS redirector entitlement and signing checks.
  - [ ] Mitigates: `#7419`
  - [ ] Scope: deterministic validation of required entitlements/codesign state for macOS redirector path.
  - [ ] Deliverables:
    - [ ] `crates/mitm-sidecar/src/local_capture/macos_entitlements.rs`
    - [ ] `scripts/p7_macos_entitlement_check.sh`
  - [ ] Acceptance: macOS local-capture start is blocked with explicit diagnostics when entitlements are invalid.
- [ ] `P7-07` macOS transparent-mode reliability pack.
  - [ ] Mitigates: `#4835`
  - [ ] Scope: harden macOS redirect lifecycle, startup/shutdown idempotency, and flow continuity.
  - [ ] Deliverables:
    - [ ] `crates/mitm-sidecar/tests/local_capture_macos_reliability.rs`
    - [ ] `scripts/p7_macos_local_capture_soak.sh`
  - [ ] Acceptance: repeated start/stop and sustained capture runs complete without orphaned state.
- [ ] `P7-08` Local-capture protocol matrix lane.
  - [ ] Mitigates: `#6531`, `#2597`, `#2528`
  - [ ] Scope: run HTTP/1.1, HTTP/2, WebSocket, SSE, and passthrough traffic via local-capture entrypoint.
  - [ ] Deliverables:
    - [ ] `scripts/p7_local_capture_matrix.sh`
    - [ ] `testing/lanes/registry.tsv` lane registration
  - [ ] Acceptance: matrix is deterministic and blocks regressions in capture-mode routing semantics.
- [ ] `P7-09` Local-capture long-run hardening gate.
  - [ ] Mitigates: `#6531`, `#2528`, `#4835`
  - [ ] Scope: long-run soak with route churn plus deterministic close/resource invariants.
  - [ ] Deliverables:
    - [ ] `scripts/p7_local_capture_soak.sh`
    - [ ] `docs/testing/local-capture-runbook.md`
  - [ ] Acceptance: no unbounded RSS/queue growth and no stuck-flow accumulation under churned soak.
- [ ] `P7-10` Nice-to-have: bandwidth shaping hooks for test harness.
  - [ ] Mitigates: `#5208` (optional)
  - [ ] Scope: controlled latency/throughput shaping for reproducible degraded-network tests.
  - [ ] Deliverables:
    - [ ] `scripts/p7_network_shaping_harness.sh`
    - [ ] `docs/testing/network-shaping.md`
  - [ ] Acceptance: harness can inject deterministic bandwidth/latency limits without affecting proxy correctness.

### Phase 7 Priorities

1. `P7-01`..`P7-04`: critical path for usable local capture (`#2597`, `#6531`, `#4063`, `#2528`).
2. `P7-05`..`P7-07`: self-traffic and macOS reliability layers (`#1261`, `#7419`, `#4835`).
3. `P7-08`..`P7-09`: release-blocking validation and soak gates.
4. `P7-10`: nice-to-have test utility; non-blocking for core local-capture GA.

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

---

## Source: `docs/PROXY_PERFORMANCE_RESEARCH_NOTES.md`

# Rust High-Performance Intercepting Proxy: Notes and Saved References

This document captures key learnings from the provided research write-up and stores actionable references for `soth-mitm`.

## Key Learnings to Apply in `soth-mitm`

1. Treat the project as a platform, not only a proxy dataplane.
   - Need a protocol stack plus stable extensibility hooks, event model, and operational tooling.
2. Prefer a pragmatic core stack.
   - `tokio` + `hyper` + `rustls` for primary dataplane.
   - `h2` for direct HTTP/2 control where hyper abstraction is insufficient.
   - `quinn` + `h3` only as a later HTTP/3 interception module; start with passthrough first.
3. Separate protocol state from I/O where possible.
   - Sans-I/O style modules improve deterministic tests and fuzzability.
4. Keep streaming as default behavior.
   - Avoid whole-body buffering unless explicitly required by policy/parser stages.
5. Make backpressure and bounded memory non-negotiable.
   - Streaming transforms, per-flow limits, and explicit queue budgets are required for stability.
6. TLS interception must be policy-driven and observable.
   - Track SNI/ALPN, cert synthesis/cache efficiency, handshake classification, and source confidence.
   - Session resumption should be optimized; 0-RTT should remain opt-in and policy constrained.
7. HTTP/3 should be phased.
   - Phase 1: telemetry + passthrough.
   - Phase 2: decode/interception after test/chaos/perf maturity.
8. Benchmarking must be multi-lane and reproducible.
   - Tunnel-only vs full MITM vs MITM+parsers measured independently.
   - Focus on p99/p999 tails, not only max throughput.
9. Cross-platform concerns affect architecture early.
   - Linux/macOS/Windows eventing differences must remain hidden behind a clean runtime abstraction.
10. Migration from hudsucker should be compatibility-first.
   - Keep a handler-style API bridge while introducing richer platform controls.

## Architecture Guidance (Concrete)

1. Listener tier:
   - TCP listener for HTTP/1.1 + CONNECT.
   - Optional UDP listener for future HTTP/3/QUIC module.
2. Core flow engine:
   - deterministic event lifecycle
   - tunnel path
   - MITM TLS path
   - protocol parser path
3. Protocol layer:
   - H1/H2 + WebSocket + SSE + gRPC framing + transport sanitizers (anti-hijack)
4. Upstream connector pool:
   - key by scheme/host/port/ALPN
   - strict budgets and circuit-breaker style controls
5. Observability:
   - tracing spans, metrics, structured flow/event logs
6. Extensibility:
   - stable hook model with backpressure-safe APIs
   - avoid plugin API designs that force eager buffering

## Saved Reference Index

## Rust proxy projects

1. Hudsucker: https://github.com/omjadas/hudsucker
2. mitmproxy: https://github.com/mitmproxy/mitmproxy
3. mitmproxy_rs: https://github.com/mitmproxy/mitmproxy_rs
4. Pingora: https://github.com/cloudflare/pingora
5. Sozu: https://github.com/sozu-proxy/sozu
6. Linkerd2 proxy: https://github.com/linkerd/linkerd2-proxy

## Core runtime, protocol, TLS crates

1. Tokio: https://github.com/tokio-rs/tokio
2. Mio: https://github.com/tokio-rs/mio
3. smol: https://github.com/smol-rs/smol
4. async-std: https://github.com/async-rs/async-std
5. Hyper: https://github.com/hyperium/hyper
6. h2: https://github.com/hyperium/h2
7. rustls: https://github.com/rustls/rustls
8. hyper-rustls: https://github.com/rustls/hyper-rustls
9. Quinn: https://github.com/quinn-rs/quinn
10. h3: https://github.com/hyperium/h3

## Bench and load tools

1. wrk: https://github.com/wg/wrk
2. wrk2: https://github.com/giltene/wrk2
3. fortio: https://github.com/fortio/fortio
4. h2load (nghttp2 docs): https://nghttp2.org/documentation/h2load-howto.html
5. nghttp2 project: https://github.com/nghttp2/nghttp2
6. h2spec: https://github.com/summerwind/h2spec
7. grpcurl: https://github.com/fullstorydev/grpcurl
8. ghz: https://github.com/bojand/ghz
9. websocat: https://github.com/vi/websocat
10. Autobahn testsuite: https://github.com/crossbario/autobahn-testsuite
11. toxiproxy: https://github.com/Shopify/toxiproxy
12. tc netem manual: https://man7.org/linux/man-pages/man8/tc-netem.8.html
13. cargo-fuzz: https://github.com/rust-fuzz/cargo-fuzz
14. proptest: https://github.com/proptest-rs/proptest

## Proxy semantics and protocol standards

1. HTTP Semantics (RFC 9110): https://www.rfc-editor.org/rfc/rfc9110
2. HTTP/1.1 (RFC 9112): https://www.rfc-editor.org/rfc/rfc9112
3. HTTP/2 (RFC 9113): https://www.rfc-editor.org/rfc/rfc9113
4. HTTP/3 (RFC 9114): https://www.rfc-editor.org/rfc/rfc9114
5. QUIC Transport (RFC 9000): https://www.rfc-editor.org/rfc/rfc9000
6. QUIC TLS (RFC 9001): https://www.rfc-editor.org/rfc/rfc9001
7. QPACK (RFC 9204): https://www.rfc-editor.org/rfc/rfc9204
8. CONNECT-UDP (RFC 9298): https://www.rfc-editor.org/rfc/rfc9298
9. TLS 1.3 (RFC 8446): https://www.rfc-editor.org/rfc/rfc8446
10. WebSocket (RFC 6455): https://www.rfc-editor.org/rfc/rfc6455
11. SNI (RFC 6066): https://www.rfc-editor.org/rfc/rfc6066
12. ALPN (RFC 7301): https://www.rfc-editor.org/rfc/rfc7301

## Practical operational references

1. mitmproxy certificate concepts: https://docs.mitmproxy.org/stable/concepts/certificates/
2. mitmproxy getting started/tools overview: https://docs.mitmproxy.org/stable/
3. MDN CONNECT method: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/CONNECT
4. Android certificate pinning (Network Security Config): https://developer.android.com/privacy-and-security/security-config#CertificatePinning
5. OpenSSL `s_client` manual: https://www.openssl.org/docs/manmaster/man1/openssl-s_client.html
6. testssl.sh: https://github.com/drwetter/testssl.sh
7. badssl.com test endpoints: https://badssl.com
8. MDN Server-Sent Events: https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events
9. gRPC over HTTP/2 protocol details: https://grpc.github.io/grpc/core/md_doc__p_r_o_t_o_c_o_l-_h_t_t_p2.html
10. OWASP JSON Hijacking: https://owasp.org/www-community/attacks/JSON_Hijacking
11. GitHub Actions artifacts: https://docs.github.com/en/actions/using-workflows/storing-workflow-data-as-artifacts

## For `soth-mitm` implementation tracking

Use with:

1. `PROXY_TESTING_AND_HARDENING_PLAN.md`
2. `RUST_SOTH_MITM_IMPLEMENTATION_CHECKLIST.md`
3. `MITMPROXY_LESSONS_LEARNED_FOR_SOTH_MITM.md`

---

## Source: `docs/testing/protocol-matrix.md`

# Protocol Matrix

This document defines the Phase-2 protocol test gate matrix (`P2-12`/`P2-13`).

## Required Protocol Coverage

The gate is only valid when all required protocols are present:

1. `http2`
2. `websocket`
3. `sse`
4. `http3_passthrough`
5. `grpc_http2`

Coverage is asserted by `scripts/p2_protocol_triage.sh`.

## Matrix Source of Truth

- Matrix file: `scripts/p2_protocol_matrix.tsv`
- Lane runner: `scripts/p2_protocol_gate.sh`
- Full local matrix: `scripts/p2_protocol_matrix.sh`
- Triage summary: `scripts/p2_protocol_triage.sh`

## Lane Definitions

| Lane | Protocol | Command |
| --- | --- | --- |
| `http2` | `http2` | `cargo test -p mitm-sidecar --test http2_mitm` |
| `websocket` | `websocket` | `cargo test -p mitm-sidecar --test websocket_mitm` |
| `sse` | `sse` | `cargo test -p mitm-sidecar --test sse_mitm` |
| `http3_passthrough` | `http3_passthrough` | `cargo test -p mitm-sidecar --test http3_passthrough_mitm` |
| `grpc_http2` | `grpc_http2` | `cargo test -p mitm-sidecar --test grpc_http2_mitm` |

## Local Usage

Run all lanes with triage aggregation:

```bash
./scripts/p2_protocol_matrix.sh
```

Run one lane only:

```bash
./scripts/p2_protocol_gate.sh --lane grpc_http2 --report-dir artifacts/p2-protocol/grpc_http2
```

Generate triage output from existing lane artifacts:

```bash
./scripts/p2_protocol_triage.sh --input-root artifacts/p2-protocol --output-dir artifacts/p2-protocol/triage
```

---

## Source: `fuzz/README.md`

# Fuzz Targets

This directory contains focused fuzz targets for `soth-mitm` hardening:

- `connect_parser`: CONNECT parsing and malformed CONNECT head handling.
- `tls_classification`: TLS failure classification string parser.
- `http_header_parsing`: HTTP/1 request/response head parsing boundaries.
- `grpc_framing`: gRPC envelope parsing under chunk splits and length mismatches.
- `sse_parser`: SSE incremental parsing under partial lines/events.
- `decoder_layering_interactions`: layered decoder ordering and stage interaction invariants.

## Run

```bash
cargo fuzz run connect_parser
cargo fuzz run tls_classification
cargo fuzz run http_header_parsing
cargo fuzz run grpc_framing
cargo fuzz run sse_parser
cargo fuzz run decoder_layering_interactions
```

Run commands from `fuzz/`.

## Corpus Maintenance

From repository root:

```bash
./scripts/fuzz_corpus_maintenance.sh --runs 64
```

Artifacts are written to `artifacts/fuzz-corpus/` with per-target logs, corpus stats, and timestamped snapshots.
