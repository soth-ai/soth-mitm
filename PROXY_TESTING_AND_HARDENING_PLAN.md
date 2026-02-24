# `soth-mitm` Proxy Testing and Hardening Plan

## 1) Objective

Define and execute a complete validation and hardening strategy for `soth-mitm` so that:

1. protocol behavior is correct (`HTTP/1.1`, `HTTP/2`, `HTTP/3 passthrough`, `WebSocket`, `SSE`, `gRPC`)
2. parser behavior is safe (`gRPC framing`, `SSE`, `anti-hijack`, `msgpack`, layered decoders)
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
| MsgPack payloads | parser + malformed input tests | bounded decode, safe fallback |
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

### MsgPack parser

1. content-type and heuristic detection
2. max depth and max map/list size enforcement
3. malformed payload fallback to raw bytes
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
| TH-08 | msgpack suite | parser and limit tests | safe fail behavior under malformed input |
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
| TH-08 | MsgPack decode path must be bounded (depth/size limits) and fail safely back to raw bytes for malformed or oversized payloads. | [MessagePack spec](https://github.com/msgpack/msgpack/blob/master/spec.md) |
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
