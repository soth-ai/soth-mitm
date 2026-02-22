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
   - H1/H2 + WebSocket + SSE + gRPC framing + payload parsers (msgpack, anti-hijack)
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
10. MessagePack spec: https://github.com/msgpack/msgpack/blob/master/spec.md
11. OWASP JSON Hijacking: https://owasp.org/www-community/attacks/JSON_Hijacking
12. GitHub Actions artifacts: https://docs.github.com/en/actions/using-workflows/storing-workflow-data-as-artifacts

## For `soth-mitm` implementation tracking

Use with:

1. `PROXY_TESTING_AND_HARDENING_PLAN.md`
2. `RUST_SOTH_MITM_IMPLEMENTATION_CHECKLIST.md`
3. `MITMPROXY_LESSONS_LEARNED_FOR_SOTH_MITM.md`
