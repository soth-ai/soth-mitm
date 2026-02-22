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
- Implement parser subsystem as pluggable layered decoders (gRPC, SSE, msgpack, anti-hijack).
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
