# Protocol Matrix

This document defines the Phase-2 protocol test gate matrix (`P2-12`/`P2-13`).

## Required Protocol Coverage

The gate is only valid when all required protocols are present:

1. `http2`
2. `websocket`
3. `sse`
4. `http3_passthrough`
5. `grpc_http2`
6. `msgpack`

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
| `msgpack` | `msgpack` | `cargo test -p mitm-http --test msgpack` |

## Local Usage

Run all lanes with triage aggregation:

```bash
./scripts/p2_protocol_matrix.sh
```

Run one lane only:

```bash
./scripts/p2_protocol_gate.sh --lane msgpack --report-dir artifacts/p2-protocol/msgpack
```

Generate triage output from existing lane artifacts:

```bash
./scripts/p2_protocol_triage.sh --input-root artifacts/p2-protocol --output-dir artifacts/p2-protocol/triage
```
