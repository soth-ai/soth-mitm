# Fixture Lab

This runbook defines the local fixture harness used to validate protocol behavior through `soth-mitm`.

## Entry Point

Run the fixture matrix:

```bash
./scripts/fixture_lab_matrix.sh
```

Output artifacts:

- `artifacts/fixture-lab/status.tsv`
- `artifacts/fixture-lab/summary.md`
- `artifacts/fixture-lab/tls-fixtures/*`

## Fixture Coverage Map

| Fixture lane | Command | Coverage |
| --- | --- | --- |
| `connect_policy_and_lifecycle` | `cargo test -p mitm-sidecar --test phase_a` | CONNECT decision paths (`intercept`, `tunnel`, `block`) + lifecycle |
| `http1_fixture` | `cargo test -p mitm-sidecar --test http1_mitm intercept_get_over_tls_forwards_and_emits_http_events` | HTTP/1.1 MITM baseline |
| `http2_fixture` | `cargo test -p mitm-sidecar --test http2_mitm intercept_http2_over_tls_relays_and_marks_protocol` | HTTP/2 relay/telemetry |
| `websocket_fixture` | `cargo test -p mitm-sidecar --test websocket_mitm websocket_upgrade_relays_text_and_binary_frames_without_corruption` | WS upgrade/frame integrity |
| `sse_fixture` | `cargo test -p mitm-sidecar --test sse_mitm parses_sse_events_incrementally_and_flushes_tail_on_stream_close` | SSE incremental parsing |
| `grpc_fixture_parser` | `cargo test -p mitm-http --lib` | gRPC 5-byte envelope framing and malformed boundary handling |
| `http3_passthrough_fixture` | `cargo test -p mitm-sidecar --test http3_passthrough_mitm http3_hint_forces_tunnel_passthrough_and_emits_telemetry` | HTTP/3 passthrough (no decrypt) |
| `tls_fixture_matrix` | `./scripts/tls_failure_fixtures.sh` | TLS unknown-ca/timeout/reset/invalid-chain taxonomy |

## Notes

1. The harness is local-test based (no external dependency required for baseline fixture execution).
2. Network/socket restricted environments may require elevated execution for lanes that bind listeners.
3. Use this matrix as the `TH-01` fixture bootstrap gate before deep hardening or differential runs.
