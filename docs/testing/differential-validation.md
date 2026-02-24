# Differential Validation

Phase-4 differential validation compares deterministic behavior across engines while respecting protocol support boundaries.

## Lane Contract

1. `core_conformance`
   - shared fixture corpus event ordering and cardinality checks
   - command: `cargo test -p mitm-core --test conformance_golden`
2. `mitmproxy_tls_taxonomy`
   - TLS taxonomy parity with mitmproxy callback fixtures
   - command: `cargo test -p mitm-sidecar --test mitmproxy_tls_adapter`
3. `tls_learning_guardrails`
   - authoritative-source learning guard checks
   - command: `cargo test -p mitm-sidecar --test tls_learning_guardrails`
4. `hudsucker_supported_surface_scope`
   - validates hudsucker comparison lane scope is restricted to supported surface only
   - command: `./scripts/check_hudsucker_differential_scope.sh`
5. `replay_drift_report`
   - compares normalized per-case event traces (`soth-mitm` vs mitmproxy) and emits drift diffs
   - command: `./scripts/p4_differential_replay.sh --strict-input`

## Scope Rules

- `soth-mitm` vs mitmproxy comparisons cover full fixture corpus.
- hudsucker differential checks are limited to `docs/testing/hudsucker-differential-scope.tsv`.
- Unsupported hudsucker protocol surfaces (`SSE`, `HTTP/2`, `HTTP/3`, `gRPC`, WS turn aggregation) are explicitly excluded.

## Local Run

```bash
./scripts/p4_differential_validation.sh
```

Replay-only command:

```bash
./scripts/p4_differential_replay.sh --strict-input
```
