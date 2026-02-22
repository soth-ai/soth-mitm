# soth-mitm

Rust workspace for a lightweight MITM-capable proxy consumed by `soth`.

## Workspace crates

- `mitm-core`: transport loop and CONNECT/MITM decision pipeline
- `mitm-tls`: TLS/certificate lifecycle and failure classification primitives
- `mitm-http`: protocol enums and HTTP-related limits/config
- `mitm-policy`: policy engine for `intercept|tunnel|block|metadata_only`
- `mitm-observe`: deterministic event model and sink traits
- `mitm-sidecar`: optional process wrapper entry point

## Quick start

```bash
cargo check --workspace
```

## Testing

```bash
cargo test --workspace
./scripts/phase_a_smoke.sh
```

## Repository Rules

- Max file length is `400` lines for core Rust source files under `crates/*/src/**/*.rs`.
- Oversized core Rust files must be split before merge.
- Guard command: `./scripts/check_max_file_lines.sh`
