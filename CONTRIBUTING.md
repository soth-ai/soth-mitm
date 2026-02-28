# Contributing to soth-mitm

Thanks for contributing.

## Prerequisites

- Rust toolchain from `rust-toolchain.toml`
- Docker (for tooling and lane execution)
- `cargo`, `git`, `bash`

## Local Setup

```bash
./scripts/install_git_hooks.sh
cargo check --workspace
cargo test --workspace
```

`install_git_hooks.sh` configures repository-managed hooks so pushes run `./scripts/check_max_file_lines.sh` and `./scripts/check_prohibitions.sh` locally before reaching CI.

## Required Checks Before PR

```bash
./scripts/check_max_file_lines.sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
./scripts/p6_acceptance_matrix.sh --report-dir artifacts/p6-acceptance-local
```

For full launch-gate validation:

```bash
./scripts/docker_run_testing.sh --profile stress --profile parity --profile benchmark --strict-tools
```

## Coding Rules

- Keep core Rust files under 500 lines (`crates/*/src/**/*.rs`).
- Prefer deterministic behavior over best-effort behavior.
- Add/adjust tests with every functional change.
- Do not add provider-specific detection logic into `soth-mitm`.

## Commit Guidance

- Use focused commits with clear scope.
- Commit message format should be imperative and subsystem-first when possible.
  - Example: `sidecar: bound h2 capture buffer growth`

## Pull Request Checklist

- Problem statement and scope are explicit.
- Tests added/updated and passing.
- No secrets or machine-specific paths introduced.
- Docs updated for any new flags, config fields, or behaviors.
