# soth-mitm

Rust workspace for a lightweight MITM-capable proxy consumed by `soth`.

## Workspace crates

- `mitm-core`: transport loop and CONNECT/MITM decision pipeline
- `mitm-tls`: TLS/certificate lifecycle and failure classification primitives
- `mitm-http`: protocol enums and HTTP-related limits/config
- `mitm-policy`: policy engine for `intercept|tunnel|block` (`tunnel` is metadata-only passthrough mode)
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
./scripts/tls_failure_fixtures.sh
./scripts/p1_reliability.sh
./scripts/p2_protocol_matrix.sh
./scripts/p4_performance_gates.sh
./scripts/p4_failure_injection.sh
./scripts/p4_differential_validation.sh
./scripts/p4_chaos_adversarial.sh
./scripts/p4_chaos_network_faults.sh
./scripts/p4_tls_hardening.sh
./scripts/p4_tool_lanes.sh
./scripts/p4_hardening_plan.sh
./scripts/p5_event_log_contract.sh
./scripts/p5_runtime_soak.sh --duration-seconds 300
./scripts/collect_testing_artifacts.sh
```

## Docker Tooling Lab

Build the toolchain container:

```bash
./scripts/docker_build_tools.sh
```

Run hardening inside Docker (default: `--skip-network`):

```bash
./scripts/docker_run_hardening.sh
```

Run strict external-tool validation inside Docker:

```bash
./scripts/docker_run_hardening.sh --strict-tools
```

Run configurable stress/parity/benchmark/soak plans inside Docker:

```bash
./scripts/docker_run_testing.sh --profile stress
./scripts/docker_run_testing.sh --profile parity --profile benchmark --strict-tools
SOTH_MITM_SOAK_DURATION_SECONDS=300 ./scripts/docker_run_testing.sh --profile soak
./scripts/docker_run_testing.sh --lane phase4_differential_validation
./scripts/docker_run_testing.sh --config testing/test-plan.env
```

List available lanes:

```bash
./scripts/docker_run_testing.sh --list-lanes
```

Contributor lane registry and defaults:

- `testing/lanes/registry.tsv` (add new lane entries here)
- `testing/test-plan.env` (default run configuration)
- `scripts/run_testing_plan.sh` (config-driven lane runner)

Run fixture-lab matrix inside Docker:

```bash
./scripts/docker_run_fixture_lab.sh
```

Open an interactive shell inside the tools container:

```bash
./scripts/docker_shell.sh
```

## Policies

- MSRV and versioning policy: `docs/policies/versioning-and-msrv.md`
- Hardening plan execution: `docs/testing/hardening-plan.md`
- Differential validation contract: `docs/testing/differential-validation.md`
- Differential replay runbook: `docs/testing/differential-vs-mitmproxy.md`
- TLS taxonomy runbook: `docs/testing/tls-taxonomy.md`
- Failure injection runbook: `docs/testing/failure-injection.md`
- Performance baseline runbook: `docs/testing/perf-baselines.md`
- Event log v2 + automation contract: `docs/testing/event-log-v2-contract.md`
- Artifact triage runbook: `docs/testing/artifact-triage.md`
- Consumer adapter contract: `docs/consumer/soth-proxy-adapter-contract.md`
- Migration/cutover playbook: `docs/migration/soth-cutover.md`

## Repository Rules

- Max file length is `400` lines for core Rust source files under `crates/*/src/**/*.rs`.
- Oversized core Rust files must be split before merge.
- Guard command: `./scripts/check_max_file_lines.sh`
