# Hardening Plan Execution

`PROXY_TESTING_AND_HARDENING_PLAN.md` is the authoritative hardening plan for this repository.

Phase-2 protocol matrix (`./scripts/p2_protocol_matrix.sh`) is a prerequisite coverage gate and remains the canonical protocol surface gate.

Fixture bootstrap gate (`TH-01`):

```bash
./scripts/fixture_lab_matrix.sh
```

## Phase-4 Gate Entry Points

1. `./scripts/p4_performance_gates.sh`
2. `./scripts/p4_failure_injection.sh`
3. `./scripts/p4_differential_validation.sh`
4. `./scripts/p4_chaos_adversarial.sh`
5. `./scripts/p4_chaos_network_faults.sh`
6. `./scripts/p4_tool_lanes.sh`

Phase-5 runtime soak entry point:

```bash
./scripts/p5_runtime_soak.sh --duration-seconds 300
```

Phase-5 reliability contract entry point:

```bash
./scripts/p5_reliability_contract.sh
```

Phase-5 HTTP/1 smuggling guard gate entry point:

```bash
./scripts/p5_http1_smuggling_guard.sh
```

Phase-5 TLS profile matrix entry point:

```bash
./scripts/p5_tls_profile_matrix.sh
```

Phase-5 route mode matrix entry point:

```bash
./scripts/p5_route_mode_matrix.sh
```

Phase-5 HTTP/2 resilience entry point:

```bash
./scripts/p5_http2_resilience.sh
```

Phase-5 event log v2 + automation contract entry point:

```bash
./scripts/p5_event_log_contract.sh
```

Run all hardening gates in one pass:

```bash
./scripts/p4_hardening_plan.sh
```

Run strict tool-lane validation (requires all external tools installed):

```bash
./scripts/p4_hardening_plan.sh --strict-tools
```

## Config-Driven Plan Runner

Use the configurable runner when selecting stress/parity/benchmark/soak subsets:

```bash
./scripts/run_testing_plan.sh --profile stress
./scripts/run_testing_plan.sh --profile parity --profile benchmark --strict-tools
SOTH_MITM_SOAK_DURATION_SECONDS=300 ./scripts/run_testing_plan.sh --profile soak
./scripts/run_testing_plan.sh --lane phase4_differential_validation
./scripts/run_testing_plan.sh --config testing/test-plan.env
```

Docker entrypoint:

```bash
./scripts/docker_run_testing.sh --config testing/test-plan.env
```

Lane registry and defaults:

1. `testing/lanes/registry.tsv`
2. `testing/test-plan.env`

To add a new contributor lane:

1. Ensure the lane script accepts `--report-dir`.
2. Add one row in `testing/lanes/registry.tsv`.
3. Run `./scripts/run_testing_plan.sh --list-lanes` and execute the lane.

## What Each Gate Covers

- `p4_performance_gates`: connection churn, long-lived streams, header stress, memory ceiling checks.
- `p4_failure_injection`: reset/timeout taxonomy, invalid cert-chain classification, upstream EOF mid-stream handling.
- `p4_differential_validation`: deterministic event ordering and TLS taxonomy/source-confidence parity lanes.
- `p4_chaos_adversarial`: charter adversarial corpus and parser/fuzz regression lane checks.
- `p4_chaos_network_faults`: `toxiproxy`/`tc netem` capability checks plus enforceable fault profiles.
- `p4_tls_hardening`: local cert-lab/TLS taxonomy checks plus optional `testssl.sh`/`badssl` probes.
- `p4_tool_lanes`: external protocol, TLS, perf, chaos, and fuzz tooling availability/execution lanes (includes `p4_tls_hardening`).
- `phase5_reliability_contract`: deterministic runtime reliability invariants (idle watchdog, stage budget, stuck-flow telemetry).
- `phase5_http1_smuggling_guard`: HTTP/1 request/response canonicalization and smuggling corpus (`TE/CL`, malformed heads, absolute-form semantics).
- `phase5_tls_profile_matrix`: `strict|default|compat` TLS profile behavior, cert-profile fixture checks, and optional `openssl`/`badssl` probes.
- `phase5_route_mode_matrix`: route planner mode/config matrix and chained upstream host policy semantics (`direct|reverse|upstream-http|upstream-socks5`).
- `phase5_http2_resilience`: stream lifecycle hardening checks (parallel streams, benign reset/GOAWAY tolerance, header-limit guard) plus optional `h2spec` blocking command contract.
- `phase5_event_log_contract`: deterministic event log v2 serialization/index contract, sidecar machine-readable exit status contract, and differential replay fixture stability (`.events.v2.jsonl` preferred).
- `p5_runtime_soak`: mixed-protocol runtime budget soak gate (`HTTP/1`, `HTTP/2`, tunnel, SSE, gRPC envelope path) with denial/watermark assertions.

Reliability invariant reference:

- `docs/testing/reliability-invariants.md`
- `docs/testing/flow-fsm-transition-table.md`
- `docs/testing/h2spec-blocking-criteria.md`
- `docs/testing/event-log-v2-contract.md`

## Artifact Layout

- `artifacts/p4-hardening/status.tsv`
- `artifacts/p4-hardening/summary.md`
- `artifacts/p4-hardening/performance/*`
- `artifacts/p4-hardening/failure-injection/*`
- `artifacts/p4-hardening/differential/*`
- `artifacts/p4-hardening/chaos/*`
- `artifacts/p4-hardening/chaos-network/*`
- `artifacts/p4-hardening/tool-lanes/*`
- `artifacts/p5-reliability-contract/*`
- `artifacts/p5-route-mode-matrix/*`
- `artifacts/p5-http2-resilience/*`
- `artifacts/p5-event-log-contract/*`
- `artifacts/p5-runtime-soak/*`
