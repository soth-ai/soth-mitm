# CI Gates

This repository enforces protocol and reliability gates through GitHub Actions.

## Execution Tiers

CI is split into three tiers:

1. Pull request (`pull_request`): baseline quality and correctness gates.
2. Main branch (`push` to `main`): baseline plus protocol matrix/triage.
3. Release tag (`push` tag `v*`): full hardening and release-grade gates.

Manual runs (`workflow_dispatch`) support:

1. `run_profile=fast`: baseline only.
2. `run_profile=full`: full release-grade gate set.

## Gate Jobs

### Baseline (PR/Main/Tag/Fast)

1. `fmt_clippy`
2. `test`
3. `phase_a_smoke`
4. `p1_reliability`
5. `feature_matrix`
6. `compliance`
7. `tls_failure_fixtures`

### Main + Release (`push main`, `push v*`, `workflow_dispatch full`)

1. `phase2_protocol_matrix`
2. `phase2_protocol_triage`

### Release Only (`push v*`, `workflow_dispatch full`)

1. `phase4_performance_gates`
2. `phase4_failure_injection`
3. `phase4_differential_validation`
4. `phase4_tool_lanes`
5. `phase4_chaos_network_faults`
6. `phase4_chaos_adversarial`
7. `phase6_performance_gates`
8. `phase6_tls_revocation_matrix`
9. `phase6_tls_mtls_matrix`
10. `phase6_tls_fingerprint_parity`
11. `phase6_tls_compat_pack`
12. `phase6_acceptance_matrix`

### Historical/Planned (Not currently wired in `ci.yml`)

1. `phase5_reliability_contract`
2. `phase5_event_log_contract`
3. `phase5_runtime_soak`

## Phase-2 Gate Contract

`phase2_protocol_matrix` runs one lane per matrix entry and uploads lane artifacts.

`phase2_protocol_triage` downloads all lane artifacts and fails if:

1. any lane status is non-zero
2. any required protocol is missing from observed lane results

The triage output artifact is uploaded as `p2-protocol-triage` and contains:

1. `summary.md`
2. `status_aggregate.tsv`
3. `failed_lanes.txt`
4. `missing_protocols.txt`

## Artifact Locations

- Local lane reports: `artifacts/p2-protocol/<lane>`
- Local triage report: `artifacts/p2-protocol/triage`
- Local performance gate report: `artifacts/p4-performance`
- Local failure injection report: `artifacts/p4-failure-injection`
- Local differential validation report: `artifacts/p4-differential`
- Local tool lanes report: `artifacts/p4-tool-lanes`
- Local chaos network fault report: `artifacts/p4-chaos-network`
- Local chaos/adversarial report: `artifacts/p4-chaos`
- Local phase-5 reliability contract report: `artifacts/p5-reliability-contract`
- Local phase-5 event log contract report: `artifacts/p5-event-log-contract`
- Local phase-5 runtime soak report: `artifacts/p5-runtime-soak`
- Local phase-6 TLS revocation matrix report: `artifacts/p6-tls-revocation-matrix`
- Local phase-6 TLS mTLS matrix report: `artifacts/p6-tls-mtls-matrix`
- Local phase-6 TLS fingerprint parity report: `artifacts/p6-tls-fingerprint-parity`
- Local phase-6 TLS compatibility pack report: `artifacts/p6-tls-compat-pack`
