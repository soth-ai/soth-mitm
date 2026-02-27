# CI Gates

This repository enforces protocol and reliability gates through GitHub Actions.

## Gate Jobs

1. `fmt_clippy`
2. `test`
3. `phase_a_smoke`
4. `p1_reliability`
5. `phase2_protocol_matrix`
6. `phase2_protocol_triage`
7. `phase4_performance_gates`
8. `phase4_failure_injection`
9. `phase4_differential_validation`
10. `phase4_tool_lanes`
11. `phase4_chaos_network_faults`
12. `phase4_chaos_adversarial`
13. `phase5_reliability_contract`
14. `phase5_event_log_contract`
15. `phase5_runtime_soak`
16. `phase6_tls_revocation_matrix`

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
