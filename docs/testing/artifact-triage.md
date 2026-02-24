# Artifact Triage

This runbook defines how to assemble and inspect testing/hardening artifacts after CI or local runs.

## Collect Artifacts

```bash
./scripts/collect_testing_artifacts.sh
```

Artifacts are consolidated under `artifacts/testing-artifacts/`.

## Consolidated Outputs

1. `index.tsv`: available source artifact directories and summary files
2. `summary.md`: consolidated high-level status report
3. copied summaries/status files from available gate directories

## Source Artifact Roots

The collector inspects these paths when present:

1. `artifacts/fixture-lab`
2. `artifacts/tls-failure-fixtures`
3. `artifacts/p2-protocol/triage`
4. `artifacts/p4-performance`
5. `artifacts/p4-failure-injection`
6. `artifacts/p4-differential`
7. `artifacts/p4-differential-replay`
8. `artifacts/p4-chaos`
9. `artifacts/p4-chaos-network`
10. `artifacts/p4-tool-lanes`
11. `artifacts/p4-hardening`
12. `artifacts/p5-reliability-contract`
13. `artifacts/p5-route-mode-matrix`
14. `artifacts/p5-http2-resilience`
15. `artifacts/p5-event-log-contract`
16. `artifacts/p5-runtime-soak`
17. `artifacts/fuzz-corpus`

## Triage Order

1. Check top-level `summary.md` for failed/skip-heavy lanes.
2. Inspect corresponding `status.tsv` for failed case ids.
3. Open per-lane logs/diff files for root cause.
4. Map failure to lane owner and remediation checklist item.
