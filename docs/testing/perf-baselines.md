# Performance Baselines

This runbook defines baseline performance gate execution and artifact expectations.

## Baseline Gate

```bash
./scripts/p4_performance_gates.sh
```

Artifacts:

- `artifacts/p4-performance/status.tsv`
- `artifacts/p4-performance/summary.md`

## Baseline Dimensions

1. connection churn
2. long-lived streams (WS, SSE)
3. header stress (HTTP/2 oversized and parallel streams)
4. memory ceilings (runtime governor + decoder budgets)

## Tool-Driven Perf Lanes

The external perf tool lane is executed via:

```bash
./scripts/p4_tool_lanes.sh
```

Strict mode (requires all tools installed):

```bash
./scripts/p4_tool_lanes.sh --strict-tools
```

Expected external tools for deep perf baselines:

1. `wrk`
2. `hey`
3. `h2load`
4. `ghz`

## Baseline Tracking Guidance

1. Commit status summaries for baseline runs in CI artifacts.
2. Review regressions before release-candidate gating.
3. Keep a stable lane command set to preserve comparability across commits.
