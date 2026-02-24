# `soth` Proxy Engine Migration and Cutover

This document defines required migration controls for switching from `hudsucker` to `soth-mitm` in `soth`.

## Dual Engine Config

`proxy_engine` must be explicit in `soth` runtime config:

```yaml
proxy_engine: hudsucker
# or
proxy_engine: soth-mitm
```

## Shadow Mode Requirements

Shadow mode must compare these dimensions on matched traffic cohorts:

1. decision diff (`intercept|tunnel|block`)
2. TLS outcome diff (taxonomy reason + source/provider metadata)
3. event diff (ordering + cardinality + close reason)

## Cutover Gates

Cutover is allowed only when all conditions are met:

1. parity threshold met for decisions/TLS/event ordering
2. soak period completed without high-severity regressions
3. rollback path tested and documented

## Protocol Routing Rules During Migration

1. Do not route `SSE`, `HTTP/2`, `HTTP/3`, or `gRPC` traffic to hudsucker cohorts.
2. Do not use hudsucker cohorts as source-of-truth for TLS learning metrics.
3. Start TLS-learning rollouts with mitmproxy-backed cohorts first.

## Operational Rollout Sequence

1. Run shadow mode with `soth-mitm` event capture only.
2. Enable read-only differential alerts.
3. Enable low-percentage `soth-mitm` decision enforcement.
4. Expand cohort after each soak window passes.
5. Make `soth-mitm` default and keep rollback gate armed.
