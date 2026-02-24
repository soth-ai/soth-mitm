# Failure Injection

This runbook defines deterministic failure-injection execution for `soth-mitm`.

## Primary Gate

```bash
./scripts/p4_failure_injection.sh
```

Artifacts:

- `artifacts/p4-failure-injection/status.tsv`
- `artifacts/p4-failure-injection/summary.md`

## Covered Fault Classes

1. TLS reset/timeout/invalid-chain taxonomy
2. native unknown-CA classification path
3. fragmented TLS ClientHello failure handling
4. upstream EOF mid-stream tunnel behavior

## Extended Chaos Network Faults

```bash
./scripts/p4_chaos_network_faults.sh
```

For privileged/fault-enforcing environments:

```bash
./scripts/p4_chaos_network_faults.sh --strict-tools --enforce-faults
```

Artifacts:

- `artifacts/p4-chaos-network/status.tsv`
- `artifacts/p4-chaos-network/netem_profiles.tsv`
- `artifacts/p4-chaos-network/toxiproxy_profiles.tsv`

## Expected Outcomes

1. No panic under injected failures.
2. Deterministic `stream_closed` reason codes.
3. Stable TLS failure taxonomy mapping.
