# Differential vs mitmproxy

This runbook defines replay-driven drift detection between `soth-mitm` and mitmproxy on a shared fixture corpus.

## Corpus Manifest

- Manifest: `testing/differential/corpus/manifest.tsv`
- Sample normalized traces: `testing/differential/samples/`

Each normalized event row is a tab-separated record:

```text
sequence_id\tevent_kind\tflow_id\tprotocol\treason_or_marker
```

## Replay Drift Command

```bash
./scripts/p4_differential_replay.sh \
  --manifest testing/differential/corpus/manifest.tsv \
  --input-root testing/differential/samples \
  --strict-input
```

Artifacts:

- `artifacts/p4-differential-replay/status.tsv`
- `artifacts/p4-differential-replay/summary.md`
- `artifacts/p4-differential-replay/drift/<case>.diff`

## End-to-End Differential Gate

`./scripts/p4_differential_validation.sh` includes:

1. deterministic core conformance replay checks
2. TLS taxonomy/source-confidence parity checks
3. hudsucker scope guardrails
4. normalized replay drift report generation (`p4_differential_replay`)

## Notes

1. The normalized replay format is intentionally engine-agnostic.
2. Live mitmproxy capture/replay can populate `--input-root` using external harness tooling.
3. Hudsucker comparison remains scoped to supported protocol/mode surface only.
