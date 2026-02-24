# Fuzz Targets

This directory contains focused fuzz targets for `soth-mitm` hardening:

- `connect_parser`: CONNECT parsing and malformed CONNECT head handling.
- `tls_classification`: TLS failure classification string parser.
- `http_header_parsing`: HTTP/1 request/response head parsing boundaries.
- `grpc_framing`: gRPC envelope parsing under chunk splits and length mismatches.
- `sse_parser`: SSE incremental parsing under partial lines/events.
- `msgpack_decoder`: msgpack structural decoder bounds checks.
- `decoder_layering_interactions`: layered decoder ordering and stage interaction invariants.

## Run

```bash
cargo fuzz run connect_parser
cargo fuzz run tls_classification
cargo fuzz run http_header_parsing
cargo fuzz run grpc_framing
cargo fuzz run sse_parser
cargo fuzz run msgpack_decoder
cargo fuzz run decoder_layering_interactions
```

Run commands from `fuzz/`.

## Corpus Maintenance

From repository root:

```bash
./scripts/fuzz_corpus_maintenance.sh --runs 64
```

Artifacts are written to `artifacts/fuzz-corpus/` with per-target logs, corpus stats, and timestamped snapshots.
