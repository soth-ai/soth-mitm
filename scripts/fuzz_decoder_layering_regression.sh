#!/usr/bin/env bash
set -euo pipefail

runs=128
while [[ $# -gt 0 ]]; do
  case "$1" in
    --runs)
      runs="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

cargo run --manifest-path fuzz/Cargo.toml --bin decoder_layering_interactions -- \
  -runs="$runs" fuzz/corpus/decoder_layering
