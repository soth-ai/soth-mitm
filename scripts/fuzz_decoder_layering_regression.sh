#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
runs=128
corpus_dir="$repo_root/fuzz/corpus/decoder_layering"
seed_file="$corpus_dir/seed"

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

mkdir -p "$corpus_dir"
if [[ ! -f "$seed_file" ]]; then
  printf '{"seed":"decoder-layering"}\n' >"$seed_file"
fi

cargo run --manifest-path "$repo_root/fuzz/Cargo.toml" --bin decoder_layering_interactions -- \
  -runs="$runs" "$corpus_dir"
