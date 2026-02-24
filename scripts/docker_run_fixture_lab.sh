#!/usr/bin/env bash
set -euo pipefail

cmd="./scripts/fixture_lab_matrix.sh"
for arg in "$@"; do
  quoted="$(printf '%q' "$arg")"
  cmd+=" ${quoted}"
done

docker compose run --rm soth-mitm-tools bash -c "$cmd"
