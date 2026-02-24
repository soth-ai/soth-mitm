#!/usr/bin/env bash
set -euo pipefail

cmd="./scripts/p4_hardening_plan.sh"
if [[ "$#" -eq 0 ]]; then
  cmd+=" --skip-network"
else
  for arg in "$@"; do
    quoted="$(printf '%q' "$arg")"
    cmd+=" ${quoted}"
  done
fi

docker compose run --rm soth-mitm-tools bash -c "$cmd"
