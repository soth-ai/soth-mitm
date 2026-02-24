#!/usr/bin/env bash
set -euo pipefail

build_tools=0
args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-tools)
      build_tools=1
      shift
      ;;
    *)
      args+=("$1")
      shift
      ;;
  esac
done

if [[ "$build_tools" -eq 1 ]]; then
  docker compose build soth-mitm-tools
fi

docker compose up -d soth-mitm-tools

cmd="./scripts/run_testing_plan.sh"
if [[ "${#args[@]}" -gt 0 ]]; then
  for arg in "${args[@]}"; do
    quoted="$(printf '%q' "$arg")"
    cmd+=" ${quoted}"
  done
fi

docker exec soth-mitm-tools bash -lc "cd /workspace && ${cmd}"
