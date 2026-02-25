#!/usr/bin/env bash
set -euo pipefail

build_tools=0
duration_seconds="${SOTH_MITM_SOAK_DURATION_SECONDS:-21600}"
min_iterations="${SOTH_MITM_SOAK_MIN_ITERATIONS:-1}"
args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-tools)
      build_tools=1
      shift
      ;;
    --duration-seconds)
      duration_seconds="$2"
      shift 2
      ;;
    --min-iterations)
      min_iterations="$2"
      shift 2
      ;;
    *)
      args+=("$1")
      shift
      ;;
  esac
done

if [[ "$build_tools" -eq 1 ]]; then
  ./scripts/docker_build_tools.sh
fi

SOTH_MITM_SOAK_DURATION_SECONDS="$duration_seconds" \
SOTH_MITM_SOAK_MIN_ITERATIONS="$min_iterations" \
./scripts/docker_run_testing.sh --profile soak --strict-soak "${args[@]}"
