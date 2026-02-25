#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

declare -a cargo_args=()
if [[ "${OFFLINE:-0}" == "1" ]]; then
  cargo_args+=(--offline)
fi

run_cargo_test() {
  if [[ "${#cargo_args[@]}" -gt 0 ]]; then
    cargo test "$@" "${cargo_args[@]}"
  else
    cargo test "$@"
  fi
}

echo "[phase-a] core parser + policy unit tests"
run_cargo_test -p mitm-core

echo "[phase-a] sidecar transport integration fixtures"
run_cargo_test -p mitm-sidecar --test phase_a

echo "[phase-a] http/1.1 MITM integration fixtures"
run_cargo_test -p mitm-sidecar --test http1_mitm
