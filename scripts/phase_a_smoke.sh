#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo_args=()
if [[ "${OFFLINE:-0}" == "1" ]]; then
  cargo_args+=(--offline)
fi

echo "[phase-a] core parser + policy unit tests"
cargo test -p mitm-core "${cargo_args[@]}"

echo "[phase-a] sidecar transport integration fixtures"
cargo test -p mitm-sidecar --test phase_a "${cargo_args[@]}"

echo "[phase-a] http/1.1 MITM integration fixtures"
cargo test -p mitm-sidecar --test http1_mitm "${cargo_args[@]}"
