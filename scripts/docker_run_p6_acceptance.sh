#!/usr/bin/env bash
set -euo pipefail

build_tools=0
long_run=0
report_dir="artifacts/p6-acceptance"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-tools)
      build_tools=1
      shift
      ;;
    --long-run)
      long_run=1
      shift
      ;;
    --report-dir)
      report_dir="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ "$build_tools" -eq 1 ]]; then
  docker compose build soth-mitm-tools
fi

docker compose up -d soth-mitm-tools

cmd="./scripts/p6_acceptance_matrix.sh --strict-tools --strict-acceptance --report-dir $(printf '%q' "$report_dir")"
if [[ "$long_run" -eq 1 ]]; then
  cmd+=" --long-run"
fi

docker exec soth-mitm-tools bash -lc "cd /workspace && ${cmd}"
