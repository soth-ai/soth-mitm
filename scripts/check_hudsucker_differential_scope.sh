#!/usr/bin/env bash
set -euo pipefail

scope_file="docs/testing/hudsucker-differential-scope.tsv"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --scope-file)
      scope_file="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ ! -f "$scope_file" ]]; then
  echo "scope file not found: $scope_file" >&2
  exit 2
fi

required_lanes=(connect_block_tunnel http1_connect_passthrough)
for lane in "${required_lanes[@]}"; do
  if ! awk -F '\t' -v lane="$lane" '$1 == lane {found=1} END {exit !found}' "$scope_file"; then
    echo "missing required hudsucker differential lane: $lane" >&2
    exit 1
  fi
done

unsupported_protocols=(websocket sse http2 http3_passthrough grpc_http2)
for protocol in "${unsupported_protocols[@]}"; do
  if awk -F '\t' -v protocol="$protocol" '$2 == protocol {found=1} END {exit !found}' "$scope_file"; then
    echo "unsupported protocol included in hudsucker differential scope: $protocol" >&2
    exit 1
  fi
done

echo "hudsucker differential scope is restricted to supported protocol/mode surface."
