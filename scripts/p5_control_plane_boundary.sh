#!/usr/bin/env bash
set -euo pipefail

report_dir="artifacts/p5-control-plane-boundary"

while [[ $# -gt 0 ]]; do
  case "$1" in
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

mkdir -p "$report_dir"
status_tsv="$report_dir/status.tsv"
summary_md="$report_dir/summary.md"

record_status() {
  local lane="$1"
  local status="$2"
  local detail="$3"
  printf '%s\t%s\t%s\n' "$lane" "$status" "$detail" >>"$status_tsv"
}

: >"$status_tsv"

if command -v rg >/dev/null 2>&1; then
  control_surface_cmd=(rg -n \
    "control_plane|management_endpoint|admin_endpoint|control_listener|bind_control|host_allowlist|origin_allowlist|anti_rebinding" \
    crates/mitm-sidecar/src crates/mitm-core/src -g '*.rs')
else
  control_surface_cmd=(grep -R -n -E --include='*.rs' \
    "control_plane|management_endpoint|admin_endpoint|control_listener|bind_control|host_allowlist|origin_allowlist|anti_rebinding" \
    crates/mitm-sidecar/src crates/mitm-core/src)
fi

if "${control_surface_cmd[@]}" >"$report_dir/unexpected-surface.txt"; then
  record_status control_plane_surface "fail" "unexpected_control_surface_tokens"
else
  record_status control_plane_surface "pass" "no_control_plane_endpoints_exposed"
fi

if grep -n -E "bind_listener_with_socket_hardening" crates/mitm-sidecar/src/socket_hardening.rs >/dev/null 2>&1; then
  record_status explicit_single_listener_guard "pass" "single_data_plane_listener_path"
else
  record_status explicit_single_listener_guard "fail" "listener_guard_missing"
fi

failed="$(awk '$2 == "fail" {print $1}' "$status_tsv" || true)"
{
  echo "# Phase 5 Control-Plane Boundary Guard"
  echo
  echo "Generated: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo
  if [[ -z "$failed" ]]; then
    echo "Status: PASS"
    echo
    echo "No management/control endpoint surface is currently exposed."
  else
    echo "Status: FAIL"
    echo
    echo "Failed lanes:"
    echo "$failed"
  fi
  echo
  echo "## Lane Status"
  echo
  echo '```tsv'
  cat "$status_tsv"
  echo '```'
} >"$summary_md"

if [[ -n "$failed" ]]; then
  exit 1
fi
