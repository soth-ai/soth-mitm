#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

report_file="artifacts/p6-acceptance/ac11/audit_report.generated.txt"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --report-file)
      report_file="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

mkdir -p "$(dirname "$report_file")"

status="pass"
details=()

if rg -n '\bunsafe\b' crates/soth-mitm/src crates/mitm-core/src crates/mitm-http/src \
  crates/mitm-policy/src crates/mitm-sidecar/src crates/mitm-tls/src crates/mitm-observe/src \
  >/dev/null 2>&1; then
  status="fail"
  details+=("unsafe_usage_detected")
fi

if rg -n 'libc::|nix::sys::|std::os::unix::io::FromRawFd|std::os::fd::FromRawFd' \
  crates/soth-mitm/src >/dev/null 2>&1; then
  status="fail"
  details+=("raw_syscall_boundary_violation")
fi

unauthorized_commands="$(
  rg -n 'tokio::process::Command|std::process::Command' crates/soth-mitm/src -S | \
    awk -F: '
      !($1 ~ /crates\/soth-mitm\/src\/process\/(linux|macos|windows)\.rs$/) &&
      !($1 ~ /crates\/soth-mitm\/src\/ca_trust\/backend_common\.rs$/) {print}
    '
)"
if [[ -n "$unauthorized_commands" ]]; then
  status="fail"
  details+=("command_invocation_outside_allowed_boundary")
fi

{
  echo "audit_status=$status"
  echo "generated_at=$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  if [[ "${#details[@]}" -eq 0 ]]; then
    echo "details=ok"
  else
    echo "details=${details[*]}"
  fi
} >"$report_file"

if [[ "$status" != "pass" ]]; then
  exit 1
fi
