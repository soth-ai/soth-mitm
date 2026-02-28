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
has_rg=0
if command -v rg >/dev/null 2>&1; then
  has_rg=1
fi

search_sources() {
  local pattern="$1"
  shift
  if [[ "$has_rg" -eq 1 ]]; then
    rg -n "$pattern" "$@"
  else
    grep -R -n -E "$pattern" "$@"
  fi
}

unsafe_pattern='(^|[^[:alnum:]_])unsafe([^[:alnum:]_]|$)'
if [[ "$has_rg" -eq 1 ]]; then
  unsafe_pattern='\bunsafe\b'
fi

unsafe_matches="$(
  search_sources "$unsafe_pattern" \
    crates/soth-mitm/src \
    crates/mitm-core/src \
    crates/mitm-http/src \
    crates/mitm-policy/src \
    crates/mitm-sidecar/src \
    crates/mitm-tls/src \
    crates/mitm-observe/src | \
    awk -F: '
      !($1 ~ /crates\/soth-mitm\/src\/process\/socket_pid\.rs$/) {print}
    ' || true
)"
if [[ -n "$unsafe_matches" ]]; then
  status="fail"
  details+=("unsafe_usage_detected")
fi

raw_syscall_matches="$(
  search_sources 'libc::|nix::sys::|std::os::unix::io::FromRawFd|std::os::fd::FromRawFd' \
    crates/soth-mitm/src | \
    awk -F: '
      !($1 ~ /crates\/soth-mitm\/src\/process\/socket_pid\.rs$/) {print}
    ' || true
)"
if [[ -n "$raw_syscall_matches" ]]; then
  status="fail"
  details+=("raw_syscall_boundary_violation")
fi

unauthorized_commands="$(
  search_sources 'tokio::process::Command|std::process::Command' crates/soth-mitm/src | \
    awk -F: '
      !($1 ~ /crates\/soth-mitm\/src\/ca_trust\/backend_common\.rs$/) {print}
    ' || true
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
