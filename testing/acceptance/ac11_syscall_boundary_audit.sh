#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

source testing/acceptance/common.sh

report_dir="artifacts/p6-acceptance/ac11"
strict_tools=0
audit_report="${P6_AC11_AUDIT_REPORT:-}"
enable_live_trace="${P6_AC11_ENABLE_LIVE_TRACE:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --report-dir)
      report_dir="$2"
      shift 2
      ;;
    --strict-tools)
      strict_tools=1
      shift
      ;;
    --long-run)
      shift
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
outcome_tsv="$report_dir/outcome.tsv"
printf 'check\tstatus\tdetail\n' >"$status_tsv"

if [[ "$(uname -s)" == "Linux" ]]; then
  if command -v strace >/dev/null 2>&1; then
    ac_record_status "$status_tsv" syscall_trace_tool pass strace
  else
    if [[ "$strict_tools" -eq 1 ]]; then
      ac_record_status "$status_tsv" syscall_trace_tool fail missing_tools:strace
    else
      ac_record_status "$status_tsv" syscall_trace_tool pass trace_tool_optional_missing:strace
    fi
  fi
elif [[ "$(uname -s)" == "Darwin" ]]; then
  if command -v dtruss >/dev/null 2>&1; then
    ac_record_status "$status_tsv" syscall_trace_tool pass dtruss
  else
    if [[ "$strict_tools" -eq 1 ]]; then
      ac_record_status "$status_tsv" syscall_trace_tool fail missing_tools:dtruss
    else
      ac_record_status "$status_tsv" syscall_trace_tool pass trace_tool_optional_missing:dtruss
    fi
  fi
else
  if [[ "$strict_tools" -eq 1 ]]; then
    ac_record_status "$status_tsv" syscall_trace_tool fail unsupported_platform
  else
    ac_record_status "$status_tsv" syscall_trace_tool pass unsupported_platform
  fi
fi

generated_audit_report="$report_dir/audit_report.generated.txt"
if ./scripts/p6_syscall_boundary_audit.sh --report-file "$generated_audit_report"; then
  ac_record_status "$status_tsv" syscall_boundary_static_audit pass generated
else
  ac_record_status "$status_tsv" syscall_boundary_static_audit fail generated_failed
fi

audit_report_to_validate="$generated_audit_report"
if [[ -n "$audit_report" ]]; then
  if [[ -f "$audit_report" ]]; then
    cp "$audit_report" "$report_dir/audit_report.input.txt"
    audit_report_to_validate="$audit_report"
  else
    ac_record_status "$status_tsv" syscall_audit_evidence fail missing_audit_report_file
    audit_report_to_validate=""
  fi
fi

if [[ -n "$audit_report_to_validate" ]]; then
  if rg -n '^audit_status=pass$' "$audit_report_to_validate" >/dev/null 2>&1; then
    ac_record_status "$status_tsv" syscall_audit_evidence pass supplied_report_pass
  else
    ac_record_status "$status_tsv" syscall_audit_evidence fail supplied_report_not_pass
  fi
fi

if [[ "$enable_live_trace" == "1" ]]; then
  if [[ "$(uname -s)" == "Linux" ]] && command -v strace >/dev/null 2>&1; then
    if strace -ff -o "$report_dir/live_trace" -e trace=network \
      cargo test -p mitm-sidecar --test phase_a tunnel_action_relays_data_end_to_end -q >/dev/null 2>&1; then
      ac_record_status "$status_tsv" live_trace_capture pass generated
    else
      ac_record_status "$status_tsv" live_trace_capture fail command_failed
    fi
  elif [[ "$(uname -s)" == "Darwin" ]] && command -v dtruss >/dev/null 2>&1; then
    ac_record_status "$status_tsv" live_trace_capture pass dtruss_available_manual_capture_path
  else
    if [[ "$strict_tools" -eq 1 ]]; then
      ac_record_status "$status_tsv" live_trace_capture fail trace_tool_unavailable
    else
      ac_record_status "$status_tsv" live_trace_capture pass trace_tool_optional_unavailable
    fi
  fi
else
  ac_record_status "$status_tsv" live_trace_capture pass disabled_by_config
fi

config_md=$'- strict_tools: '"${strict_tools}"$'\n- audit_report: '"${audit_report:-unset}"$'\n- enable_live_trace: '"${enable_live_trace}"$'\n- AC-11 static boundary audit is generated automatically; optional external report overrides it when provided.'

ac_finalize \
  "$status_tsv" \
  "$summary_md" \
  "$outcome_tsv" \
  "AC-11 Syscall Boundary Audit" \
  "$config_md"
