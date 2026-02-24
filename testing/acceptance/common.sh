#!/usr/bin/env bash

ac_record_status() {
  local status_tsv="$1"
  local check="$2"
  local status="$3"
  local detail="$4"
  printf '%s\t%s\t%s\n' "$check" "$status" "$detail" >>"$status_tsv"
}

ac_run_case() {
  local status_tsv="$1"
  local check="$2"
  shift 2
  if "$@"; then
    ac_record_status "$status_tsv" "$check" "pass" "ok"
  else
    local exit_code=$?
    ac_record_status "$status_tsv" "$check" "fail" "command_failed:${exit_code}"
    return 1
  fi
}

ac_require_tools() {
  local status_tsv="$1"
  local check="$2"
  local strict_tools="$3"
  shift 3

  local missing=()
  local tool
  for tool in "$@"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      missing+=("$tool")
    fi
  done

  if [[ "${#missing[@]}" -eq 0 ]]; then
    return 0
  fi

  local detail="missing_tools:${missing[*]}"
  if [[ "$strict_tools" -eq 1 ]]; then
    ac_record_status "$status_tsv" "$check" "fail" "$detail"
    return 1
  fi

  ac_record_status "$status_tsv" "$check" "skip" "$detail"
  return 0
}

ac_finalize() {
  local status_tsv="$1"
  local summary_md="$2"
  local outcome_tsv="$3"
  local title="$4"
  local config_md="${5:-}"

  local failed
  failed="$(awk -F '\t' 'NR > 1 && $2 == "fail" {print $1}' "$status_tsv" || true)"
  local skipped
  skipped="$(awk -F '\t' 'NR > 1 && $2 == "skip" {print $1}' "$status_tsv" || true)"

  local failed_count=0
  local skipped_count=0
  failed_count="$(awk -F '\t' 'NR > 1 && $2 == "fail" {count++} END {print count + 0}' "$status_tsv")"
  skipped_count="$(awk -F '\t' 'NR > 1 && $2 == "skip" {count++} END {print count + 0}' "$status_tsv")"

  local overall="pass"
  if [[ "$failed_count" -gt 0 ]]; then
    overall="fail"
  elif [[ "$skipped_count" -gt 0 ]]; then
    overall="partial"
  fi

  {
    echo "# ${title}"
    echo
    echo "Generated: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    if [[ -n "$config_md" ]]; then
      echo
      echo "Config:"
      printf '%s\n' "$config_md"
    fi
    echo
    echo "Overall: ${overall}"

    if [[ -n "$failed" ]]; then
      echo
      echo "Failed checks:"
      echo "$failed"
    fi
    if [[ -n "$skipped" ]]; then
      echo
      echo "Skipped checks:"
      echo "$skipped"
    fi

    echo
    echo "## Check Status"
    echo
    echo '```tsv'
    cat "$status_tsv"
    echo '```'
  } >"$summary_md"

  {
    echo -e "metric\tvalue"
    echo -e "overall\t${overall}"
    echo -e "failed_count\t${failed_count}"
    echo -e "skipped_count\t${skipped_count}"
  } >"$outcome_tsv"

  if [[ "$failed_count" -gt 0 ]]; then
    return 1
  fi
  return 0
}
