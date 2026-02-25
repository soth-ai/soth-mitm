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

ac_run_with_preferred_bench_linker() {
  local mode="${MITM_BENCH_LINKER_MODE:-auto}"
  if [[ "$mode" == "off" ]]; then
    "$@"
    return 0
  fi

  local rust_lld=""
  if command -v rustc >/dev/null 2>&1; then
    local rustc_sysroot
    local rustc_host
    rustc_sysroot="$(rustc --print sysroot 2>/dev/null || true)"
    rustc_host="$(rustc -vV 2>/dev/null | awk '/^host:/ {print $2}')"
    if [[ -n "$rustc_sysroot" && -n "$rustc_host" ]]; then
      rust_lld="${rustc_sysroot}/lib/rustlib/${rustc_host}/bin/gcc-ld/ld.lld"
    fi
  fi

  local use_lld=0
  if [[ "$mode" == "lld" ]]; then
    use_lld=1
  elif [[ "$mode" == "auto" && "$(uname -s)" == "Linux" ]]; then
    if [[ -x "$rust_lld" ]] || command -v ld.lld >/dev/null 2>&1; then
      use_lld=1
    fi
  fi

  if [[ "$use_lld" -eq 1 ]] && command -v clang >/dev/null 2>&1; then
    local linker_arg="-fuse-ld=lld"
    if [[ -x "$rust_lld" ]]; then
      linker_arg="-fuse-ld=${rust_lld}"
    elif ! command -v ld.lld >/dev/null 2>&1; then
      "$@"
      return $?
    fi

    local rustflags="${RUSTFLAGS:-}"
    if [[ "$rustflags" != *"${linker_arg}"* ]]; then
      if [[ -n "$rustflags" ]]; then
        rustflags="${rustflags} "
      fi
      rustflags="${rustflags}-C linker=clang -C link-arg=${linker_arg}"
    fi
    env RUSTFLAGS="$rustflags" "$@"
  else
    "$@"
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
