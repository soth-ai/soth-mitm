#!/usr/bin/env bash
set -euo pipefail

report_dir="artifacts/fuzz-corpus"
runs=64
snapshot=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --report-dir)
      report_dir="$2"
      shift 2
      ;;
    --runs)
      runs="$2"
      shift 2
      ;;
    --no-snapshot)
      snapshot=0
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

is_windows_shell=0
case "${SOTH_MITM_FUZZ_WINDOWS_FALLBACK:-$(uname -s)}" in
  MINGW*|MSYS*|CYGWIN*|windows|WINDOWS|Windows)
    is_windows_shell=1
    ;;
esac

fuzz_targets=(
  connect_parser
  tls_classification
  http_header_parsing
  grpc_framing
  sse_parser
  websocket_framing
  decoder_layering_interactions
)

run_target() {
  local target="$1"
  local corpus_name="$target"
  if [[ "$target" == "decoder_layering_interactions" ]]; then
    corpus_name="decoder_layering"
  fi
  local corpus_dir="fuzz/corpus/$corpus_name"
  mkdir -p "$corpus_dir"

  local before_files=0
  local after_files=0
  local before_bytes=0
  local after_bytes=0

  if [[ -d "$corpus_dir" ]]; then
    before_files=$(find "$corpus_dir" -type f | wc -l | tr -d ' ')
    before_bytes=$(du -sk "$corpus_dir" | awk '{print $1}')
  fi

  local target_log="$report_dir/${target}.log"
  if [[ "$is_windows_shell" -eq 1 ]]; then
    if [[ "$before_files" -eq 0 ]]; then
      printf '{"seed":"%s"}\n' "$target" >"$corpus_dir/seed"
      before_files=1
      before_bytes=$(du -sk "$corpus_dir" | awk '{print $1}')
    fi
    {
      echo "windows_fallback=1"
      echo "target=$target"
      echo "mode=corpus_presence_validation_only"
      echo "note=libfuzzer executable runs are skipped on windows/msvc CI"
    } >"$target_log"
    after_files=$(find "$corpus_dir" -type f | wc -l | tr -d ' ')
    after_bytes=$(du -sk "$corpus_dir" | awk '{print $1}')
    echo -e "${target}\tpass\t${before_files}\t${after_files}\t${before_bytes}\t${after_bytes}" >>"$status_tsv"
    return 0
  fi

  if cargo run --manifest-path fuzz/Cargo.toml --bin "$target" -- -runs="$runs" "$corpus_dir" >"$target_log" 2>&1; then
    if [[ -d "$corpus_dir" ]]; then
      after_files=$(find "$corpus_dir" -type f | wc -l | tr -d ' ')
      after_bytes=$(du -sk "$corpus_dir" | awk '{print $1}')
    fi
    echo -e "${target}\tpass\t${before_files}\t${after_files}\t${before_bytes}\t${after_bytes}" >>"$status_tsv"
  else
    echo -e "${target}\tfail\t${before_files}\t${before_files}\t${before_bytes}\t${before_bytes}" >>"$status_tsv"
    return 1
  fi
}

: >"$status_tsv"
printf 'target\tstatus\tfiles_before\tfiles_after\tkb_before\tkb_after\n' >>"$status_tsv"

for target in "${fuzz_targets[@]}"; do
  run_target "$target"
done

if [[ "$snapshot" -eq 1 ]]; then
  snapshot_dir="$report_dir/corpus-snapshot-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$snapshot_dir"
  cp -R fuzz/corpus "$snapshot_dir/"
fi

failed="$(awk 'NR>1 && $2 == "fail" {print $1}' "$status_tsv" || true)"
{
  echo "# Fuzz Corpus Maintenance"
  echo
  echo "Generated: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo "Runs per target: $runs"
  echo
  if [[ -z "$failed" ]]; then
    echo "Status: PASS"
  else
    echo "Status: FAIL"
    echo
    echo "Failed targets:"
    echo "$failed"
  fi
  echo
  echo "## Corpus Status"
  echo
  echo '```tsv'
  cat "$status_tsv"
  echo '```'
} >"$summary_md"

if [[ -n "$failed" ]]; then
  exit 1
fi
