#!/usr/bin/env bash
set -euo pipefail

report_dir="artifacts/p5-websocket-chaos-burnin"
iterations="${SOTH_MITM_WS_CHAOS_BURNIN_ITERATIONS:-20}"
clients="${SOTH_MITM_WS_CHAOS_CLIENTS:-240}"
poll_interval_ms="${SOTH_MITM_WS_BURNIN_POLL_INTERVAL_MS:-200}"
allow_fd_growth="${SOTH_MITM_WS_BURNIN_MAX_FD_GROWTH:-24}"
allow_rss_growth_kb="${SOTH_MITM_WS_BURNIN_MAX_RSS_GROWTH_KB:-65536}"
fail_fast=1
strict_tools=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --report-dir)
      report_dir="$2"
      shift 2
      ;;
    --iterations)
      iterations="$2"
      shift 2
      ;;
    --clients)
      clients="$2"
      shift 2
      ;;
    --poll-interval-ms)
      poll_interval_ms="$2"
      shift 2
      ;;
    --allow-fd-growth)
      allow_fd_growth="$2"
      shift 2
      ;;
    --allow-rss-growth-kb)
      allow_rss_growth_kb="$2"
      shift 2
      ;;
    --strict-tools)
      strict_tools=1
      shift
      ;;
    --no-fail-fast)
      fail_fast=0
      shift
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

is_uint() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

if ! is_uint "$iterations" || ! is_uint "$clients" || ! is_uint "$poll_interval_ms" || ! is_uint "$allow_fd_growth" || ! is_uint "$allow_rss_growth_kb"; then
  echo "numeric arguments must be unsigned integers" >&2
  exit 2
fi
if (( iterations < 1 || clients < 1 || poll_interval_ms < 10 )); then
  echo "invalid configuration: iterations>=1, clients>=1, poll_interval_ms>=10 required" >&2
  exit 2
fi

mkdir -p "$report_dir"
status_tsv="$report_dir/status.tsv"
iterations_tsv="$report_dir/iterations.tsv"
samples_tsv="$report_dir/samples.tsv"
summary_md="$report_dir/summary.md"

has_lsof=1
if ! command -v lsof >/dev/null 2>&1; then
  has_lsof=0
fi

if [[ "$strict_tools" -eq 1 && "$has_lsof" -eq 0 ]]; then
  echo "strict-tools enabled but lsof is unavailable" >&2
  exit 1
fi

printf 'lane\tstatus\tdetail\n' >"$status_tsv"
printf 'iteration\texit_code\tduration_ms\tpeak_rss_kb\tpeak_fd_count\tlog_file\n' >"$iterations_tsv"
printf 'iteration\tobserved_at_utc\tpid\trss_kb\tfd_count\n' >"$samples_tsv"

failure_detected=0
for iteration in $(seq 1 "$iterations"); do
  log_file="$report_dir/iteration_${iteration}.log"
  start_epoch_ms="$(($(date +%s) * 1000))"
  env SOTH_MITM_WS_CHAOS_CLIENTS="$clients" \
    cargo test -p mitm-sidecar --test websocket_reliability_soak \
      websocket_chaos_soak_mixed_lanes_settle_without_stuck_flows -q \
    >"$log_file" 2>&1 &
  test_pid=$!
  peak_rss_kb=0
  peak_fd_count=0
  while kill -0 "$test_pid" >/dev/null 2>&1; do
    observed_at_utc="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    rss_kb="$(ps -o rss= -p "$test_pid" 2>/dev/null | tr -d ' ' || true)"
    if ! is_uint "${rss_kb:-}"; then
      rss_kb="0"
    fi
    if (( rss_kb > peak_rss_kb )); then
      peak_rss_kb="$rss_kb"
    fi

    if [[ "$has_lsof" -eq 1 ]]; then
      # The test process may exit between kill-probe and lsof sampling; treat that as zero.
      fd_count="$( (lsof -n -P -p "$test_pid" 2>/dev/null || true) | wc -l | tr -d ' ')"
      if ! is_uint "${fd_count:-}"; then
        fd_count="0"
      fi
      if (( fd_count > peak_fd_count )); then
        peak_fd_count="$fd_count"
      fi
    else
      fd_count="NA"
    fi

    printf '%s\t%s\t%s\t%s\t%s\n' \
      "$iteration" \
      "$observed_at_utc" \
      "$test_pid" \
      "$rss_kb" \
      "$fd_count" >>"$samples_tsv"

    sleep "$(awk "BEGIN { printf \"%.3f\", $poll_interval_ms / 1000 }")"
  done

  set +e
  wait "$test_pid"
  exit_code=$?
  set -e

  end_epoch_ms="$(($(date +%s) * 1000))"
  duration_ms="$((end_epoch_ms - start_epoch_ms))"
  peak_fd_value="$peak_fd_count"
  if [[ "$has_lsof" -eq 0 ]]; then
    peak_fd_value="NA"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$iteration" \
    "$exit_code" \
    "$duration_ms" \
    "$peak_rss_kb" \
    "$peak_fd_value" \
    "$log_file" >>"$iterations_tsv"

  if [[ "$exit_code" -ne 0 ]]; then
    failure_detected=1
    if [[ "$fail_fast" -eq 1 ]]; then
      break
    fi
  fi
done

if [[ "$failure_detected" -eq 1 ]]; then
  printf 'burnin_iterations\tfail\tnon_zero_test_exit\n' >>"$status_tsv"
else
  printf 'burnin_iterations\tpass\tall_iterations_passed\n' >>"$status_tsv"
fi

successful_count="$(awk -F'\t' 'NR>1 && $2 == 0 {count++} END {print count+0}' "$iterations_tsv")"
rss_mono=0
rss_growth=0
fd_mono="NA"
fd_growth="NA"
leak_guard_failed=0

if (( successful_count >= 2 )); then
  read -r rss_mono rss_growth < <(
    awk -F'\t' '
      NR > 1 && $2 == 0 {
        rss[++n] = $4
      }
      END {
        mono = 1
        for (i = 2; i <= n; i++) {
          if (rss[i] < rss[i - 1]) {
            mono = 0
          }
        }
        growth = (n >= 1) ? rss[n] - rss[1] : 0
        printf "%d %d\n", mono, growth
      }
    ' "$iterations_tsv"
  )
  if (( rss_mono == 1 && rss_growth > allow_rss_growth_kb )); then
    leak_guard_failed=1
  fi

  if [[ "$has_lsof" -eq 1 ]]; then
    read -r fd_mono fd_growth < <(
      awk -F'\t' '
        NR > 1 && $2 == 0 {
          fd[++n] = $5
        }
        END {
          mono = 1
          for (i = 2; i <= n; i++) {
            if (fd[i] < fd[i - 1]) {
              mono = 0
            }
          }
          growth = (n >= 1) ? fd[n] - fd[1] : 0
          printf "%d %d\n", mono, growth
        }
      ' "$iterations_tsv"
    )
    if (( fd_mono == 1 && fd_growth > allow_fd_growth )); then
      leak_guard_failed=1
    fi
  fi
fi

if (( successful_count < 2 )); then
  printf 'burnin_leak_guard\tskip\tinsufficient_successful_iterations\n' >>"$status_tsv"
elif [[ "$leak_guard_failed" -eq 1 ]]; then
  printf 'burnin_leak_guard\tfail\tmonotonic_growth_above_threshold\n' >>"$status_tsv"
else
  printf 'burnin_leak_guard\tpass\tno_monotonic_leak_growth\n' >>"$status_tsv"
fi

overall_failed="$(awk -F'\t' 'NR>1 && $2 == "fail" {print $1}' "$status_tsv" || true)"
{
  echo "# Phase 5 WebSocket Chaos Burn-In"
  echo
  echo "Generated: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo
  echo "Config:"
  echo "- iterations: $iterations"
  echo "- clients: $clients"
  echo "- poll_interval_ms: $poll_interval_ms"
  echo "- fail_fast: $fail_fast"
  echo "- strict_tools: $strict_tools"
  echo "- allow_fd_growth: $allow_fd_growth"
  echo "- allow_rss_growth_kb: $allow_rss_growth_kb"
  echo
  if [[ -z "$overall_failed" ]]; then
    echo "Status: PASS"
  else
    echo "Status: FAIL"
    echo
    echo "Failed lanes:"
    echo "$overall_failed"
  fi
  echo
  echo "Leak trend diagnostics:"
  echo "- successful_iterations: $successful_count"
  echo "- rss_monotonic: $rss_mono"
  echo "- rss_growth_kb: $rss_growth"
  echo "- fd_monotonic: $fd_mono"
  echo "- fd_growth: $fd_growth"
  if [[ "$has_lsof" -eq 0 ]]; then
    echo "- fd_sampling: disabled (lsof unavailable)"
  fi
  echo
  echo "## Lane Status"
  echo
  echo '```tsv'
  cat "$status_tsv"
  echo '```'
  echo
  echo "## Iteration Summary"
  echo
  echo '```tsv'
  cat "$iterations_tsv"
  echo '```'
  echo
  echo "## Samples"
  echo
  echo "See: $samples_tsv"
} >"$summary_md"

if [[ -n "$overall_failed" ]]; then
  exit 1
fi
