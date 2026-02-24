#!/usr/bin/env bash
set -euo pipefail

export PATH="/usr/local/cargo/bin:/usr/local/go/bin:${PATH}"

registry_file="testing/lanes/registry.tsv"
config_file="testing/test-plan.env"
report_dir=""
strict_tools=0
skip_network=1
enforce_faults=0
fail_fast=1
list_lanes=0

profiles=(stress parity benchmark)
lanes=()
cli_profiles=()
cli_lanes=()
cli_report_dir=""
cli_strict_tools=""
cli_skip_network=""
cli_enforce_faults=""
cli_fail_fast=""

registry_lane_ids=()
declare -A lane_category=()
declare -A lane_script=()
declare -A lane_supports_strict_tools=()
declare -A lane_supports_skip_network=()
declare -A lane_supports_enforce_faults=()
declare -A lane_description=()

usage() {
  cat <<'USAGE'
Usage: ./scripts/run_testing_plan.sh [options]

Config-driven runner for stress/parity/benchmark lanes.

Options:
  --config <path>           Config file (default: testing/test-plan.env)
  --profile <name>          Profile to run (repeatable): stress|parity|benchmark
  --lane <lane_id>          Explicit lane selection (repeatable)
  --report-dir <path>       Output root directory
  --strict-tools            Enable strict tool checks where supported
  --skip-network            Skip network probes where supported
  --no-skip-network         Force-enable network probes where supported
  --enforce-faults          Enforce live fault probes where supported
  --no-enforce-faults       Disable enforced live fault probes
  --fail-fast               Stop at first lane failure
  --no-fail-fast            Continue running remaining lanes after a failure
  --list-lanes              Print registered lanes and exit
  -h, --help                Show this help

Examples:
  ./scripts/run_testing_plan.sh --profile stress
  ./scripts/run_testing_plan.sh --profile parity --profile benchmark --strict-tools
  ./scripts/run_testing_plan.sh --lane phase4_differential_validation
  ./scripts/run_testing_plan.sh --config testing/test-plan.env
USAGE
}

split_items() {
  local raw="$1"
  raw="${raw//,/ }"
  for item in $raw; do
    if [[ -n "$item" ]]; then
      echo "$item"
    fi
  done
}

contains_item() {
  local needle="$1"
  shift
  local item
  for item in "$@"; do
    if [[ "$item" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

parse_bool() {
  local raw="$1"
  case "$raw" in
    1|true|TRUE|yes|YES|on|ON) echo 1 ;;
    0|false|FALSE|no|NO|off|OFF) echo 0 ;;
    *)
      echo "invalid boolean value: $raw" >&2
      exit 2
      ;;
  esac
}

load_config() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    return 0
  fi

  # shellcheck disable=SC1090
  source "$file"

  if [[ -n "${TEST_PROFILES:-}" ]]; then
    mapfile -t profiles < <(split_items "$TEST_PROFILES")
  fi
  if [[ -n "${TEST_LANES:-}" ]]; then
    mapfile -t lanes < <(split_items "$TEST_LANES")
  fi
  if [[ -n "${REPORT_DIR:-}" ]]; then
    report_dir="$REPORT_DIR"
  fi
  if [[ -n "${STRICT_TOOLS:-}" ]]; then
    strict_tools="$(parse_bool "$STRICT_TOOLS")"
  fi
  if [[ -n "${SKIP_NETWORK:-}" ]]; then
    skip_network="$(parse_bool "$SKIP_NETWORK")"
  fi
  if [[ -n "${ENFORCE_FAULTS:-}" ]]; then
    enforce_faults="$(parse_bool "$ENFORCE_FAULTS")"
  fi
  if [[ -n "${FAIL_FAST:-}" ]]; then
    fail_fast="$(parse_bool "$FAIL_FAST")"
  fi
}

load_registry() {
  if [[ ! -f "$registry_file" ]]; then
    echo "lane registry not found: $registry_file" >&2
    exit 2
  fi

  local lane_id category script supports_strict supports_skip supports_enforce description
  while IFS=$'\t' read -r lane_id category script supports_strict supports_skip supports_enforce description; do
    if [[ -z "$lane_id" || "${lane_id:0:1}" == "#" ]]; then
      continue
    fi
    registry_lane_ids+=("$lane_id")
    lane_category["$lane_id"]="$category"
    lane_script["$lane_id"]="$script"
    lane_supports_strict_tools["$lane_id"]="$supports_strict"
    lane_supports_skip_network["$lane_id"]="$supports_skip"
    lane_supports_enforce_faults["$lane_id"]="$supports_enforce"
    lane_description["$lane_id"]="$description"
  done <"$registry_file"

  if [[ "${#registry_lane_ids[@]}" -eq 0 ]]; then
    echo "lane registry is empty: $registry_file" >&2
    exit 2
  fi
}

print_lanes() {
  printf 'lane_id\tcategory\tscript\tdescription\n'
  local lane_id
  for lane_id in "${registry_lane_ids[@]}"; do
    printf '%s\t%s\t%s\t%s\n' \
      "$lane_id" \
      "${lane_category[$lane_id]}" \
      "${lane_script[$lane_id]}" \
      "${lane_description[$lane_id]}"
  done
}

validate_selection() {
  local valid_profiles=(stress parity benchmark)
  local profile
  for profile in "${profiles[@]}"; do
    if ! contains_item "$profile" "${valid_profiles[@]}"; then
      echo "unsupported profile: $profile" >&2
      exit 2
    fi
  done

  local selected
  for selected in "${lanes[@]}"; do
    if ! contains_item "$selected" "${registry_lane_ids[@]}"; then
      echo "unknown lane id: $selected" >&2
      exit 2
    fi
  done
}

select_lanes() {
  local selected=()
  local lane_id
  if [[ "${#lanes[@]}" -gt 0 ]]; then
    selected=("${lanes[@]}")
  else
    for lane_id in "${registry_lane_ids[@]}"; do
      if contains_item "${lane_category[$lane_id]}" "${profiles[@]}"; then
        selected+=("$lane_id")
      fi
    done
  fi

  if [[ "${#selected[@]}" -eq 0 ]]; then
    echo "no lanes selected" >&2
    exit 2
  fi

  printf '%s\n' "${selected[@]}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      config_file="$2"
      shift 2
      ;;
    --profile)
      cli_profiles+=("$2")
      shift 2
      ;;
    --lane)
      cli_lanes+=("$2")
      shift 2
      ;;
    --report-dir)
      cli_report_dir="$2"
      shift 2
      ;;
    --strict-tools)
      cli_strict_tools=1
      shift
      ;;
    --skip-network)
      cli_skip_network=1
      shift
      ;;
    --no-skip-network)
      cli_skip_network=0
      shift
      ;;
    --enforce-faults)
      cli_enforce_faults=1
      shift
      ;;
    --no-enforce-faults)
      cli_enforce_faults=0
      shift
      ;;
    --fail-fast)
      cli_fail_fast=1
      shift
      ;;
    --no-fail-fast)
      cli_fail_fast=0
      shift
      ;;
    --list-lanes)
      list_lanes=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

load_config "$config_file"

if [[ "${#cli_profiles[@]}" -gt 0 ]]; then
  profiles=("${cli_profiles[@]}")
fi
if [[ "${#cli_lanes[@]}" -gt 0 ]]; then
  lanes=("${cli_lanes[@]}")
fi
if [[ -n "$cli_report_dir" ]]; then
  report_dir="$cli_report_dir"
fi
if [[ -n "$cli_strict_tools" ]]; then
  strict_tools="$cli_strict_tools"
fi
if [[ -n "$cli_skip_network" ]]; then
  skip_network="$cli_skip_network"
fi
if [[ -n "$cli_enforce_faults" ]]; then
  enforce_faults="$cli_enforce_faults"
fi
if [[ -n "$cli_fail_fast" ]]; then
  fail_fast="$cli_fail_fast"
fi

load_registry

if [[ "$list_lanes" -eq 1 ]]; then
  print_lanes
  exit 0
fi

validate_selection

if [[ -z "$report_dir" ]]; then
  report_dir="artifacts/testing-plan/$(date -u +%Y%m%dT%H%M%SZ)"
fi
mkdir -p "$report_dir"

status_tsv="$report_dir/status.tsv"
summary_md="$report_dir/summary.md"

echo -e "lane_id\tcategory\tstatus\tdetail\treport_dir" >"$status_tsv"

mapfile -t selected_lanes < <(select_lanes)

failed_lanes=()
run_count=0

for lane_id in "${selected_lanes[@]}"; do
  run_count=$((run_count + 1))
  category="${lane_category[$lane_id]}"
  script_path="${lane_script[$lane_id]}"

  if [[ ! -x "$script_path" ]]; then
    echo -e "${lane_id}\t${category}\tfail\tmissing_or_non_executable_script\t-" >>"$status_tsv"
    failed_lanes+=("$lane_id")
    if [[ "$fail_fast" -eq 1 ]]; then
      break
    fi
    continue
  fi

  lane_report_dir="$report_dir/$lane_id"
  mkdir -p "$lane_report_dir"

  lane_cmd=("$script_path" "--report-dir" "$lane_report_dir")

  if [[ "$strict_tools" -eq 1 && "${lane_supports_strict_tools[$lane_id]}" == "1" ]]; then
    lane_cmd+=("--strict-tools")
  fi
  if [[ "$skip_network" -eq 1 && "${lane_supports_skip_network[$lane_id]}" == "1" ]]; then
    lane_cmd+=("--skip-network")
  fi
  if [[ "$enforce_faults" -eq 1 && "${lane_supports_enforce_faults[$lane_id]}" == "1" ]]; then
    lane_cmd+=("--enforce-faults")
  fi

  echo "[lane:${lane_id}] ${lane_cmd[*]}"
  if "${lane_cmd[@]}" >"$lane_report_dir/run.log" 2>&1; then
    echo -e "${lane_id}\t${category}\tpass\tok\t${lane_report_dir}" >>"$status_tsv"
  else
    echo -e "${lane_id}\t${category}\tfail\tcommand_failed\t${lane_report_dir}" >>"$status_tsv"
    failed_lanes+=("$lane_id")
    if [[ "$fail_fast" -eq 1 ]]; then
      break
    fi
  fi
done

skipped_count=$(( ${#selected_lanes[@]} - run_count ))

{
  echo "# Testing Plan Run"
  echo
  echo "Generated: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo
  if [[ "${#failed_lanes[@]}" -eq 0 ]]; then
    echo "Status: PASS"
  else
    echo "Status: FAIL"
    echo
    echo "Failed lanes:"
    printf '%s\n' "${failed_lanes[@]}"
  fi
  echo
  echo "Config:"
  echo "- profiles: ${profiles[*]}"
  if [[ "${#lanes[@]}" -gt 0 ]]; then
    echo "- lanes: ${lanes[*]}"
  fi
  echo "- strict_tools: ${strict_tools}"
  echo "- skip_network: ${skip_network}"
  echo "- enforce_faults: ${enforce_faults}"
  echo "- fail_fast: ${fail_fast}"
  echo "- selected_lane_count: ${#selected_lanes[@]}"
  echo "- executed_lane_count: ${run_count}"
  echo "- skipped_after_failure: ${skipped_count}"
  echo
  echo "## Lane Status"
  echo
  echo '```tsv'
  cat "$status_tsv"
  echo '```'
} >"$summary_md"

if [[ "${#failed_lanes[@]}" -gt 0 ]]; then
  exit 1
fi
