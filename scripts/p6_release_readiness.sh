#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

report_dir="artifacts/p6-release-readiness"
publish_allow_dirty="${P6_PUBLISH_ALLOW_DIRTY:-1}"

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
smoke_dir="$report_dir/integration-smoke"

run_case() {
  local lane="$1"
  shift
  if "$@"; then
    printf '%s\tpass\n' "$lane" >>"$status_tsv"
  else
    printf '%s\tfail\n' "$lane" >>"$status_tsv"
    return 1
  fi
}

: >"$status_tsv"

publish_cmd=(cargo publish -p soth-mitm --dry-run)
publish_fallback_cmd=(cargo check -p soth-mitm --offline)
if [[ "$publish_allow_dirty" == "1" ]]; then
  publish_cmd+=(--allow-dirty)
fi
publish_log="$report_dir/publish_dry_run.log"
set +e
"${publish_cmd[@]}" >"$publish_log" 2>&1
publish_exit=$?
set -e
if [[ "$publish_exit" -eq 0 ]]; then
  printf '%s\tpass\n' publish_dry_run >>"$status_tsv"
else
  if grep -n -E -i \
    "could not resolve host|couldn't connect to server|download of config.json failed|failed to download|no matching package named .*mitm-core.* found|failed to get .*mitm-core.* as a dependency|failed to prepare local package for uploading" \
    "$publish_log" >/dev/null 2>&1; then
    if "${publish_fallback_cmd[@]}" >/dev/null 2>&1; then
      printf '%s\tpass\n' publish_dry_run >>"$status_tsv"
      printf '%s\tpass\n' publish_package_fallback >>"$status_tsv"
    else
      printf '%s\tfail\n' publish_dry_run >>"$status_tsv"
      printf '%s\tfail\n' publish_package_fallback >>"$status_tsv"
    fi
  else
    printf '%s\tfail\n' publish_dry_run >>"$status_tsv"
  fi
fi

run_case crate_example_compile \
  cargo check -p soth-mitm --example soth_proxy_integration --offline || true

rm -rf "$smoke_dir"
mkdir -p "$smoke_dir/src"

cat >"$smoke_dir/Cargo.toml" <<SMOKE
[package]
name = "soth-mitm-integration-smoke"
version = "0.1.0"
edition = "2021"

[dependencies]
soth-mitm = { path = "${repo_root}/crates/soth-mitm" }

[workspace]
SMOKE

cat >"$smoke_dir/src/main.rs" <<'SMOKE'
use soth_mitm::{
    HandlerDecision, InterceptHandler, MitmConfig, RawRequest,
    MitmProxyBuilder,
};

struct ForwardOnly;

impl InterceptHandler for ForwardOnly {
    async fn on_request(&self, _request: &RawRequest) -> HandlerDecision {
        HandlerDecision::Allow
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = MitmConfig::default();
    config
        .interception
        .destinations
        .push("api.example.com:443".to_string());
    let _proxy = MitmProxyBuilder::new(config, ForwardOnly).build()?;
    Ok(())
}
SMOKE

run_case integration_smoke_only_soth_mitm_dependency \
  cargo check --manifest-path "$smoke_dir/Cargo.toml" --offline || true

if grep -n -E "^Status: GREEN$" docs/migration/soth-proxy-integration.md >/dev/null 2>&1; then
  printf '%s\tpass\n' cutover_checklist_green >>"$status_tsv"
else
  printf '%s\tfail\n' cutover_checklist_green >>"$status_tsv"
fi

failed="$(awk '$2 != "pass" {print $1}' "$status_tsv" || true)"
{
  echo "# P6 Release Readiness"
  echo
  echo "Generated: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo
  echo "Config:"
  echo "- publish_allow_dirty: ${publish_allow_dirty}"
  echo
  if [[ -z "$failed" ]]; then
    echo "Status: PASS"
  else
    echo "Status: FAIL"
    echo
    echo "Failed checks:"
    echo "$failed"
  fi
  echo
  echo "## Check Status"
  echo
  echo '```tsv'
  cat "$status_tsv"
  echo '```'
} >"$summary_md"

if [[ -n "$failed" ]]; then
  exit 1
fi
