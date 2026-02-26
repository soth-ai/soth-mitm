#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ ! -f "crates/soth-mitm/Cargo.toml" ]]; then
  echo "expected to run from soth-mitm workspace root" >&2
  exit 2
fi

mapfile -t rust_files < <(find crates/soth-mitm/src crates/soth-mitm/tests -type f -name "*.rs" | sort)

if [[ "${#rust_files[@]}" -eq 0 ]]; then
  echo "no Rust files found under crates/soth-mitm" >&2
  exit 2
fi

violations=0
has_rg=0
if command -v rg >/dev/null 2>&1; then
  has_rg=1
fi

report_violation() {
  local title="$1"
  local matches="$2"
  violations=$((violations + 1))
  echo "[prohibition] ${title}" >&2
  if [[ -n "$matches" ]]; then
    echo "$matches" >&2
  fi
  echo >&2
}

scan_fixed_term() {
  local title="$1"
  local term="$2"
  local matches
  if [[ "$has_rg" -eq 1 ]]; then
    matches="$(rg -n --color=never -i --fixed-strings "$term" "${rust_files[@]}" || true)"
  else
    matches="$(grep -n -i -F -- "$term" "${rust_files[@]}" || true)"
  fi
  if [[ -n "$matches" ]]; then
    report_violation "$title" "$matches"
  fi
}

if [[ "$has_rg" -eq 1 ]]; then
  delay_usage_matches="$(rg -n --color=never --pcre2 'Handler(?:Decision|Action)\s*::\s*(Delay|Hold)\b' "${rust_files[@]}" || true)"
else
  delay_usage_matches="$(grep -n -E 'Handler(Decision|Action)[[:space:]]*::[[:space:]]*(Delay|Hold)' "${rust_files[@]}" || true)"
fi
if [[ -n "$delay_usage_matches" ]]; then
  report_violation "Delay/Hold action usage is prohibited" "$delay_usage_matches"
fi

if [[ "$has_rg" -eq 1 ]]; then
  delay_variant_matches="$(rg -n --color=never --pcre2 '^\s*(Delay|Hold)\s*(\{|,|\()' crates/soth-mitm/src/actions.rs || true)"
else
  delay_variant_matches="$(grep -n -E '^[[:space:]]*(Delay|Hold)[[:space:]]*(\{|,|\()' crates/soth-mitm/src/actions.rs || true)"
fi
if [[ -n "$delay_variant_matches" ]]; then
  report_violation "Delay/Hold action variant is prohibited" "$delay_variant_matches"
fi

provider_terms=(
  "openai"
  "anthropic"
  "claude"
  "gpt"
  "gemini"
  "mistral"
  "llama"
  "bedrock"
  "cohere"
  "perplexity"
)

for term in "${provider_terms[@]}"; do
  scan_fixed_term "AI/provider-specific term '${term}' is prohibited" "$term"
done

if [[ "$has_rg" -eq 1 ]]; then
  body_logging_matches="$(
    rg -n -U --color=never --pcre2 \
      '(?is)(tracing::(?:trace|debug|info|warn|error)|log::(?:trace|debug|info|warn|error)|eprintln|println)!\s*\([^)]{0,512}\b(body|payload|chunk)\b' \
      "${rust_files[@]}" || true
  )"
else
  body_logging_matches="$(
    grep -n -E -i \
      '(tracing::(trace|debug|info|warn|error)|log::(trace|debug|info|warn|error)|eprintln|println)!.*(body|payload|chunk)' \
      "${rust_files[@]}" || true
  )"
fi
if [[ -n "$body_logging_matches" ]]; then
  report_violation "request/response body logging is prohibited" "$body_logging_matches"
fi

telemetry_deps=(
  "opentelemetry"
  "opentelemetry_sdk"
  "tracing-opentelemetry"
  "sentry"
  "sentry-core"
  "sentry-tracing"
  "prometheus"
  "metrics-exporter-prometheus"
  "datadog"
)

for dep in "${telemetry_deps[@]}"; do
  if [[ "$has_rg" -eq 1 ]]; then
    dep_matches="$(rg -n --color=never --pcre2 "^\s*${dep}\s*=" crates/soth-mitm/Cargo.toml || true)"
  else
    dep_matches="$(grep -n -E "^[[:space:]]*${dep}[[:space:]]*=" crates/soth-mitm/Cargo.toml || true)"
  fi
  if [[ -n "$dep_matches" ]]; then
    report_violation "telemetry dependency '${dep}' is prohibited in soth-mitm crate" "$dep_matches"
  fi
done

if (( violations > 0 )); then
  echo "prohibition check failed with ${violations} violation(s)" >&2
  exit 1
fi

echo "prohibition check passed"
