#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ ! -f "crates/soth-mitm/Cargo.toml" ]]; then
  echo "expected to run from soth-mitm workspace root" >&2
  exit 2
fi

rust_files=()
while IFS= read -r rust_file; do
  rust_files+=("$rust_file")
done < <(find crates/soth-mitm/src crates/soth-mitm/tests -type f -name "*.rs" | sort)

if [[ "${#rust_files[@]}" -eq 0 ]]; then
  echo "no Rust files found under crates/soth-mitm" >&2
  exit 2
fi

# Non-test source files only (exclude test modules, integration tests,
# and files whose names indicate they are test-only include!() targets)
src_files=()
while IFS= read -r src_file; do
  src_files+=("$src_file")
done < <(find crates/soth-mitm/src -type f -name "*.rs" \
  ! -name "tests_*.rs" ! -name "tests.rs" ! -name "test_*.rs" \
  ! -path "*/tests/*" ! -path "*/tests.rs" | sort)

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

# Same as scan_fixed_term but only checks non-test source files.
# Filters out matches inside #[cfg(test)] blocks by checking if the
# match line is after the last #[cfg(test)] in that file.
scan_fixed_term_src_only() {
  local title="$1"
  local term="$2"
  local raw_matches
  if [[ "${#src_files[@]}" -eq 0 ]]; then return; fi
  if [[ "$has_rg" -eq 1 ]]; then
    raw_matches="$(rg -n --color=never -i --fixed-strings "$term" "${src_files[@]}" || true)"
  else
    raw_matches="$(grep -n -i -F -- "$term" "${src_files[@]}" || true)"
  fi
  if [[ -z "$raw_matches" ]]; then return; fi

  # Filter out matches that fall inside #[cfg(test)] blocks
  local filtered=""
  while IFS= read -r line; do
    # Extract file path and line number: "path:lineno:content"
    local fpath lineno
    fpath="$(echo "$line" | cut -d: -f1)"
    lineno="$(echo "$line" | cut -d: -f2)"
    # Find the last #[cfg(test)] line in the file
    local cfg_test_line
    cfg_test_line="$(grep -n '#\[cfg(test)\]' "$fpath" 2>/dev/null | tail -1 | cut -d: -f1 || true)"
    if [[ -n "$cfg_test_line" ]] && (( lineno > cfg_test_line )); then
      continue  # skip — inside test block
    fi
    filtered="${filtered}${line}"$'\n'
  done <<< "$raw_matches"

  filtered="$(echo -n "$filtered" | sed '/^$/d')"
  if [[ -n "$filtered" ]]; then
    report_violation "$title" "$filtered"
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
  scan_fixed_term_src_only "AI/provider-specific term '${term}' is prohibited" "$term"
done

if [[ "${#src_files[@]}" -gt 0 ]]; then
  if [[ "$has_rg" -eq 1 ]]; then
    body_logging_matches="$(
      rg -n -U --color=never --pcre2 \
        '(?is)(tracing::(?:trace|debug|info|warn|error)|log::(?:trace|debug|info|warn|error)|eprintln|println)!\s*\([^)]{0,512}\b(body|payload|chunk)\b' \
        "${src_files[@]}" || true
    )"
  else
    body_logging_matches="$(
      grep -n -E -i \
        '(tracing::(trace|debug|info|warn|error)|log::(trace|debug|info|warn|error)|eprintln|println)!.*(body|payload|chunk)' \
        "${src_files[@]}" || true
    )"
  fi
else
  body_logging_matches=""
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
