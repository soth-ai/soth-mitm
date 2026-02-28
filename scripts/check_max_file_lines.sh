#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

max_lines="${MAX_FILE_LINES:-500}"
core_crates_raw="${CORE_RUST_CRATES:-mitm-core,mitm-http,mitm-observe,mitm-policy,mitm-sidecar,mitm-tls,soth-mitm}"

violations=0
IFS=',' read -r -a core_crates <<<"$core_crates_raw"
while IFS= read -r file; do
  [[ -f "$file" ]] || continue

  line_count=$(wc -l <"$file")
  if (( line_count > max_lines )); then
    printf "line-limit violation: %s has %d lines (max %d)\n" "$file" "$line_count" "$max_lines"
    violations=1
  fi
done < <(
  for crate in "${core_crates[@]}"; do
    crate="$(echo "$crate" | xargs)"
    [[ -n "$crate" ]] || continue
    crate_src="crates/${crate}/src"
    [[ -d "$crate_src" ]] || continue
    find "$crate_src" \
      -type f \
      -name '*.rs' \
      ! -path '*/tests/*' \
      ! -name 'tests.rs'
  done | sort
)

if (( violations != 0 )); then
  echo "Split oversized core Rust files before merge."
  exit 1
fi

echo "max core Rust file line check passed (max=${max_lines})."
