#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

max_lines="${MAX_FILE_LINES:-400}"

violations=0
while IFS= read -r file; do
  [[ -f "$file" ]] || continue

  line_count=$(wc -l <"$file")
  if (( line_count > max_lines )); then
    printf "line-limit violation: %s has %d lines (max %d)\n" "$file" "$line_count" "$max_lines"
    violations=1
  fi
done < <(find crates -type f -name '*.rs' | rg '/src/' | sort)

if (( violations != 0 )); then
  echo "Split oversized core Rust files before merge."
  exit 1
fi

echo "max core Rust file line check passed (max=${max_lines})."
