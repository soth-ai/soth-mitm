#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

git config core.hooksPath .githooks
chmod +x .githooks/pre-push

echo "Installed git hooks path: .githooks"
echo "Enabled pre-push check: ./scripts/check_max_file_lines.sh"
