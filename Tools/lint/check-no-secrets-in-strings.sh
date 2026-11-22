#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Scan tracked text without ever emitting secret-shaped values [M1-13].
set -euo pipefail
# shellcheck source=Tools/lint/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
if (($# == 0)); then
  # Repository mode fails closed: git must list the files and the repository always has some to scan (M1-32).
  load_repo_files '*.swift' '*.go' '*.yml' '*.yaml' '*.json' '*.plist' '*.py' '*.sh' '*.md' ':!:.plan/**' || exit 1
  if ((${#REPO_FILES[@]} == 0)); then
    echo 'check-no-secrets-in-strings: no files to scan; the repository listing is empty (a broken index or listing)' >&2
    exit 1
  fi
fi
files() {
  if (($#)); then
    for arg in "$@"; do
      if [[ -d "$arg" ]]; then
        while IFS= read -r -d '' f; do printf '%s\0%s\0' "$f" "${f#"${arg%/}"/}"; done < <(find "${arg%/}" -type f -print0)
      else
        printf '%s\0%s\0' "$arg" "$(rel "$arg")"
      fi
    done
  else
    local f
    for f in "${REPO_FILES[@]}"; do printf '%s\0%s\0' "$f" "$(rel "$f")"; done
  fi
}
files "$@" | python3 -I "$LINT_ROOT/Tools/lint/secret-shapes.py"
